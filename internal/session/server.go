package session

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"vlf-runtime/internal/auth"
	"vlf-runtime/internal/limits"
	"vlf-runtime/internal/metrics"
	"vlf-runtime/internal/store"
)

type Config struct {
	ListenQUIC      string
	ListenTCP       string
	TLSConfig       *tls.Config
	IdleTimeout     time.Duration
	DialTimeout     time.Duration
	MaxFlows        int
	MaxDgramPayload int
	UpKbps          int
	DownKbps        int
	MaxUDPPPS       int
	KeepAlive       time.Duration
}

type Server struct {
	cfg      Config
	verifier *auth.Verifier
	limits   *limits.Manager
	metrics  *metrics.Metrics
	logger   *zap.Logger

	quicListener *quic.Listener
	tcpListener  net.Listener

	store *store.SessionStore

	mu       sync.RWMutex
	sessions map[uint64]managedSession
	nextID   atomic.Uint64
}

type managedSession interface {
	ID() uint64
	ClientID() string
	Close(reason string)
}

func NewServer(cfg Config, verifier *auth.Verifier, lim *limits.Manager, m *metrics.Metrics, logger *zap.Logger) *Server {
	wheel := store.NewWheel(time.Second, 512)
	return &Server{
		cfg:      cfg,
		verifier: verifier,
		limits:   lim,
		metrics:  m,
		logger:   logger,
		store:    store.NewSessionStore(wheel),
		sessions: make(map[uint64]managedSession),
	}
}

func (s *Server) Start(ctx context.Context) error {
	if s.cfg.TLSConfig == nil {
		return errors.New("session server requires TLS config")
	}
	if s.cfg.ListenQUIC == "" && s.cfg.ListenTCP == "" {
		return errors.New("session server requires at least one of listen_quic or listen_tcp")
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	started := 0
	errCh := make(chan error, 2)

	if s.cfg.ListenQUIC != "" {
		started++
		go func() {
			errCh <- s.serveQUIC(runCtx)
		}()
	}
	if s.cfg.ListenTCP != "" {
		started++
		go func() {
			errCh <- s.serveTCP(runCtx)
		}()
	}

	for remaining := started; remaining > 0; {
		select {
		case <-runCtx.Done():
			return nil
		case err := <-errCh:
			remaining--
			if err != nil {
				cancel()
				return err
			}
		}
	}
	return nil
}

func (s *Server) serveQUIC(ctx context.Context) error {
	keepAlive := s.cfg.KeepAlive
	if keepAlive == 0 {
		keepAlive = 12 * time.Second
	}

	quicCfg := &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  s.cfg.IdleTimeout,
		KeepAlivePeriod: keepAlive,
	}

	ln, err := quic.ListenAddr(s.cfg.ListenQUIC, s.cfg.TLSConfig, quicCfg)
	if err != nil {
		return fmt.Errorf("listen quic %s: %w", s.cfg.ListenQUIC, err)
	}
	s.quicListener = ln

	s.logger.Info("session QUIC lane listening", zap.String("addr", s.cfg.ListenQUIC))

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, quic.ErrServerClosed) {
				return nil
			}
			s.logger.Warn("accept QUIC conn failed", zap.Error(err))
			continue
		}

		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn *quic.Conn) {
	sessionID := s.nextID.Add(1)
	sessLogger := s.logger.With(
		zap.Uint64("session_id", sessionID),
		zap.String("remote_addr", conn.RemoteAddr().String()),
	)

	session := newSession(sessionID, conn, s, sessLogger)
	if err := session.Run(); err != nil {
		sessLogger.Warn("session finished with error", zap.Error(err))
	} else {
		sessLogger.Info("session finished")
	}
}

func (s *Server) serveTCP(ctx context.Context) error {
	ln, err := tls.Listen("tcp", s.cfg.ListenTCP, s.cfg.TLSConfig)
	if err != nil {
		return fmt.Errorf("listen tcp %s: %w", s.cfg.ListenTCP, err)
	}
	s.tcpListener = ln
	s.logger.Info("session TCP lane listening", zap.String("addr", s.cfg.ListenTCP))

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				s.logger.Warn("accept TCP conn temporary error", zap.Error(err))
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.logger.Warn("accept TCP conn failed", zap.Error(err))
			continue
		}

		go s.handleTCPConn(conn)
	}
}

func (s *Server) handleTCPConn(conn net.Conn) {
	sessionID := s.nextID.Add(1)
	sessLogger := s.logger.With(
		zap.Uint64("session_id", sessionID),
		zap.String("remote_addr", conn.RemoteAddr().String()),
		zap.String("transport", "tcp"),
	)

	sess := newTCPSession(sessionID, conn, s, sessLogger)
	if err := sess.Run(); err != nil {
		sessLogger.Warn("tcp session finished with error", zap.Error(err))
	} else {
		sessLogger.Info("tcp session finished")
	}
}

func (s *Server) registerSession(sess managedSession) {
	s.mu.Lock()
	s.sessions[sess.ID()] = sess
	s.mu.Unlock()

	s.store.Add(&store.SessionState{
		SessionID:  sess.ID(),
		ClientID:   sess.ClientID(),
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
	}, s.cfg.IdleTimeout, func() {
		sess.Close("idle_timeout")
	})

	s.metrics.ActiveSessions.Inc()
}

func (s *Server) touchSession(sessionID uint64) {
	_ = s.store.Touch(sessionID, s.cfg.IdleTimeout)
}

func (s *Server) unregisterSession(sessionID uint64) {
	s.mu.Lock()
	_, ok := s.sessions[sessionID]
	if ok {
		delete(s.sessions, sessionID)
	}
	s.mu.Unlock()

	if !ok {
		return
	}

	s.store.Delete(sessionID)
	s.limits.CleanupSession(sessionID)
	s.metrics.ActiveSessions.Dec()
}

func (s *Server) Shutdown() {
	if s.quicListener != nil {
		_ = s.quicListener.Close()
	}
	if s.tcpListener != nil {
		_ = s.tcpListener.Close()
	}

	s.mu.RLock()
	snapshot := make([]managedSession, 0, len(s.sessions))
	for _, sess := range s.sessions {
		snapshot = append(snapshot, sess)
	}
	s.mu.RUnlock()

	for _, sess := range snapshot {
		sess.Close("shutdown")
	}

	s.store.Close()
}
