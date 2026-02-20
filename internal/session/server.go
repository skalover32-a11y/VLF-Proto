package session

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
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
	ListenAddr      string
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

	listener *quic.Listener

	store *store.SessionStore

	mu       sync.RWMutex
	sessions map[uint64]*Session
	nextID   atomic.Uint64
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
		sessions: make(map[uint64]*Session),
	}
}

func (s *Server) Start(ctx context.Context) error {
	if s.cfg.TLSConfig == nil {
		return errors.New("session server requires TLS config")
	}

	keepAlive := s.cfg.KeepAlive
	if keepAlive == 0 {
		keepAlive = 12 * time.Second
	}

	quicCfg := &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  s.cfg.IdleTimeout,
		KeepAlivePeriod: keepAlive,
	}

	ln, err := quic.ListenAddr(s.cfg.ListenAddr, s.cfg.TLSConfig, quicCfg)
	if err != nil {
		return fmt.Errorf("listen quic %s: %w", s.cfg.ListenAddr, err)
	}
	s.listener = ln

	s.logger.Info("session lane listening", zap.String("addr", s.cfg.ListenAddr))

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

func (s *Server) registerSession(sess *Session) {
	s.mu.Lock()
	s.sessions[sess.id] = sess
	s.mu.Unlock()

	s.store.Add(&store.SessionState{
		SessionID:  sess.id,
		ClientID:   sess.clientID,
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
	if s.listener != nil {
		_ = s.listener.Close()
	}

	s.mu.RLock()
	snapshot := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		snapshot = append(snapshot, sess)
	}
	s.mu.RUnlock()

	for _, sess := range snapshot {
		sess.Close("shutdown")
	}

	s.store.Close()
}
