package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"vlf-runtime/internal/limits"
	"vlf-runtime/internal/metrics"
	"vlf-runtime/internal/store"

	"go.uber.org/zap"
)

var (
	ErrUnknownConn = errors.New("unknown conn_id")
	ErrForbidden   = errors.New("client is not owner of conn_id")
	ErrBadRequest  = errors.New("bad relay request")
)

type OpenRequest struct {
	Proto   string            `json:"proto"`
	DstHost string            `json:"dst_host"`
	DstPort int               `json:"dst_port"`
	SNI     string            `json:"sni,omitempty"`
	Meta    map[string]string `json:"meta,omitempty"`
}

type OpenResponse struct {
	ConnID      string `json:"conn_id"`
	ExpiresInMS int64  `json:"expires_in_ms"`
	RecvWindow  int    `json:"recv_window"`
	SendWindow  int    `json:"send_window"`
}

type SendResponse struct {
	Accepted int `json:"accepted"`
	Queued   int `json:"queued"`
}

type PingResponse struct {
	OK          bool  `json:"ok"`
	ExpiresInMS int64 `json:"expires_in_ms"`
}

type CloseResponse struct {
	Closed bool `json:"closed"`
}

type ManagerConfig struct {
	DialTimeout time.Duration
	IdleTimeout time.Duration
	RecvWindow  int
	SendWindow  int
}

type Manager struct {
	cfg     ManagerConfig
	dialer  net.Dialer
	limits  *limits.Manager
	metrics *metrics.Metrics
	logger  *zap.Logger

	ttlStore *store.RelayStore

	mu    sync.RWMutex
	conns map[string]*relayConn
}

func NewManager(cfg ManagerConfig, lim *limits.Manager, m *metrics.Metrics, logger *zap.Logger) *Manager {
	wheel := store.NewWheel(time.Second, 256)
	return &Manager{
		cfg:      cfg,
		dialer:   net.Dialer{Timeout: cfg.DialTimeout},
		limits:   lim,
		metrics:  m,
		logger:   logger,
		ttlStore: store.NewRelayStore(wheel),
		conns:    make(map[string]*relayConn),
	}
}

func (m *Manager) Open(ctx context.Context, clientID string, req OpenRequest) (*OpenResponse, error) {
	if req.Proto != "tcp" {
		return nil, fmt.Errorf("%w: unsupported proto %q", ErrBadRequest, req.Proto)
	}
	if req.DstHost == "" || req.DstPort <= 0 || req.DstPort > 65535 {
		return nil, fmt.Errorf("%w: dst_host and valid dst_port are required", ErrBadRequest)
	}

	if err := m.limits.ReserveRelayConn(clientID); err != nil {
		return nil, err
	}

	addr := net.JoinHostPort(req.DstHost, strconv.Itoa(req.DstPort))
	target, err := m.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		m.limits.ReleaseRelayConn(clientID)
		m.metrics.OpenFailures.WithLabelValues("relay", "tcp_dial").Inc()
		return nil, fmt.Errorf("dial target: %w", err)
	}

	connID, err := newConnID()
	if err != nil {
		_ = target.Close()
		m.limits.ReleaseRelayConn(clientID)
		return nil, err
	}

	connLogger := m.logger.With(
		zap.String("conn_id", connID),
		zap.String("client_id", clientID),
		zap.String("dst", addr),
	)

	conn := newRelayConn(
		connID,
		clientID,
		target,
		m.cfg.RecvWindow,
		m.cfg.SendWindow,
		m.cfg.IdleTimeout,
		connLogger,
		m.onConnClosed,
	)

	m.mu.Lock()
	m.conns[connID] = conn
	m.mu.Unlock()

	m.ttlStore.Add(&store.RelayState{
		ConnID:     connID,
		ClientID:   clientID,
		LastActive: time.Now(),
		CreatedAt:  time.Now(),
	}, m.cfg.IdleTimeout, func() {
		m.Close(connID, clientID, "idle_timeout")
	})

	conn.Start()
	m.metrics.ActiveRelayConns.Inc()

	connLogger.Info("relay connection opened")

	return &OpenResponse{
		ConnID:      connID,
		ExpiresInMS: m.cfg.IdleTimeout.Milliseconds(),
		RecvWindow:  m.cfg.RecvWindow,
		SendWindow:  m.cfg.SendWindow,
	}, nil
}

func (m *Manager) Send(clientID, connID string, payload []byte) (*SendResponse, error) {
	conn, err := m.getOwnedConn(clientID, connID)
	if err != nil {
		return nil, err
	}

	if err := m.limits.AllowRelayBytes(clientID, len(payload)); err != nil {
		return nil, err
	}

	accepted, queued, err := conn.Enqueue(payload)
	if err != nil {
		return nil, err
	}

	if accepted > 0 {
		m.metrics.BytesIn.WithLabelValues("relay").Add(float64(accepted))
		m.touch(connID)
	}

	return &SendResponse{Accepted: accepted, Queued: queued}, nil
}

func (m *Manager) Recv(clientID, connID string, max int) ([]byte, bool, error) {
	conn, err := m.getOwnedConn(clientID, connID)
	if err != nil {
		return nil, false, err
	}

	if max <= 0 {
		max = 32768
	}
	if max > m.cfg.RecvWindow {
		max = m.cfg.RecvWindow
	}

	data, eos, err := conn.Recv(max)
	if err != nil {
		return nil, false, err
	}

	if len(data) > 0 {
		m.metrics.BytesOut.WithLabelValues("relay").Add(float64(len(data)))
		m.touch(connID)
	}

	if eos && len(data) == 0 {
		m.Close(connID, clientID, "eos_drained")
	}

	return data, eos, nil
}

func (m *Manager) Ping(clientID, connID string) (*PingResponse, error) {
	conn, err := m.getOwnedConn(clientID, connID)
	if err != nil {
		return nil, err
	}
	conn.Ping()
	m.touch(connID)

	return &PingResponse{OK: true, ExpiresInMS: conn.ExpiresInMS()}, nil
}

func (m *Manager) Close(connID, clientID, reason string) bool {
	conn, err := m.getOwnedConn(clientID, connID)
	if err != nil {
		return false
	}
	conn.Close(reason)
	return true
}

func (m *Manager) getOwnedConn(clientID, connID string) (*relayConn, error) {
	m.mu.RLock()
	conn, ok := m.conns[connID]
	m.mu.RUnlock()
	if !ok {
		return nil, ErrUnknownConn
	}
	if conn.clientID != clientID {
		return nil, ErrForbidden
	}
	return conn, nil
}

func (m *Manager) touch(connID string) {
	_ = m.ttlStore.Touch(connID, m.cfg.IdleTimeout)
}

func (m *Manager) onConnClosed(connID, clientID string) {
	m.mu.Lock()
	_, existed := m.conns[connID]
	if existed {
		delete(m.conns, connID)
	}
	m.mu.Unlock()

	if !existed {
		return
	}

	m.ttlStore.Delete(connID)
	m.limits.ReleaseRelayConn(clientID)
	m.metrics.ActiveRelayConns.Dec()
}

func (m *Manager) Shutdown() {
	m.mu.RLock()
	ids := make([]string, 0, len(m.conns))
	clients := make([]string, 0, len(m.conns))
	for id, conn := range m.conns {
		ids = append(ids, id)
		clients = append(clients, conn.clientID)
	}
	m.mu.RUnlock()

	for i := range ids {
		m.Close(ids[i], clients[i], "shutdown")
	}

	if st := m.ttlStore; st != nil {
		st.Close()
	}
}

func newConnID() (string, error) {
	raw := make([]byte, 10)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate conn id: %w", err)
	}
	return "c_" + hex.EncodeToString(raw), nil
}
