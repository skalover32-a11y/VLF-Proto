package limits

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrMaxConnsPerClient     = errors.New("max_conns_per_client exceeded")
	ErrMaxTotalConns         = errors.New("max_total_conns exceeded")
	ErrMaxBytesPerMinute     = errors.New("max_bytes_per_minute exceeded")
	ErrMaxBytesPerMinuteSess = errors.New("max_bytes_per_minute_per_session exceeded")
	ErrMaxUDPPPS             = errors.New("max_udp_pps exceeded")
)

type Config struct {
	MaxConnsPerClient           int
	MaxTotalConns               int
	MaxBytesPerMinutePerClient  int64
	MaxBytesPerMinutePerSession int64
	MaxUDPPPS                   int
}

type byteWindow struct {
	windowStart time.Time
	bytes       int64
}

type ppsWindow struct {
	secondStart time.Time
	packets     int
}

type Manager struct {
	cfg Config

	mu                 sync.Mutex
	totalRelayConns    int
	relayConnsByClient map[string]int
	relayBytesByClient map[string]*byteWindow
	sessionBytes       map[uint64]*byteWindow
	sessionPackets     map[uint64]*ppsWindow
	nowFn              func() time.Time
}

func NewManager(cfg Config) *Manager {
	return &Manager{
		cfg:                cfg,
		relayConnsByClient: make(map[string]int),
		relayBytesByClient: make(map[string]*byteWindow),
		sessionBytes:       make(map[uint64]*byteWindow),
		sessionPackets:     make(map[uint64]*ppsWindow),
		nowFn:              time.Now,
	}
}

func (m *Manager) ReserveRelayConn(clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cfg.MaxTotalConns > 0 && m.totalRelayConns >= m.cfg.MaxTotalConns {
		return ErrMaxTotalConns
	}
	if m.cfg.MaxConnsPerClient > 0 && m.relayConnsByClient[clientID] >= m.cfg.MaxConnsPerClient {
		return ErrMaxConnsPerClient
	}

	m.totalRelayConns++
	m.relayConnsByClient[clientID]++
	return nil
}

func (m *Manager) ReleaseRelayConn(clientID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.totalRelayConns > 0 {
		m.totalRelayConns--
	}
	if count := m.relayConnsByClient[clientID]; count > 1 {
		m.relayConnsByClient[clientID] = count - 1
	} else {
		delete(m.relayConnsByClient, clientID)
	}
}

func (m *Manager) RelayCounts() (total int, byClient map[string]int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	copied := make(map[string]int, len(m.relayConnsByClient))
	for k, v := range m.relayConnsByClient {
		copied[k] = v
	}
	return m.totalRelayConns, copied
}

func (m *Manager) AllowRelayBytes(clientID string, n int) error {
	if n <= 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.nowFn()
	window := m.relayBytesByClient[clientID]
	if window == nil {
		window = &byteWindow{windowStart: now}
		m.relayBytesByClient[clientID] = window
	}

	if now.Sub(window.windowStart) >= time.Minute {
		window.windowStart = now
		window.bytes = 0
	}

	limit := m.cfg.MaxBytesPerMinutePerClient
	if limit > 0 && window.bytes+int64(n) > limit {
		return fmt.Errorf("%w: client=%s used=%d add=%d limit=%d", ErrMaxBytesPerMinute, clientID, window.bytes, n, limit)
	}

	window.bytes += int64(n)
	return nil
}

func (m *Manager) AllowSessionBytes(sessionID uint64, n int) error {
	if n <= 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.nowFn()
	window := m.sessionBytes[sessionID]
	if window == nil {
		window = &byteWindow{windowStart: now}
		m.sessionBytes[sessionID] = window
	}

	if now.Sub(window.windowStart) >= time.Minute {
		window.windowStart = now
		window.bytes = 0
	}

	limit := m.cfg.MaxBytesPerMinutePerSession
	if limit > 0 && window.bytes+int64(n) > limit {
		return fmt.Errorf("%w: session=%d used=%d add=%d limit=%d", ErrMaxBytesPerMinuteSess, sessionID, window.bytes, n, limit)
	}

	window.bytes += int64(n)
	return nil
}

func (m *Manager) AllowUDPPacket(sessionID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.nowFn().Truncate(time.Second)
	window := m.sessionPackets[sessionID]
	if window == nil {
		window = &ppsWindow{secondStart: now}
		m.sessionPackets[sessionID] = window
	}

	if !window.secondStart.Equal(now) {
		window.secondStart = now
		window.packets = 0
	}

	limit := m.cfg.MaxUDPPPS
	if limit > 0 && window.packets >= limit {
		return fmt.Errorf("%w: session=%d limit=%d", ErrMaxUDPPPS, sessionID, limit)
	}

	window.packets++
	return nil
}

func (m *Manager) CleanupSession(sessionID uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessionBytes, sessionID)
	delete(m.sessionPackets, sessionID)
}
