package resume

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"vlf-runtime/internal/store"
)

var (
	ErrTokenDisabled = errors.New("resume tokens disabled")
	ErrTokenExpired  = errors.New("resume token expired")
	ErrTokenReplay   = errors.New("resume token replayed")
	ErrTokenRejected = errors.New("resume token rejected")
)

type Context struct {
	ClientID   string
	ProfileID  string
	PathFamily string
	Lineage    uint64
}

type State struct {
	Tag        []byte
	Token      []byte
	ExpiresAt  time.Time
	ProfileID  string
	PathFamily string
	Lineage    uint64
}

type Validation struct {
	Context   Context
	ExpiresAt time.Time
	Epoch     uint32
}

type Config struct {
	Enabled        bool
	Secret         []byte
	TokenTTL       time.Duration
	ReplayTTL      time.Duration
	EpochRotation  time.Duration
	LookupTagBytes int
	TokenIDBytes   int
	Now            func() time.Time
}

type epoch struct {
	id        uint32
	secret    []byte
	activated time.Time
}

type entry struct {
	tokenID   string
	ctx       Context
	expiresAt time.Time
	epochID   uint32
}

type Manager struct {
	cfg Config

	mu       sync.Mutex
	active   epoch
	previous *epoch
	nextID   uint32
	entries  map[string]entry
	replayed map[string]time.Time
	wheel    *store.Wheel
}

type Store interface {
	Load(key string) (State, bool)
	Save(key string, state State)
	Clear(key string)
}

type MemoryStore struct {
	mu    sync.RWMutex
	items map[string]State
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{items: make(map[string]State)}
}

func (s *MemoryStore) Load(key string) (State, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out, ok := s.items[key]
	return out, ok
}

func (s *MemoryStore) Save(key string, state State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[key] = state
}

func (s *MemoryStore) Clear(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
}

func Key(serverHost, clientID string) string {
	return strings.TrimSpace(strings.ToLower(serverHost)) + "|" + strings.TrimSpace(strings.ToLower(clientID))
}

func NewManager(cfg Config) (*Manager, error) {
	if !cfg.Enabled {
		return &Manager{cfg: cfg}, nil
	}
	if len(cfg.Secret) < 16 {
		return nil, fmt.Errorf("resume secret must be at least 16 bytes")
	}
	if cfg.TokenTTL <= 0 {
		cfg.TokenTTL = 2 * time.Minute
	}
	if cfg.ReplayTTL <= 0 {
		cfg.ReplayTTL = 2 * time.Minute
	}
	if cfg.EpochRotation <= 0 {
		cfg.EpochRotation = 15 * time.Minute
	}
	if cfg.LookupTagBytes <= 0 {
		cfg.LookupTagBytes = 8
	}
	if cfg.TokenIDBytes <= 0 {
		cfg.TokenIDBytes = 16
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	mgr := &Manager{
		cfg:      cfg,
		entries:  make(map[string]entry),
		replayed: make(map[string]time.Time),
		wheel:    store.NewWheel(time.Second, 512),
	}
	mgr.rotateLocked(cfg.Now())
	return mgr, nil
}

func (m *Manager) Close() {
	if m == nil || m.wheel == nil {
		return
	}
	m.wheel.Close()
}

func (m *Manager) Issue(ctx Context) (State, error) {
	if m == nil || !m.cfg.Enabled {
		return State{}, ErrTokenDisabled
	}
	now := m.cfg.Now()

	m.mu.Lock()
	defer m.mu.Unlock()
	m.rotateIfNeededLocked(now)

	tokenID := make([]byte, m.cfg.TokenIDBytes)
	if _, err := rand.Read(tokenID); err != nil {
		return State{}, err
	}
	expiresAt := now.Add(m.cfg.TokenTTL)
	raw := m.encodeTokenLocked(tokenID, ctx, expiresAt)
	tag := m.lookupTagLocked(tokenID)
	tagKey := base64.RawStdEncoding.EncodeToString(tag)
	m.entries[tagKey] = entry{tokenID: string(tokenID), ctx: ctx, expiresAt: expiresAt, epochID: m.active.id}
	m.wheel.Upsert("resume:"+tagKey, m.cfg.TokenTTL, func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.entries, tagKey)
	})
	return State{Tag: tag, Token: raw, ExpiresAt: expiresAt, ProfileID: ctx.ProfileID, PathFamily: ctx.PathFamily, Lineage: ctx.Lineage}, nil
}

func (m *Manager) Validate(tag, token []byte, clientID, pathFamily string) (Validation, error) {
	if m == nil || !m.cfg.Enabled {
		return Validation{}, ErrTokenDisabled
	}
	now := m.cfg.Now()

	m.mu.Lock()
	defer m.mu.Unlock()
	m.rotateIfNeededLocked(now)

	parsed, err := m.decodeTokenLocked(token)
	if err != nil {
		return Validation{}, ErrTokenRejected
	}
	if !parsed.expiresAt.After(now) {
		return Validation{}, ErrTokenExpired
	}
	tokenKey := parsed.replayKey
	if ts, ok := m.replayed[tokenKey]; ok && now.Sub(ts) < m.cfg.ReplayTTL {
		return Validation{}, ErrTokenReplay
	}
	tagKey := base64.RawStdEncoding.EncodeToString(tag)
	entry, ok := m.entries[tagKey]
	if !ok {
		return Validation{}, ErrTokenRejected
	}
	if entry.tokenID != parsed.tokenID {
		return Validation{}, ErrTokenRejected
	}
	if entry.ctx.ClientID != clientID {
		return Validation{}, ErrTokenRejected
	}
	if entry.ctx.PathFamily != "" && pathFamily != "" && entry.ctx.PathFamily != pathFamily {
		return Validation{}, ErrTokenRejected
	}
	expected := m.macForEpochLocked(parsed.epochID, parsed.payload, entry.ctx)
	if !hmac.Equal(parsed.mac, expected[:16]) {
		return Validation{}, ErrTokenRejected
	}
	m.replayed[tokenKey] = now
	m.wheel.Upsert("resume-replay:"+tokenKey, m.cfg.ReplayTTL, func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.replayed, tokenKey)
	})
	return Validation{Context: entry.ctx, ExpiresAt: entry.expiresAt, Epoch: parsed.epochID}, nil
}

type parsedToken struct {
	epochID   uint32
	expiresAt time.Time
	tokenID   string
	replayKey string
	payload   []byte
	mac       []byte
}

func (m *Manager) encodeTokenLocked(tokenID []byte, ctx Context, expiresAt time.Time) []byte {
	raw := make([]byte, 1+4+4+8+len(tokenID)+16)
	raw[0] = 1
	binary.BigEndian.PutUint32(raw[1:5], m.active.id)
	binary.BigEndian.PutUint32(raw[5:9], uint32(expiresAt.Unix()))
	binary.BigEndian.PutUint64(raw[9:17], ctx.Lineage)
	copy(raw[17:17+len(tokenID)], tokenID)
	mac := m.macForEpochLocked(m.active.id, raw[:17+len(tokenID)], ctx)
	copy(raw[17+len(tokenID):], mac[:16])
	return raw
}

func (m *Manager) decodeTokenLocked(token []byte) (parsedToken, error) {
	minLen := 1 + 4 + 4 + 8 + m.cfg.TokenIDBytes + 16
	if len(token) != minLen || token[0] != 1 {
		return parsedToken{}, ErrTokenRejected
	}
	epochID := binary.BigEndian.Uint32(token[1:5])
	expiresAt := time.Unix(int64(binary.BigEndian.Uint32(token[5:9])), 0)
	tokenIDBytes := append([]byte(nil), token[17:17+m.cfg.TokenIDBytes]...)
	payload := append([]byte(nil), token[:17+m.cfg.TokenIDBytes]...)
	mac := append([]byte(nil), token[17+m.cfg.TokenIDBytes:]...)
	if _, ok := m.secretForEpochLocked(epochID); !ok {
		return parsedToken{}, ErrTokenRejected
	}
	return parsedToken{
		epochID:   epochID,
		expiresAt: expiresAt,
		tokenID:   string(tokenIDBytes),
		replayKey: base64.RawStdEncoding.EncodeToString(token),
		payload:   payload,
		mac:       mac,
	}, nil
}

func (m *Manager) lookupTagLocked(tokenID []byte) []byte {
	mac := computeMAC(m.active.secret, append([]byte("tag|"), tokenID...))
	return append([]byte(nil), mac[:m.cfg.LookupTagBytes]...)
}

func (m *Manager) rotateIfNeededLocked(now time.Time) {
	if m.active.activated.IsZero() || now.Sub(m.active.activated) >= m.cfg.EpochRotation {
		m.rotateLocked(now)
	}
}

func (m *Manager) rotateLocked(now time.Time) {
	nextSecret := computeMAC(m.cfg.Secret, []byte(now.UTC().Format(time.RFC3339Nano)))
	if _, err := rand.Read(nextSecret[:]); err == nil {
	}
	if m.active.id != 0 {
		prev := m.active
		m.previous = &prev
	}
	m.nextID++
	m.active = epoch{id: m.nextID, secret: append([]byte(nil), nextSecret...), activated: now}
}

func (m *Manager) secretForEpochLocked(epochID uint32) ([]byte, bool) {
	if m.active.id == epochID {
		return m.active.secret, true
	}
	if m.previous != nil && m.previous.id == epochID {
		return m.previous.secret, true
	}
	return nil, false
}

func (m *Manager) macForEpochLocked(epochID uint32, payload []byte, ctx Context) []byte {
	secret, ok := m.secretForEpochLocked(epochID)
	if !ok {
		secret = m.active.secret
	}
	bound := append([]byte{}, payload...)
	bound = append(bound, []byte("|")...)
	bound = append(bound, []byte(ctx.ClientID)...)
	bound = append(bound, []byte("|")...)
	bound = append(bound, []byte(ctx.ProfileID)...)
	bound = append(bound, []byte("|")...)
	bound = append(bound, []byte(ctx.PathFamily)...)
	return computeMAC(secret, bound)
}

func computeMAC(secret, payload []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}
