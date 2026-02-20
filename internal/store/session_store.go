package store

import (
	"sync"
	"time"
)

type SessionState struct {
	SessionID  uint64
	ClientID   string
	LastActive time.Time
	CreatedAt  time.Time
}

type SessionStore struct {
	mu    sync.RWMutex
	byID  map[uint64]*SessionState
	wheel *Wheel
}

func NewSessionStore(wheel *Wheel) *SessionStore {
	return &SessionStore{
		byID:  make(map[uint64]*SessionState),
		wheel: wheel,
	}
}

func (s *SessionStore) Add(st *SessionState, ttl time.Duration, onExpire func()) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.byID[st.SessionID] = st
	s.wheel.Upsert(SessionKey(st.SessionID), ttl, onExpire)
}

func (s *SessionStore) Touch(sessionID uint64, ttl time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.byID[sessionID]
	if !ok {
		return false
	}
	st.LastActive = time.Now()
	return s.wheel.Touch(SessionKey(sessionID), ttl)
}

func (s *SessionStore) Delete(sessionID uint64) *SessionState {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.byID[sessionID]
	if !ok {
		return nil
	}

	delete(s.byID, sessionID)
	s.wheel.Remove(SessionKey(sessionID))

	cp := *st
	return &cp
}

func (s *SessionStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

func (s *SessionStore) Close() {
	if s.wheel != nil {
		s.wheel.Close()
	}
}
