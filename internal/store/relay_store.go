package store

import (
	"sync"
	"time"
)

type RelayState struct {
	ConnID     string
	ClientID   string
	LastActive time.Time
	CreatedAt  time.Time
}

type RelayStore struct {
	mu       sync.RWMutex
	byID     map[string]*RelayState
	byClient map[string]map[string]struct{}
	wheel    *Wheel
}

func NewRelayStore(wheel *Wheel) *RelayStore {
	return &RelayStore{
		byID:     make(map[string]*RelayState),
		byClient: make(map[string]map[string]struct{}),
		wheel:    wheel,
	}
}

func (s *RelayStore) Add(st *RelayState, ttl time.Duration, onExpire func()) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.byID[st.ConnID] = st
	set := s.byClient[st.ClientID]
	if set == nil {
		set = make(map[string]struct{})
		s.byClient[st.ClientID] = set
	}
	set[st.ConnID] = struct{}{}

	s.wheel.Upsert(RelayKey(st.ConnID), ttl, onExpire)
}

func (s *RelayStore) Touch(connID string, ttl time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.byID[connID]
	if !ok {
		return false
	}
	st.LastActive = time.Now()
	return s.wheel.Touch(RelayKey(connID), ttl)
}

func (s *RelayStore) Get(connID string) (*RelayState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	st, ok := s.byID[connID]
	if !ok {
		return nil, false
	}
	cp := *st
	return &cp, true
}

func (s *RelayStore) Delete(connID string) *RelayState {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.byID[connID]
	if !ok {
		return nil
	}

	delete(s.byID, connID)
	if set := s.byClient[st.ClientID]; set != nil {
		delete(set, connID)
		if len(set) == 0 {
			delete(s.byClient, st.ClientID)
		}
	}
	s.wheel.Remove(RelayKey(connID))

	cp := *st
	return &cp
}

func (s *RelayStore) CountTotal() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

func (s *RelayStore) CountByClient(clientID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byClient[clientID])
}

func (s *RelayStore) Close() {
	if s.wheel != nil {
		s.wheel.Close()
	}
}
