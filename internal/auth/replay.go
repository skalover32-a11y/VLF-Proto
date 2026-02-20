package auth

import (
	"errors"
	"sync"
	"time"
)

var ErrReplay = errors.New("replayed nonce")

type ReplayCache struct {
	ttl   time.Duration
	mu    sync.Mutex
	items map[string]map[string]time.Time
}

func NewReplayCache(ttl time.Duration) *ReplayCache {
	return &ReplayCache{
		ttl:   ttl,
		items: make(map[string]map[string]time.Time),
	}
}

func (r *ReplayCache) CheckAndStore(clientID, nonce string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	clientNonces, ok := r.items[clientID]
	if !ok {
		clientNonces = make(map[string]time.Time)
		r.items[clientID] = clientNonces
	}

	cutoff := now.Add(-r.ttl)
	for key, ts := range clientNonces {
		if ts.Before(cutoff) {
			delete(clientNonces, key)
		}
	}

	if ts, ok := clientNonces[nonce]; ok && ts.After(cutoff) {
		return ErrReplay
	}

	clientNonces[nonce] = now
	return nil
}
