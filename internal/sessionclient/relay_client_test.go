package sessionclient

import (
	"sync"
	"testing"
)

func TestNewRelayNonce_UniqueConcurrent(t *testing.T) {
	const total = 5000

	seen := make(map[string]struct{}, total)
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(total)

	for i := 0; i < total; i++ {
		go func() {
			defer wg.Done()
			nonce := newRelayNonce()
			if nonce == "" {
				t.Errorf("empty nonce")
				return
			}

			mu.Lock()
			if _, ok := seen[nonce]; ok {
				t.Errorf("duplicate nonce detected: %s", nonce)
			} else {
				seen[nonce] = struct{}{}
			}
			mu.Unlock()
		}()
	}

	wg.Wait()
}
