package auth

import (
	"errors"
	"fmt"
	"sync"
)

var ErrUnknownClient = errors.New("unknown client")

// SelfSecretProvider wraps a StaticSecretProvider with a Phase-1 fallback:
// when a client is not in the pre-configured map, the client_id itself is used
// as the HMAC secret (secret == client_id == UUID by Phase-1 design contract).
type SelfSecretProvider struct {
	inner *StaticSecretProvider
}

func NewSelfSecretProvider(inner *StaticSecretProvider) *SelfSecretProvider {
	return &SelfSecretProvider{inner: inner}
}

func (p *SelfSecretProvider) SecretFor(clientID string) ([]byte, error) {
	if secret, err := p.inner.SecretFor(clientID); err == nil {
		return secret, nil
	}
	// Phase-1 fallback: clientId IS the secret (raw UTF-8 bytes).
	if clientID == "" {
		return nil, ErrUnknownClient
	}
	return []byte(clientID), nil
}

type SecretProvider interface {
	SecretFor(clientID string) ([]byte, error)
}

type StaticSecretProvider struct {
	mu      sync.RWMutex
	secrets map[string][]byte
}

func NewStaticSecretProvider(secrets map[string]string) (*StaticSecretProvider, error) {
	cp := make(map[string][]byte, len(secrets))
	for k, v := range secrets {
		parsed, err := ParseSecretString(v)
		if err != nil {
			return nil, fmt.Errorf("parse secret for client %q: %w", k, err)
		}
		cp[k] = parsed
	}
	return &StaticSecretProvider{secrets: cp}, nil
}

func (p *StaticSecretProvider) SecretFor(clientID string) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	secret, ok := p.secrets[clientID]
	if !ok {
		return nil, ErrUnknownClient
	}
	out := make([]byte, len(secret))
	copy(out, secret)
	return out, nil
}
