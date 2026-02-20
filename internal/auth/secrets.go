package auth

import (
	"errors"
	"fmt"
	"sync"
)

var ErrUnknownClient = errors.New("unknown client")

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
