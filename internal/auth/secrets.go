package auth

import (
	"errors"
	"sync"
)

var ErrUnknownClient = errors.New("unknown client")

type SecretProvider interface {
	SecretFor(clientID string) (string, error)
}

type StaticSecretProvider struct {
	mu      sync.RWMutex
	secrets map[string]string
}

func NewStaticSecretProvider(secrets map[string]string) *StaticSecretProvider {
	cp := make(map[string]string, len(secrets))
	for k, v := range secrets {
		cp[k] = v
	}
	return &StaticSecretProvider{secrets: cp}
}

func (p *StaticSecretProvider) SecretFor(clientID string) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	secret, ok := p.secrets[clientID]
	if !ok {
		return "", ErrUnknownClient
	}
	return secret, nil
}
