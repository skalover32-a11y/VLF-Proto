package auth

import (
	"encoding/base64"
	"fmt"
	"strings"
)

const base64SecretPrefix = "b64:"

// ParseSecretString normalizes HMAC secret formats:
// - "b64:<base64>" -> decoded bytes
// - everything else -> raw UTF-8 bytes
func ParseSecretString(raw string) ([]byte, error) {
	secret := strings.TrimSpace(raw)
	if secret == "" {
		return nil, fmt.Errorf("secret is empty")
	}

	if strings.HasPrefix(secret, base64SecretPrefix) {
		encoded := strings.TrimSpace(strings.TrimPrefix(secret, base64SecretPrefix))
		if encoded == "" {
			return nil, fmt.Errorf("b64 secret payload is empty")
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(encoded)
		}
		if err != nil {
			return nil, fmt.Errorf("decode b64 secret: %w", err)
		}
		if len(decoded) == 0 {
			return nil, fmt.Errorf("decoded b64 secret is empty")
		}
		return decoded, nil
	}

	return []byte(secret), nil
}
