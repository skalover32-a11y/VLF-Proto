package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	ErrMissingHeaders = errors.New("missing auth headers")
	ErrClockSkew      = errors.New("clock skew exceeded")
	ErrBadSignature   = errors.New("invalid signature")
)

type VerifyHooks struct {
	OnAuthFail   func(clientID string)
	OnReplayDrop func(clientID string)
}

type Verifier struct {
	secrets   SecretProvider
	replay    *ReplayCache
	clockSkew time.Duration
	hooks     VerifyHooks
	nowFn     func() time.Time
}

func NewVerifier(secrets SecretProvider, replay *ReplayCache, clockSkew time.Duration, hooks VerifyHooks) *Verifier {
	return &Verifier{
		secrets:   secrets,
		replay:    replay,
		clockSkew: clockSkew,
		hooks:     hooks,
		nowFn:     time.Now,
	}
}

func HashBody(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func (v *Verifier) VerifyHTTP(r *http.Request, body []byte) (string, error) {
	clientID := strings.TrimSpace(r.Header.Get("X-VLF-Client"))
	tsRaw := strings.TrimSpace(r.Header.Get("X-VLF-TS"))
	nonce := strings.TrimSpace(r.Header.Get("X-VLF-Nonce"))
	sigHex := strings.TrimSpace(r.Header.Get("X-VLF-Sig"))

	if clientID == "" || tsRaw == "" || nonce == "" || sigHex == "" {
		v.markAuthFail(clientID)
		return "", ErrMissingHeaders
	}

	tsMS, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		v.markAuthFail(clientID)
		return "", fmt.Errorf("parse X-VLF-TS: %w", err)
	}

	now := v.nowFn()
	reqTime := time.UnixMilli(tsMS)
	if skew := now.Sub(reqTime); skew > v.clockSkew || skew < -v.clockSkew {
		v.markAuthFail(clientID)
		return "", ErrClockSkew
	}

	secret, err := v.secrets.SecretFor(clientID)
	if err != nil {
		v.markAuthFail(clientID)
		return "", err
	}

	bodyHash := HashBody(body)
	material := fmt.Sprintf("%s|%s|%d|%s|%s", strings.ToUpper(r.Method), r.URL.Path, tsMS, nonce, bodyHash)
	expected := computeHMAC(secret, []byte(material))

	providedSig, err := hex.DecodeString(sigHex)
	if err != nil {
		v.markAuthFail(clientID)
		return "", fmt.Errorf("decode signature: %w", err)
	}

	if !hmac.Equal(expected, providedSig) {
		v.markAuthFail(clientID)
		return "", ErrBadSignature
	}

	if err := v.replay.CheckAndStore(clientID, nonce, now); err != nil {
		if errors.Is(err, ErrReplay) {
			v.markReplay(clientID)
		} else {
			v.markAuthFail(clientID)
		}
		return "", err
	}

	return clientID, nil
}

func SessionAuthMaterial(clientID string, tsMS uint64, nonce []byte, caps uint64) []byte {
	nonceHex := hex.EncodeToString(nonce)
	return []byte(fmt.Sprintf("AUTH|%s|%d|%s|%d", clientID, tsMS, nonceHex, caps))
}

func (v *Verifier) SignSession(clientID string, tsMS uint64, nonce []byte, caps uint64) ([]byte, error) {
	secret, err := v.secrets.SecretFor(clientID)
	if err != nil {
		return nil, err
	}
	return computeHMAC(secret, SessionAuthMaterial(clientID, tsMS, nonce, caps)), nil
}

func (v *Verifier) VerifySession(clientID string, tsMS uint64, nonce, sig []byte, caps uint64) error {
	if clientID == "" || len(nonce) == 0 || len(sig) == 0 {
		v.markAuthFail(clientID)
		return ErrMissingHeaders
	}
	if len(nonce) < 12 || len(nonce) > 32 {
		v.markAuthFail(clientID)
		return fmt.Errorf("nonce size must be 12..32, got %d", len(nonce))
	}

	now := v.nowFn()
	reqTime := time.UnixMilli(int64(tsMS))
	if skew := now.Sub(reqTime); skew > v.clockSkew || skew < -v.clockSkew {
		v.markAuthFail(clientID)
		return ErrClockSkew
	}

	secret, err := v.secrets.SecretFor(clientID)
	if err != nil {
		v.markAuthFail(clientID)
		return err
	}

	expected := computeHMAC(secret, SessionAuthMaterial(clientID, tsMS, nonce, caps))
	if !hmac.Equal(expected, sig) {
		v.markAuthFail(clientID)
		return ErrBadSignature
	}

	nonceKey := hex.EncodeToString(nonce)
	if err := v.replay.CheckAndStore(clientID, nonceKey, now); err != nil {
		if errors.Is(err, ErrReplay) {
			v.markReplay(clientID)
		} else {
			v.markAuthFail(clientID)
		}
		return err
	}

	return nil
}

func computeHMAC(secret, payload []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func EncodeUint64(v uint64) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, v)
	return out
}

func (v *Verifier) markAuthFail(clientID string) {
	if v.hooks.OnAuthFail != nil {
		v.hooks.OnAuthFail(clientID)
	}
}

func (v *Verifier) markReplay(clientID string) {
	if v.hooks.OnReplayDrop != nil {
		v.hooks.OnReplayDrop(clientID)
	}
}
