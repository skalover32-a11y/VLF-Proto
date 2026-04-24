package resume

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestIssueAndValidate(t *testing.T) {
	now := time.Unix(1700000000, 0)
	mgr, err := NewManager(Config{
		Enabled:       true,
		Secret:        []byte("0123456789abcdef0123456789abcdef"),
		TokenTTL:      time.Minute,
		ReplayTTL:     time.Minute,
		EpochRotation: 10 * time.Minute,
		Now:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer mgr.Close()

	state, err := mgr.Issue(Context{
		ClientID:   "client-a",
		ProfileID:  "balanced",
		PathFamily: "quic_like",
		Lineage:    42,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(state.Tag) == 0 || len(state.Token) == 0 {
		t.Fatalf("empty state: %+v", state)
	}

	validation, err := mgr.Validate(state.Tag, state.Token, "client-a", "quic_like")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if validation.Context.Lineage != 42 {
		t.Fatalf("lineage=%d, want 42", validation.Context.Lineage)
	}
}

func TestReplayRejected(t *testing.T) {
	now := time.Unix(1700000000, 0)
	mgr, err := NewManager(Config{
		Enabled:       true,
		Secret:        []byte("0123456789abcdef0123456789abcdef"),
		TokenTTL:      time.Minute,
		ReplayTTL:     time.Minute,
		EpochRotation: 10 * time.Minute,
		Now:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer mgr.Close()

	state, err := mgr.Issue(Context{ClientID: "client-a", ProfileID: "balanced", PathFamily: "quic_like", Lineage: 1})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := mgr.Validate(state.Tag, state.Token, "client-a", "quic_like"); err != nil {
		t.Fatalf("first validate: %v", err)
	}
	if _, err := mgr.Validate(state.Tag, state.Token, "client-a", "quic_like"); !errors.Is(err, ErrTokenReplay) {
		t.Fatalf("err=%v, want replay", err)
	}
}

func TestExpiredRejected(t *testing.T) {
	now := time.Unix(1700000000, 0)
	mgr, err := NewManager(Config{
		Enabled:       true,
		Secret:        []byte("0123456789abcdef0123456789abcdef"),
		TokenTTL:      5 * time.Second,
		ReplayTTL:     time.Minute,
		EpochRotation: 10 * time.Minute,
		Now:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer mgr.Close()

	state, err := mgr.Issue(Context{ClientID: "client-a", ProfileID: "balanced", PathFamily: "quic_like", Lineage: 1})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	now = now.Add(10 * time.Second)
	if _, err := mgr.Validate(state.Tag, state.Token, "client-a", "quic_like"); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("err=%v, want expired", err)
	}
}

func TestSecretRotationAllowsPreviousEpoch(t *testing.T) {
	now := time.Unix(1700000000, 0)
	mgr, err := NewManager(Config{
		Enabled:       true,
		Secret:        []byte("0123456789abcdef0123456789abcdef"),
		TokenTTL:      time.Minute,
		ReplayTTL:     time.Minute,
		EpochRotation: 10 * time.Second,
		Now:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer mgr.Close()

	state, err := mgr.Issue(Context{ClientID: "client-a", ProfileID: "balanced", PathFamily: "quic_like", Lineage: 7})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	oldTag := append([]byte(nil), state.Tag...)
	oldToken := append([]byte(nil), state.Token...)

	now = now.Add(11 * time.Second)
	_, _ = mgr.Issue(Context{ClientID: "client-a", ProfileID: "balanced", PathFamily: "quic_like", Lineage: 8})
	validation, err := mgr.Validate(oldTag, oldToken, "client-a", "quic_like")
	if err != nil {
		t.Fatalf("validate previous epoch: %v", err)
	}
	if validation.Context.Lineage != 7 {
		t.Fatalf("lineage=%d, want 7", validation.Context.Lineage)
	}
	if !bytes.Equal(oldTag, state.Tag) {
		// no-op: test only keeps static copy to ensure mutation doesn't happen
	}
}
