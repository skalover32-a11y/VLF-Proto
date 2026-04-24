package sessionclient

import (
	"testing"
	"time"

	"vlf-runtime/internal/transport/profile"
)

func TestProfileProbePayloadAppliesPaddingPolicy(t *testing.T) {
	token := []byte("ping")
	p := profile.TransportProfile{
		PacketSizeStrategy: profile.PacketSizeStrategy{PaddingTargetBytes: 12},
		PaddingPolicy:      profile.PaddingPolicy{Enabled: true, MaxPaddingBytes: 16},
	}

	payload := profileProbePayload(token, p)
	if got, want := len(payload), 12; got != want {
		t.Fatalf("len(payload)=%d, want %d", got, want)
	}
	if string(payload[:len(token)]) != string(token) {
		t.Fatalf("payload prefix=%q, want %q", payload[:len(token)], token)
	}
}

func TestProfileProbeTimeoutHonorsAckHintBudget(t *testing.T) {
	p := profile.TransportProfile{
		RetryPolicy: profile.RetryPolicy{ProbeBackoff: 1500 * time.Millisecond},
		AckHintPolicy: profile.AckHintPolicy{
			Enabled:        true,
			ExpectedAckGap: 2 * time.Second,
			AckDelayBudget: 250 * time.Millisecond,
		},
	}

	if got, want := profileProbeTimeout(p, time.Second), 2750*time.Millisecond; got != want {
		t.Fatalf("profileProbeTimeout=%s, want %s", got, want)
	}
}

func TestProfileBurstPauseUsesCoalescingBoundary(t *testing.T) {
	p := profile.TransportProfile{
		CoalescingPolicy: profile.CoalescingPolicy{
			Enabled:       true,
			MaxFrames:     2,
			FlushInterval: 3 * time.Millisecond,
		},
	}

	if got := profileBurstPause(p, 0, 3); got != 0 {
		t.Fatalf("profileBurstPause first packet=%s, want 0", got)
	}
	if got, want := profileBurstPause(p, 1, 3), 3*time.Millisecond; got != want {
		t.Fatalf("profileBurstPause boundary=%s, want %s", got, want)
	}
}
