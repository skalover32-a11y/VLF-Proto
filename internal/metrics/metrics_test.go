package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestUDPPPSHoldWindow(t *testing.T) {
	now := time.Unix(1700000000, 0)
	m := NewWithConfig(Config{
		UDPPPSHoldWindow: 3 * time.Second,
		PPSTickInterval:  time.Hour,
		Now: func() time.Time {
			return now
		},
	})
	defer m.Close()

	for i := 0; i < 7; i++ {
		m.ObserveUDPForwarded()
	}
	m.publishUDPPPS(now)
	if got := testutil.ToFloat64(m.UDPPPS); got != 7 {
		t.Fatalf("expected live pps=7, got %v", got)
	}

	now = now.Add(2 * time.Second)
	m.publishUDPPPS(now)
	if got := testutil.ToFloat64(m.UDPPPS); got != 7 {
		t.Fatalf("expected hold pps=7 before expiry, got %v", got)
	}

	now = now.Add(1500 * time.Millisecond)
	m.publishUDPPPS(now)
	if got := testutil.ToFloat64(m.UDPPPS); got != 0 {
		t.Fatalf("expected pps=0 after hold expiry, got %v", got)
	}
}

func TestUDPPPSUpdatesOnNextLiveWindow(t *testing.T) {
	now := time.Unix(1700001000, 0)
	m := NewWithConfig(Config{
		UDPPPSHoldWindow: 3 * time.Second,
		PPSTickInterval:  time.Hour,
		Now: func() time.Time {
			return now
		},
	})
	defer m.Close()

	for i := 0; i < 5; i++ {
		m.ObserveUDPForwarded()
	}
	m.publishUDPPPS(now)
	if got := testutil.ToFloat64(m.UDPPPS); got != 5 {
		t.Fatalf("expected first live pps=5, got %v", got)
	}

	now = now.Add(5 * time.Second)
	m.publishUDPPPS(now)
	if got := testutil.ToFloat64(m.UDPPPS); got != 0 {
		t.Fatalf("expected pps=0 after idle hold expiry, got %v", got)
	}

	now = now.Add(100 * time.Millisecond)
	for i := 0; i < 3; i++ {
		m.ObserveUDPForwarded()
	}
	m.publishUDPPPS(now)
	if got := testutil.ToFloat64(m.UDPPPS); got != 3 {
		t.Fatalf("expected next live pps=3, got %v", got)
	}
}
