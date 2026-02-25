package main

import (
	"testing"
	"time"
)

func TestParseStatsFormat(t *testing.T) {
	cases := []struct {
		in      string
		want    statsFormat
		wantErr bool
	}{
		{in: "text", want: statsFormatText},
		{in: "json", want: statsFormatJSON},
		{in: "JSON", want: statsFormatJSON},
		{in: "bad", wantErr: true},
	}

	for _, tc := range cases {
		got, err := parseStatsFormat(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("parseStatsFormat(%q) expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseStatsFormat(%q) unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("parseStatsFormat(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestAdaptiveCapEnableDisableByRTT(t *testing.T) {
	now := time.Now()
	c := &policyController{
		configured:     modeAuto,
		currentMode:    modeNormal,
		flows:          make(map[uint64]*flowState),
		pendingPermits: 2,
	}

	high := 300.0
	low := 80.0

	c.mu.Lock()
	c.updateAdaptiveCapLocked(now, 5, &high)
	if c.capEnabled {
		c.mu.Unlock()
		t.Fatal("cap must not enable on first high RTT tick")
	}

	c.updateAdaptiveCapLocked(now.Add(statsPrintInterval), 5, &high)
	if !c.capEnabled {
		c.mu.Unlock()
		t.Fatal("cap must enable on second consecutive high RTT tick")
	}
	if c.capMaxNewPerSec != capMaxNewFlowsPerSecond {
		c.mu.Unlock()
		t.Fatalf("unexpected capMaxNewPerSec=%d", c.capMaxNewPerSec)
	}
	expectedActive := 5 + 2 + capActiveFlowsMargin
	if c.capMaxActiveFlows != expectedActive {
		c.mu.Unlock()
		t.Fatalf("unexpected capMaxActiveFlows=%d want=%d", c.capMaxActiveFlows, expectedActive)
	}

	c.updateAdaptiveCapLocked(now.Add(2*statsPrintInterval), 5, &low)
	c.updateAdaptiveCapLocked(now.Add(3*statsPrintInterval), 5, &low)
	if !c.capEnabled {
		c.mu.Unlock()
		t.Fatal("cap must stay enabled before third low RTT tick")
	}

	c.updateAdaptiveCapLocked(now.Add(4*statsPrintInterval), 5, &low)
	if c.capEnabled {
		c.mu.Unlock()
		t.Fatal("cap must disable on third consecutive low RTT tick")
	}
	c.mu.Unlock()
}
