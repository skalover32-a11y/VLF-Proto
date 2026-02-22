//go:build windows

package main

import (
	"testing"
	"time"

	"vlf-runtime/internal/sessionclient"
)

func TestParseResolver(t *testing.T) {
	tests := []struct {
		in        string
		host      string
		port      int
		shouldErr bool
	}{
		{in: "1.1.1.1:53", host: "1.1.1.1", port: 53},
		{in: "8.8.8.8", host: "8.8.8.8", port: 53},
		{in: "dns.google:5353", host: "dns.google", port: 5353},
		{in: "", shouldErr: true},
	}

	for _, tc := range tests {
		host, port, err := parseResolver(tc.in)
		if tc.shouldErr {
			if err == nil {
				t.Fatalf("parseResolver(%q) expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseResolver(%q) unexpected error: %v", tc.in, err)
		}
		if host != tc.host || port != tc.port {
			t.Fatalf("parseResolver(%q) got %s:%d want %s:%d", tc.in, host, port, tc.host, tc.port)
		}
	}
}

func TestDialConfigUDPForcesQUIC(t *testing.T) {
	c := newPolicyController(sessionclient.Config{
		PreferQUIC:        false,
		DisableQUIC:       true,
		DisableTCPSession: false,
		AllowRelay:        true,
	}, modeNormal, statsFormatText)
	defer c.Close()

	cfg, _ := c.dialConfigUDP()
	if !cfg.PreferQUIC {
		t.Fatal("dialConfigUDP must prefer QUIC")
	}
	if cfg.DisableQUIC {
		t.Fatal("dialConfigUDP must enable QUIC")
	}
	if !cfg.DisableTCPSession {
		t.Fatal("dialConfigUDP must disable TCP session")
	}
	if cfg.AllowRelay {
		t.Fatal("dialConfigUDP must disable relay")
	}
}

func TestUDPManagerDefaultIdleTimeout(t *testing.T) {
	c := newPolicyController(sessionclient.Config{}, modeAuto, statsFormatText)
	defer c.Close()

	m := newUDPManager(c, 2*time.Second, udpOptions{})
	defer m.Close()
	if m.opts.IdleTimeout <= 0 {
		t.Fatal("idle timeout must be defaulted")
	}
}

func TestElevationTypeName(t *testing.T) {
	if got := elevationTypeName(tokenElevationTypeFull); got != "full" {
		t.Fatalf("unexpected type name for full: %s", got)
	}
	if got := elevationTypeName(tokenElevationTypeLimited); got != "limited" {
		t.Fatalf("unexpected type name for limited: %s", got)
	}
	if got := elevationTypeName(999); got != "unknown" {
		t.Fatalf("unexpected type name for unknown: %s", got)
	}
}
