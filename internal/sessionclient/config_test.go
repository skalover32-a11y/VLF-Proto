package sessionclient

import (
	"strings"
	"testing"
)

func TestBuildProtoIDList(t *testing.T) {
	got := buildProtoIDList(" custom/1 ", []string{"vlf-runtime/0.1", "custom/1", "legacy/0.9", " ", "vlf-session/0.1"})
	want := []string{"custom/1", "vlf-runtime/0.1", "legacy/0.9", "vlf-session/0.1"}

	if len(got) != len(want) {
		t.Fatalf("len mismatch: got=%d want=%d list=%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("item mismatch at %d: got=%q want=%q list=%v", i, got[i], want[i], got)
		}
	}
}

func TestBuildProtoIDListFallbackDefault(t *testing.T) {
	got := buildProtoIDList("", nil)
	if len(got) == 0 {
		t.Fatal("expected non-empty proto list")
	}
	if got[0] != "vlf-runtime/0.1" {
		t.Fatalf("unexpected first proto: %q", got[0])
	}
}

func TestTLSConfigProductionRequiresSPKIPin(t *testing.T) {
	cfg := Config{
		GatewayHost:   "example.com",
		TLSServerName: "example.com",
		Production:    true,
		ProtoID:       "vlf-runtime/0.1",
	}

	if _, err := cfg.TLSConfig(); err == nil {
		t.Fatal("TLSConfig succeeded without SPKI pin in production mode")
	}
}

func TestTLSConfigProductionWithSPKIPin(t *testing.T) {
	cfg := Config{
		GatewayHost:   "example.com",
		TLSServerName: "example.com",
		Production:    true,
		ProtoID:       "vlf-runtime/0.1",
		PinSPKI:       strings.Repeat("A", 43) + "=",
	}

	tlsConf, err := cfg.TLSConfig()
	if err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}
	if tlsConf.VerifyPeerCertificate == nil {
		t.Fatal("VerifyPeerCertificate is nil with production SPKI pin")
	}
}
