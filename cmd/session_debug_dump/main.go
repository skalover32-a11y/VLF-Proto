package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"vlf-runtime/internal/auth"
	"vlf-runtime/internal/sessionclient"
	"vlf-runtime/internal/transport/resume"
)

func main() {
	cfg, err := sessionclient.LoadConfigFromEnv()
	if err != nil {
		fatalf("load session config: %v", err)
	}

	serverHost := flag.String("server", cfg.GatewayHost, "gateway host")
	serverIP := flag.String("server-ip", cfg.GatewayDialHost, "optional direct dial host/ip override")
	tlsServerName := flag.String("tls-server-name", cfg.TLSServerName, "optional TLS SNI override")
	portUDP := flag.Int("port-udp", cfg.GatewayUDP, "gateway QUIC/UDP port")
	portTCP := flag.Int("port-tcp", cfg.GatewayTCP, "gateway TCP session port")
	transport := flag.String("transport", "auto", "transport preference: auto|quic|tcp")
	timeout := flag.Duration("timeout", 5*time.Second, "dial timeout")
	probe := flag.Bool("probe", false, "send one RTT probe before dumping state")
	profilesEnabled := flag.Bool("profiles", cfg.TransportProfilesEnabled, "enable transport profiles in auth path")
	scoringEnabled := flag.Bool("scoring", cfg.ProfileScoringEnabled, "enable profile scoring")
	migrationEnabled := flag.Bool("migration", cfg.ProfileMigrationEnabled, "enable profile migration")
	resumeEnabled := flag.Bool("resume", cfg.ResumeTokensEnabled, "enable resume tokens")
	profileID := flag.String("profile", cfg.TransportProfileID, "transport profile id")
	clientID := flag.String("client-id", cfg.ClientID, "override client id")
	secretRaw := flag.String("secret", "", "override secret (plain or b64:...)")
	debug := flag.Bool("debug", cfg.Debug, "enable sessionclient debug logs")
	flag.Parse()

	cfg.GatewayHost = strings.TrimSpace(*serverHost)
	if dialHost := strings.TrimSpace(*serverIP); dialHost != "" {
		cfg.GatewayDialHost = dialHost
	} else {
		cfg.GatewayDialHost = cfg.GatewayHost
	}
	if sni := strings.TrimSpace(*tlsServerName); sni != "" {
		cfg.TLSServerName = sni
	} else if cfg.TLSServerName == "" {
		cfg.TLSServerName = cfg.GatewayHost
	}
	cfg.GatewayUDP = *portUDP
	cfg.GatewayTCP = *portTCP
	cfg.TransportProfilesEnabled = *profilesEnabled
	cfg.ProfileScoringEnabled = *scoringEnabled
	cfg.ProfileMigrationEnabled = *migrationEnabled
	cfg.ResumeTokensEnabled = *resumeEnabled
	cfg.TransportProfileID = strings.TrimSpace(*profileID)
	cfg.ClientID = strings.TrimSpace(*clientID)
	cfg.Debug = *debug
	if cfg.ResumeTokensEnabled && cfg.ResumeStore == nil {
		cfg.ResumeStore = resume.NewMemoryStore()
	}

	if raw := strings.TrimSpace(*secretRaw); raw != "" {
		secret, err := auth.ParseSecretString(raw)
		if err != nil {
			fatalf("parse --secret: %v", err)
		}
		cfg.Secret = secret
	}

	switch strings.ToLower(strings.TrimSpace(*transport)) {
	case "", "auto":
	case "quic":
		cfg.DisableQUIC = false
		cfg.DisableTCPSession = true
		cfg.AllowRelay = false
	case "tcp":
		cfg.DisableQUIC = true
		cfg.DisableTCPSession = false
		cfg.AllowRelay = false
	default:
		fatalf("invalid --transport=%q (allowed: auto|quic|tcp)", *transport)
	}

	if *timeout > 0 {
		cfg.QUICTimeout = *timeout
		cfg.TCPTimeout = *timeout
	}
	dialTimeout := *timeout
	if dialTimeout <= 0 {
		dialTimeout = 5 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	client, err := sessionclient.Dial(ctx, cfg)
	if err != nil {
		fatalf("dial: %v", err)
	}
	defer client.Close()

	if *probe {
		probeCtx, probeCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _ = client.ProbeRTT(probeCtx)
		probeCancel()
	}

	raw, err := client.DebugDumpJSON()
	if err != nil {
		fatalf("debug dump: %v", err)
	}
	_, _ = os.Stdout.Write(raw)
	_, _ = os.Stdout.Write([]byte("\n"))
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
