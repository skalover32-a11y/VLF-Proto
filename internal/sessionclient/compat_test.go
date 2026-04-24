package sessionclient

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"vlf-runtime/internal/session"
	"vlf-runtime/internal/transport/profile"
	"vlf-runtime/internal/transport/resume"
)

type mockTCPSessionServerOptions struct {
	strictLegacyAuth bool
	authOKProfileID  string
	sendResumeTail   bool
	allowProfileSet  bool
}

type mockQUICSessionServerOptions struct {
	strictLegacyAuth              bool
	closeExtendedAuthWithoutReply bool
	authOKProfileID               string
	sendResumeTail                bool
	allowProfileSet               bool
}

type mockTCPSessionServer struct {
	addr            string
	listener        net.Listener
	done            chan struct{}
	connectionCount atomic.Int32
	authCount       atomic.Int32
	profileSetCount atomic.Int32
}

type mockQUICSessionServer struct {
	addr            string
	listener        *quic.Listener
	done            chan struct{}
	connectionCount atomic.Int32
	authCount       atomic.Int32
	profileSetCount atomic.Int32
}

func startMockTCPSessionServer(t *testing.T, opts mockTCPSessionServerOptions) *mockTCPSessionServer {
	t.Helper()

	tlsConf := newTestServerTLSConfig(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConf)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}

	srv := &mockTCPSessionServer{
		addr:     ln.Addr().String(),
		listener: ln,
		done:     make(chan struct{}),
	}

	go func() {
		defer close(srv.done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				return
			}
			srv.connectionCount.Add(1)
			go srv.handleConn(conn, opts)
		}
	}()

	t.Cleanup(func() {
		_ = srv.Close()
	})
	return srv
}

func startMockQUICSessionServer(t *testing.T, opts mockQUICSessionServerOptions) *mockQUICSessionServer {
	t.Helper()

	tlsConf := newTestServerTLSConfig(t)
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("quic.ListenAddr: %v", err)
	}

	srv := &mockQUICSessionServer{
		addr:     ln.Addr().String(),
		listener: ln,
		done:     make(chan struct{}),
	}

	go func() {
		defer close(srv.done)
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			srv.connectionCount.Add(1)
			go srv.handleConn(conn, opts)
		}
	}()

	t.Cleanup(func() {
		_ = srv.Close()
	})
	return srv
}

func (s *mockTCPSessionServer) Close() error {
	if s == nil || s.listener == nil {
		return nil
	}
	err := s.listener.Close()
	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
	}
	return err
}

func (s *mockQUICSessionServer) Close() error {
	if s == nil || s.listener == nil {
		return nil
	}
	err := s.listener.Close()
	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
	}
	return err
}

func (s *mockTCPSessionServer) handleConn(conn net.Conn, opts mockTCPSessionServerOptions) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)
	frame, err := session.ReadFrame(reader)
	if err != nil {
		return
	}
	if frame.Type != session.FrameAUTH {
		return
	}
	s.authCount.Add(1)

	authPayload, err := session.DecodeAuthPayload(frame.Payload)
	if err != nil {
		_ = session.WriteFrame(conn, session.FrameAUTHFAIL, session.EncodeAuthFail("invalid AUTH payload"))
		return
	}
	if opts.strictLegacyAuth && (authPayload.ProfileID != "" || len(authPayload.ResumeTag) > 0 || len(authPayload.ResumeToken) > 0) {
		_ = session.WriteFrame(conn, session.FrameAUTHFAIL, session.EncodeAuthFail("invalid AUTH payload"))
		return
	}

	authOK := session.AuthOKPayload{
		SessionID: 99,
		ExpiresMS: uint32((45 * time.Second) / time.Millisecond),
		UpKbps:    1000,
		DownKbps:  1000,
		MaxFlows:  16,
		MaxUDPPPS: 900,
		ProfileID: opts.authOKProfileID,
	}
	if opts.sendResumeTail {
		authOK.ResumeTag = []byte("resume-tag")
		authOK.ResumeToken = []byte("resume-token")
	}
	if err := session.WriteFrame(conn, session.FrameAUTHOK, session.EncodeAuthOKPayload(authOK)); err != nil {
		return
	}

	for {
		frame, err := session.ReadFrame(reader)
		if err != nil {
			return
		}
		switch frame.Type {
		case session.FramePING:
			_ = session.WriteFrame(conn, session.FramePONG, frame.Payload)
		case session.FramePROFILESET:
			s.profileSetCount.Add(1)
			profilePayload, err := session.DecodeProfilePayload(frame.Payload)
			if err != nil {
				_ = session.WriteFrame(conn, session.FramePROFILEFAIL, session.EncodeProfilePayload(session.ProfilePayload{Reason: "invalid profile payload"}))
				continue
			}
			if !opts.allowProfileSet {
				_ = session.WriteFrame(conn, session.FramePROFILEFAIL, session.EncodeProfilePayload(session.ProfilePayload{
					ProfileID: profilePayload.ProfileID,
					Reason:    "profile migration disabled",
				}))
				continue
			}
			_ = session.WriteFrame(conn, session.FramePROFILEOK, session.EncodeProfilePayload(session.ProfilePayload{
				ProfileID: profilePayload.ProfileID,
			}))
		}
	}
}

func (s *mockQUICSessionServer) handleConn(conn *quic.Conn, opts mockQUICSessionServerOptions) {
	defer func() {
		_ = conn.CloseWithError(0, "test_done")
	}()

	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		return
	}
	defer stream.Close()

	reader := bufio.NewReader(stream)
	frame, err := session.ReadFrame(reader)
	if err != nil {
		return
	}
	if frame.Type != session.FrameAUTH {
		return
	}
	s.authCount.Add(1)

	authPayload, err := session.DecodeAuthPayload(frame.Payload)
	if err != nil {
		_ = session.WriteFrame(stream, session.FrameAUTHFAIL, session.EncodeAuthFail("invalid AUTH payload"))
		return
	}
	if opts.strictLegacyAuth && (authPayload.ProfileID != "" || len(authPayload.ResumeTag) > 0 || len(authPayload.ResumeToken) > 0) {
		if opts.closeExtendedAuthWithoutReply {
			return
		}
		_ = session.WriteFrame(stream, session.FrameAUTHFAIL, session.EncodeAuthFail("invalid AUTH payload"))
		return
	}

	authOK := session.AuthOKPayload{
		SessionID: 99,
		ExpiresMS: uint32((45 * time.Second) / time.Millisecond),
		UpKbps:    1000,
		DownKbps:  1000,
		MaxFlows:  16,
		MaxUDPPPS: 900,
		ProfileID: opts.authOKProfileID,
	}
	if opts.sendResumeTail {
		authOK.ResumeTag = []byte("resume-tag")
		authOK.ResumeToken = []byte("resume-token")
	}
	if err := session.WriteFrame(stream, session.FrameAUTHOK, session.EncodeAuthOKPayload(authOK)); err != nil {
		return
	}

	for {
		frame, err := session.ReadFrame(reader)
		if err != nil {
			return
		}
		switch frame.Type {
		case session.FramePING:
			_ = session.WriteFrame(stream, session.FramePONG, frame.Payload)
		case session.FramePROFILESET:
			s.profileSetCount.Add(1)
			profilePayload, err := session.DecodeProfilePayload(frame.Payload)
			if err != nil {
				_ = session.WriteFrame(stream, session.FramePROFILEFAIL, session.EncodeProfilePayload(session.ProfilePayload{Reason: "invalid profile payload"}))
				continue
			}
			if !opts.allowProfileSet {
				_ = session.WriteFrame(stream, session.FramePROFILEFAIL, session.EncodeProfilePayload(session.ProfilePayload{
					ProfileID: profilePayload.ProfileID,
					Reason:    "profile migration disabled",
				}))
				continue
			}
			_ = session.WriteFrame(stream, session.FramePROFILEOK, session.EncodeProfilePayload(session.ProfilePayload{
				ProfileID: profilePayload.ProfileID,
			}))
		}
	}
}

func newTestServerTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"vlf-runtime/0.1", "vlf-session/0.1"},
	}
}

func newTestDialConfig(addr string) Config {
	host, portRaw, _ := net.SplitHostPort(addr)
	port, _ := net.LookupPort("tcp", portRaw)
	return Config{
		GatewayHost:        host,
		GatewayDialHost:    host,
		GatewayTCP:         port,
		ClientID:           "smoke-client",
		Secret:             []byte("smoke-secret"),
		TLSServerName:      "localhost",
		TCPTimeout:         2 * time.Second,
		DisableQUIC:        true,
		DisableTCPSession:  false,
		AllowRelay:         false,
		TransportProfileID: profile.ProfileBalanced,
		ProfileRegistry:    profile.DefaultRegistry(),
	}
}

func newTestQUICDialConfig(addr string) Config {
	host, portRaw, _ := net.SplitHostPort(addr)
	port, _ := net.LookupPort("udp", portRaw)
	return Config{
		GatewayHost:        host,
		GatewayDialHost:    host,
		GatewayUDP:         port,
		ClientID:           "smoke-client",
		Secret:             []byte("smoke-secret"),
		TLSServerName:      "localhost",
		QUICTimeout:        2 * time.Second,
		DisableQUIC:        false,
		DisableTCPSession:  true,
		AllowRelay:         false,
		TransportProfileID: profile.ProfileBalanced,
		ProfileRegistry:    profile.DefaultRegistry(),
	}
}

func preloadResumeState(cfg *Config) {
	cfg.ResumeTokensEnabled = true
	store := resume.NewMemoryStore()
	store.Save(resume.Key(firstNonEmpty(cfg.GatewayHost, cfg.GatewayDialHost), cfg.ClientID), resume.State{
		Tag:        []byte("resume-tag"),
		Token:      []byte("resume-token"),
		ExpiresAt:  time.Now().Add(5 * time.Minute),
		ProfileID:  profile.ProfileBalanced,
		PathFamily: "tcp-session",
		Lineage:    77,
	})
	cfg.ResumeStore = store
}

func preloadResumeStateForPath(cfg *Config, pathFamily string) {
	cfg.ResumeTokensEnabled = true
	store := resume.NewMemoryStore()
	store.Save(resume.Key(firstNonEmpty(cfg.GatewayHost, cfg.GatewayDialHost), cfg.ClientID), resume.State{
		Tag:        []byte("resume-tag"),
		Token:      []byte("resume-token"),
		ExpiresAt:  time.Now().Add(5 * time.Minute),
		ProfileID:  profile.ProfileBalanced,
		PathFamily: pathFamily,
		Lineage:    77,
	})
	cfg.ResumeStore = store
}

func TestTCPSessionLegacyServerFallbacksCleanly(t *testing.T) {
	srv := startMockTCPSessionServer(t, mockTCPSessionServerOptions{strictLegacyAuth: true})

	cfg := newTestDialConfig(srv.addr)
	cfg.TransportProfilesEnabled = true
	preloadResumeState(&cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	if got := srv.connectionCount.Load(); got != 2 {
		t.Fatalf("connection_count=%d, want 2 (extended auth fallback to legacy)", got)
	}
	if got := srv.authCount.Load(); got != 2 {
		t.Fatalf("auth_count=%d, want 2", got)
	}
	if _, err := client.ProbeRTT(ctx); err != nil {
		t.Fatalf("ProbeRTT after legacy fallback: %v", err)
	}

	snapshot, ok := client.DebugSnapshot()
	if !ok {
		t.Fatal("DebugSnapshot unavailable")
	}
	if !snapshot.LegacyPeerFallback {
		t.Fatal("LegacyPeerFallback=false, want true")
	}
	if !snapshot.ProfileSwitchUnsupported {
		t.Fatal("ProfileSwitchUnsupported=false, want true after legacy fallback")
	}
	if snapshot.ResumePath != ResumePathLegacyFallback {
		t.Fatalf("ResumePath=%q, want %q", snapshot.ResumePath, ResumePathLegacyFallback)
	}
}

func TestTCPSessionProfilesOnlyModernPeer(t *testing.T) {
	srv := startMockTCPSessionServer(t, mockTCPSessionServerOptions{
		authOKProfileID: profile.ProfileLowObservable,
	})

	cfg := newTestDialConfig(srv.addr)
	cfg.TransportProfilesEnabled = true
	cfg.TransportProfileID = profile.ProfileLowObservable

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	if got := srv.connectionCount.Load(); got != 1 {
		t.Fatalf("connection_count=%d, want 1", got)
	}
	snapshot, ok := client.DebugSnapshot()
	if !ok {
		t.Fatal("DebugSnapshot unavailable")
	}
	if snapshot.ActiveProfile != profile.ProfileLowObservable {
		t.Fatalf("ActiveProfile=%q, want %q", snapshot.ActiveProfile, profile.ProfileLowObservable)
	}
	if snapshot.LegacyPeerFallback {
		t.Fatal("LegacyPeerFallback=true, want false")
	}
	if snapshot.ResumePath != ResumePathFullAuth {
		t.Fatalf("ResumePath=%q, want %q", snapshot.ResumePath, ResumePathFullAuth)
	}
	if _, ok := snapshot.TimeSpentPerProfile[snapshot.ActiveProfile]; !ok {
		t.Fatalf("time_spent_per_profile missing active profile %s", snapshot.ActiveProfile)
	}
	if got := srv.profileSetCount.Load(); got != 0 {
		t.Fatalf("profile_set_count=%d, want 0", got)
	}
}

func TestTCPSessionProfilesScoringWithoutMigrationStaysLegacyControlPath(t *testing.T) {
	srv := startMockTCPSessionServer(t, mockTCPSessionServerOptions{
		authOKProfileID: profile.ProfileBalanced,
	})

	cfg := newTestDialConfig(srv.addr)
	cfg.TransportProfilesEnabled = true
	cfg.ProfileScoringEnabled = true
	cfg.ProfileMigrationEnabled = false

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	if _, err := client.ProbeRTT(ctx); err != nil {
		t.Fatalf("ProbeRTT: %v", err)
	}
	healthSnapshot, ok := client.HealthSnapshot()
	if !ok {
		t.Fatal("HealthSnapshot unavailable")
	}
	if healthSnapshot.Score <= 0 {
		t.Fatalf("health_score=%d, want > 0", healthSnapshot.Score)
	}
	debugSnapshot, ok := client.DebugSnapshot()
	if !ok {
		t.Fatal("DebugSnapshot unavailable")
	}
	if debugSnapshot.MigrationAttempts != 0 {
		t.Fatalf("migration_attempts=%d, want 0", debugSnapshot.MigrationAttempts)
	}
	if got := srv.profileSetCount.Load(); got != 0 {
		t.Fatalf("profile_set_count=%d, want 0 when migration is disabled", got)
	}
}

func TestTCPSessionResumeEnabledAgainstServerWithoutResumeUsesFullAuthPath(t *testing.T) {
	srv := startMockTCPSessionServer(t, mockTCPSessionServerOptions{
		authOKProfileID: profile.ProfileBalanced,
		sendResumeTail:  false,
	})

	cfg := newTestDialConfig(srv.addr)
	preloadResumeState(&cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	if got := srv.connectionCount.Load(); got != 1 {
		t.Fatalf("connection_count=%d, want 1", got)
	}
	snapshot, ok := client.DebugSnapshot()
	if !ok {
		t.Fatal("DebugSnapshot unavailable")
	}
	if snapshot.ResumePath != ResumePathFullAuth {
		t.Fatalf("ResumePath=%q, want %q when peer does not confirm resume", snapshot.ResumePath, ResumePathFullAuth)
	}
	if snapshot.LegacyPeerFallback {
		t.Fatal("LegacyPeerFallback=true, want false")
	}
}

func TestTCPSessionProfileSwitchUnsupportedFallsBackWithoutLoop(t *testing.T) {
	srv := startMockTCPSessionServer(t, mockTCPSessionServerOptions{
		authOKProfileID: profile.ProfileBalanced,
		allowProfileSet: false,
	})

	cfg := newTestDialConfig(srv.addr)
	cfg.TransportProfilesEnabled = true
	cfg.ProfileScoringEnabled = true
	cfg.ProfileMigrationEnabled = true

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	if err := client.ApplyTransportProfile(ctx, profile.ProfileLowObservable); !errors.Is(err, ErrProfileSwitchUnsupported) {
		t.Fatalf("first ApplyTransportProfile err=%v, want ErrProfileSwitchUnsupported", err)
	}
	if err := client.ApplyTransportProfile(ctx, profile.ProfileSurvival); !errors.Is(err, ErrProfileSwitchUnsupported) {
		t.Fatalf("second ApplyTransportProfile err=%v, want ErrProfileSwitchUnsupported", err)
	}
	if got := srv.profileSetCount.Load(); got != 1 {
		t.Fatalf("profile_set_count=%d, want 1 after peer marked unsupported", got)
	}

	snapshot, ok := client.DebugSnapshot()
	if !ok {
		t.Fatal("DebugSnapshot unavailable")
	}
	if !snapshot.ProfileSwitchUnsupported {
		t.Fatal("ProfileSwitchUnsupported=false, want true")
	}
	if snapshot.MigrationAttempts != 1 {
		t.Fatalf("migration_attempts=%d, want 1", snapshot.MigrationAttempts)
	}
}

func TestDebugDumpJSONIncludesClientVisibleTransportState(t *testing.T) {
	srv := startMockTCPSessionServer(t, mockTCPSessionServerOptions{
		authOKProfileID: profile.ProfileLowObservable,
		sendResumeTail:  true,
	})

	cfg := newTestDialConfig(srv.addr)
	cfg.TransportProfilesEnabled = true
	cfg.ProfileScoringEnabled = true
	preloadResumeState(&cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	if _, err := client.ProbeRTT(ctx); err != nil {
		t.Fatalf("ProbeRTT: %v", err)
	}
	raw, err := client.DebugDumpJSON()
	if err != nil {
		t.Fatalf("DebugDumpJSON: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("DebugDumpJSON returned empty payload")
	}
}

func TestQUICLegacyServerFallbacksCleanly(t *testing.T) {
	srv := startMockQUICSessionServer(t, mockQUICSessionServerOptions{strictLegacyAuth: true})

	cfg := newTestQUICDialConfig(srv.addr)
	cfg.TransportProfilesEnabled = true
	preloadResumeStateForPath(&cfg, "quic")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	if got := srv.connectionCount.Load(); got != 2 {
		t.Fatalf("connection_count=%d, want 2 (extended auth fallback to legacy)", got)
	}
	if got := srv.authCount.Load(); got != 2 {
		t.Fatalf("auth_count=%d, want 2", got)
	}
	if _, err := client.ProbeRTT(ctx); err != nil {
		t.Fatalf("ProbeRTT after legacy fallback: %v", err)
	}

	snapshot, ok := client.DebugSnapshot()
	if !ok {
		t.Fatal("DebugSnapshot unavailable")
	}
	if client.Transport() != TransportQUIC {
		t.Fatalf("transport=%s, want quic", client.Transport())
	}
	if !snapshot.LegacyPeerFallback {
		t.Fatal("LegacyPeerFallback=false, want true")
	}
	if !snapshot.ProfileSwitchUnsupported {
		t.Fatal("ProfileSwitchUnsupported=false, want true after legacy fallback")
	}
	if snapshot.ResumePath != ResumePathLegacyFallback {
		t.Fatalf("ResumePath=%q, want %q", snapshot.ResumePath, ResumePathLegacyFallback)
	}
}

func TestQUICLegacyServerClosesDuringExtendedAuthFallbacksOnce(t *testing.T) {
	srv := startMockQUICSessionServer(t, mockQUICSessionServerOptions{
		strictLegacyAuth:              true,
		closeExtendedAuthWithoutReply: true,
	})

	cfg := newTestQUICDialConfig(srv.addr)
	cfg.TransportProfilesEnabled = true
	preloadResumeStateForPath(&cfg, "quic")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	if got := srv.connectionCount.Load(); got != 2 {
		t.Fatalf("connection_count=%d, want exactly 2 (one extended attempt, one legacy retry)", got)
	}
	if got := srv.authCount.Load(); got != 2 {
		t.Fatalf("auth_count=%d, want exactly 2", got)
	}
	snapshot, ok := client.DebugSnapshot()
	if !ok {
		t.Fatal("DebugSnapshot unavailable")
	}
	if !snapshot.LegacyPeerFallback {
		t.Fatal("LegacyPeerFallback=false, want true")
	}
	if snapshot.ResumePath != ResumePathLegacyFallback {
		t.Fatalf("ResumePath=%q, want %q", snapshot.ResumePath, ResumePathLegacyFallback)
	}
}

func TestQUICProfilesOnlyModernPeer(t *testing.T) {
	srv := startMockQUICSessionServer(t, mockQUICSessionServerOptions{
		authOKProfileID: profile.ProfileLowObservable,
	})

	cfg := newTestQUICDialConfig(srv.addr)
	cfg.TransportProfilesEnabled = true
	cfg.TransportProfileID = profile.ProfileLowObservable

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	if got := srv.connectionCount.Load(); got != 1 {
		t.Fatalf("connection_count=%d, want 1", got)
	}
	snapshot, ok := client.DebugSnapshot()
	if !ok {
		t.Fatal("DebugSnapshot unavailable")
	}
	if snapshot.ActiveProfile != profile.ProfileLowObservable {
		t.Fatalf("ActiveProfile=%q, want %q", snapshot.ActiveProfile, profile.ProfileLowObservable)
	}
	if snapshot.LegacyPeerFallback {
		t.Fatal("LegacyPeerFallback=true, want false")
	}
	if snapshot.ResumePath != ResumePathFullAuth {
		t.Fatalf("ResumePath=%q, want %q", snapshot.ResumePath, ResumePathFullAuth)
	}
	if _, ok := snapshot.TimeSpentPerProfile[snapshot.ActiveProfile]; !ok {
		t.Fatalf("time_spent_per_profile missing active profile %s", snapshot.ActiveProfile)
	}
	if got := srv.profileSetCount.Load(); got != 0 {
		t.Fatalf("profile_set_count=%d, want 0", got)
	}
}

func TestQUICProfilesScoringWithoutMigrationStaysLegacyControlPath(t *testing.T) {
	srv := startMockQUICSessionServer(t, mockQUICSessionServerOptions{
		authOKProfileID: profile.ProfileBalanced,
	})

	cfg := newTestQUICDialConfig(srv.addr)
	cfg.TransportProfilesEnabled = true
	cfg.ProfileScoringEnabled = true
	cfg.ProfileMigrationEnabled = false

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	if _, err := client.ProbeRTT(ctx); err != nil {
		t.Fatalf("ProbeRTT: %v", err)
	}
	healthSnapshot, ok := client.HealthSnapshot()
	if !ok {
		t.Fatal("HealthSnapshot unavailable")
	}
	if healthSnapshot.Score <= 0 {
		t.Fatalf("health_score=%d, want > 0", healthSnapshot.Score)
	}
	debugSnapshot, ok := client.DebugSnapshot()
	if !ok {
		t.Fatal("DebugSnapshot unavailable")
	}
	if debugSnapshot.MigrationAttempts != 0 {
		t.Fatalf("migration_attempts=%d, want 0", debugSnapshot.MigrationAttempts)
	}
	if got := srv.profileSetCount.Load(); got != 0 {
		t.Fatalf("profile_set_count=%d, want 0 when migration is disabled", got)
	}
}

func TestQUICResumeEnabledAgainstServerWithoutResumeUsesFullAuthPath(t *testing.T) {
	srv := startMockQUICSessionServer(t, mockQUICSessionServerOptions{
		authOKProfileID: profile.ProfileBalanced,
		sendResumeTail:  false,
	})

	cfg := newTestQUICDialConfig(srv.addr)
	preloadResumeStateForPath(&cfg, "quic")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	if got := srv.connectionCount.Load(); got != 1 {
		t.Fatalf("connection_count=%d, want 1", got)
	}
	snapshot, ok := client.DebugSnapshot()
	if !ok {
		t.Fatal("DebugSnapshot unavailable")
	}
	if snapshot.ResumePath != ResumePathFullAuth {
		t.Fatalf("ResumePath=%q, want %q when peer does not confirm resume", snapshot.ResumePath, ResumePathFullAuth)
	}
	if snapshot.LegacyPeerFallback {
		t.Fatal("LegacyPeerFallback=true, want false")
	}
}

func TestQUICProfileSwitchUnsupportedFallsBackWithoutLoop(t *testing.T) {
	srv := startMockQUICSessionServer(t, mockQUICSessionServerOptions{
		authOKProfileID: profile.ProfileBalanced,
		allowProfileSet: false,
	})

	cfg := newTestQUICDialConfig(srv.addr)
	cfg.TransportProfilesEnabled = true
	cfg.ProfileScoringEnabled = true
	cfg.ProfileMigrationEnabled = true

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	if err := client.ApplyTransportProfile(ctx, profile.ProfileLowObservable); !errors.Is(err, ErrProfileSwitchUnsupported) {
		t.Fatalf("first ApplyTransportProfile err=%v, want ErrProfileSwitchUnsupported", err)
	}
	if err := client.ApplyTransportProfile(ctx, profile.ProfileSurvival); !errors.Is(err, ErrProfileSwitchUnsupported) {
		t.Fatalf("second ApplyTransportProfile err=%v, want ErrProfileSwitchUnsupported", err)
	}
	if got := srv.profileSetCount.Load(); got != 1 {
		t.Fatalf("profile_set_count=%d, want 1 after peer marked unsupported", got)
	}
	if _, err := client.ProbeRTT(ctx); err != nil {
		t.Fatalf("ProbeRTT after unsupported profile switch: %v", err)
	}

	snapshot, ok := client.DebugSnapshot()
	if !ok {
		t.Fatal("DebugSnapshot unavailable")
	}
	if !snapshot.ProfileSwitchUnsupported {
		t.Fatal("ProfileSwitchUnsupported=false, want true")
	}
	if snapshot.MigrationAttempts != 1 {
		t.Fatalf("migration_attempts=%d, want 1", snapshot.MigrationAttempts)
	}
}
