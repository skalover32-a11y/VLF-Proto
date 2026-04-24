package session

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
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"vlf-runtime/internal/auth"
	"vlf-runtime/internal/limits"
	"vlf-runtime/internal/metrics"
	"vlf-runtime/internal/transport/resume"
)

func pipeConnPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	return client, server
}

func newSessionTestTLSConfig(t *testing.T) *tls.Config {
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

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	addr := ln.LocalAddr().String()
	_ = ln.Close()
	return addr
}

func waitForQUICListener(t *testing.T, server *Server) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if server.quicListener != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server QUIC listener did not start in time")
}

func TestTCPSessionLegacyClientGetsLegacyAuthOK(t *testing.T) {
	const (
		clientID  = "client-a"
		secretRaw = "smoke-secret"
	)

	provider, err := auth.NewStaticSecretProvider(map[string]string{clientID: secretRaw})
	if err != nil {
		t.Fatalf("NewStaticSecretProvider: %v", err)
	}
	verifier := auth.NewVerifier(provider, auth.NewReplayCache(time.Minute), time.Minute, auth.VerifyHooks{})
	m := metrics.New()
	defer m.Close()

	resumeMgr, err := resume.NewManager(resume.Config{
		Enabled:       true,
		Secret:        []byte("0123456789abcdef0123456789abcdef"),
		TokenTTL:      time.Minute,
		ReplayTTL:     time.Minute,
		EpochRotation: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer resumeMgr.Close()

	server := NewServer(Config{
		IdleTimeout:              time.Minute,
		MaxFlows:                 16,
		MaxUDPPPS:                1000,
		TransportProfilesEnabled: true,
		ProfileMigrationEnabled:  true,
		DefaultProfileID:         "balanced",
		ResumeTokensEnabled:      true,
		ResumeManager:            resumeMgr,
	}, verifier, limits.NewManager(limits.Config{}), m, zap.NewNop())
	defer server.Shutdown()

	clientConn, serverConn := pipeConnPair(t)
	defer clientConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- newTCPSession(42, serverConn, server, zap.NewNop()).Run()
	}()

	nonce := []byte("0123456789abcdef")
	ts := uint64(time.Now().UnixMilli())
	sig, err := verifier.SignSession(clientID, ts, nonce, 0b0011)
	if err != nil {
		t.Fatalf("SignSession: %v", err)
	}
	payload := EncodeAuthPayload(AuthPayload{
		ClientID: clientID,
		TSMS:     ts,
		Nonce:    nonce,
		Sig:      sig,
		Caps:     0b0011,
	})
	if err := WriteFrame(clientConn, FrameAUTH, payload); err != nil {
		t.Fatalf("WriteFrame AUTH: %v", err)
	}

	frame, err := ReadFrame(bufio.NewReader(clientConn))
	if err != nil {
		t.Fatalf("ReadFrame AUTH_OK: %v", err)
	}
	if frame.Type != FrameAUTHOK {
		t.Fatalf("frame.Type=%d, want AUTH_OK", frame.Type)
	}
	if got, want := len(frame.Payload), 28; got != want {
		t.Fatalf("AUTH_OK payload len=%d, want %d for legacy client compatibility", got, want)
	}
	authOK, err := DecodeAuthOKPayload(frame.Payload)
	if err != nil {
		t.Fatalf("DecodeAuthOKPayload: %v", err)
	}
	if authOK.ProfileID != "" {
		t.Fatalf("ProfileID=%q, want empty for legacy client", authOK.ProfileID)
	}
	if len(authOK.ResumeTag) != 0 || len(authOK.ResumeToken) != 0 {
		t.Fatalf("resume tail must be empty for legacy client: tag=%x token=%x", authOK.ResumeTag, authOK.ResumeToken)
	}

	_ = clientConn.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("session.Run err=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session.Run did not exit after client close")
	}
}

func TestQUICSessionLegacyClientGetsLegacyAuthOK(t *testing.T) {
	const (
		clientID  = "client-a"
		secretRaw = "smoke-secret"
	)

	provider, err := auth.NewStaticSecretProvider(map[string]string{clientID: secretRaw})
	if err != nil {
		t.Fatalf("NewStaticSecretProvider: %v", err)
	}
	verifier := auth.NewVerifier(provider, auth.NewReplayCache(time.Minute), time.Minute, auth.VerifyHooks{})
	m := metrics.New()
	defer m.Close()

	resumeMgr, err := resume.NewManager(resume.Config{
		Enabled:       true,
		Secret:        []byte("0123456789abcdef0123456789abcdef"),
		TokenTTL:      time.Minute,
		ReplayTTL:     time.Minute,
		EpochRotation: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer resumeMgr.Close()

	server := NewServer(Config{
		ListenQUIC:               freeUDPAddr(t),
		TLSConfig:                newSessionTestTLSConfig(t),
		IdleTimeout:              time.Minute,
		MaxFlows:                 16,
		MaxUDPPPS:                1000,
		TransportProfilesEnabled: true,
		ProfileMigrationEnabled:  true,
		DefaultProfileID:         "balanced",
		ResumeTokensEnabled:      true,
		ResumeManager:            resumeMgr,
	}, verifier, limits.NewManager(limits.Config{}), m, zap.NewNop())
	defer server.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start(ctx)
	}()
	waitForQUICListener(t, server)

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"vlf-runtime/0.1"},
	}
	conn, err := quic.DialAddr(context.Background(), server.cfg.ListenQUIC, tlsConf, &quic.Config{
		EnableDatagrams: true,
	})
	if err != nil {
		t.Fatalf("quic.DialAddr: %v", err)
	}
	defer func() {
		_ = conn.CloseWithError(0, "test_done")
	}()

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("OpenStreamSync: %v", err)
	}
	defer stream.Close()

	nonce := []byte("0123456789abcdef")
	ts := uint64(time.Now().UnixMilli())
	sig, err := verifier.SignSession(clientID, ts, nonce, 0b1111)
	if err != nil {
		t.Fatalf("SignSession: %v", err)
	}
	payload := EncodeAuthPayload(AuthPayload{
		ClientID: clientID,
		TSMS:     ts,
		Nonce:    nonce,
		Sig:      sig,
		Caps:     0b1111,
	})
	if err := WriteFrame(stream, FrameAUTH, payload); err != nil {
		t.Fatalf("WriteFrame AUTH: %v", err)
	}

	frame, err := ReadFrame(bufio.NewReader(stream))
	if err != nil {
		t.Fatalf("ReadFrame AUTH_OK: %v", err)
	}
	if frame.Type != FrameAUTHOK {
		t.Fatalf("frame.Type=%d, want AUTH_OK", frame.Type)
	}
	if got, want := len(frame.Payload), 28; got != want {
		t.Fatalf("AUTH_OK payload len=%d, want %d for legacy client compatibility", got, want)
	}
	authOK, err := DecodeAuthOKPayload(frame.Payload)
	if err != nil {
		t.Fatalf("DecodeAuthOKPayload: %v", err)
	}
	if authOK.ProfileID != "" {
		t.Fatalf("ProfileID=%q, want empty for legacy client", authOK.ProfileID)
	}
	if len(authOK.ResumeTag) != 0 || len(authOK.ResumeToken) != 0 {
		t.Fatalf("resume tail must be empty for legacy client: tag=%x token=%x", authOK.ResumeTag, authOK.ResumeToken)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("server.Start err=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server.Start did not exit after cancel")
	}
}
