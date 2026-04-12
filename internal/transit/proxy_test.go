package transit

import (
	"context"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestConfigDefaultsAndValidation(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should validate: %v", err)
	}

	cfg.ListenUDPAlt = "0.0.0.0:0"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected invalid zero port")
	}
}

func TestTCPTransitProxy(t *testing.T) {
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	defer backendLn.Close()

	go func() {
		for {
			conn, acceptErr := backendLn.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 128)
				n, _ := c.Read(buf)
				_, _ = c.Write([]byte("echo:" + string(buf[:n])))
			}(conn)
		}
	}()

	listenAddr := freeTCPAddr(t)
	cfg := DefaultConfig()
	cfg.ListenTCP = listenAddr
	cfg.BackendTCP = backendLn.Addr().String()
	cfg.ListenUDP = freeUDPAddr(t)
	cfg.BackendUDP = freeUDPAddr(t)
	cfg.ListenUDPAlt = ""
	cfg.EnableRelay = false
	cfg.EnableMetrics = false

	proxy := NewProxy(cfg, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = proxy.Run(ctx)
	}()
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer shutdownCancel()
		_ = proxy.Shutdown(shutdownCtx)
	}()

	waitForTCP(t, listenAddr)

	conn, err := net.Dial("tcp", listenAddr)
	if err != nil {
		t.Fatalf("dial transit: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write transit: %v", err)
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read transit: %v", err)
	}
	if got := string(buf[:n]); got != "echo:hello" {
		t.Fatalf("unexpected response: %q", got)
	}
}

func TestUDPTransitProxy(t *testing.T) {
	backendAddr, err := net.ResolveUDPAddr("udp", freeUDPAddr(t))
	if err != nil {
		t.Fatalf("resolve backend udp: %v", err)
	}
	backendConn, err := net.ListenUDP("udp", backendAddr)
	if err != nil {
		t.Fatalf("listen backend udp: %v", err)
	}
	defer backendConn.Close()

	go func() {
		buf := make([]byte, 128)
		for {
			n, addr, readErr := backendConn.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			_, _ = backendConn.WriteToUDP([]byte("udp:"+string(buf[:n])), addr)
		}
	}()

	listenAddr := freeUDPAddr(t)
	cfg := DefaultConfig()
	cfg.ListenTCP = freeTCPAddr(t)
	cfg.BackendTCP = "127.0.0.1:1"
	cfg.ListenUDP = listenAddr
	cfg.BackendUDP = backendConn.LocalAddr().String()
	cfg.ListenUDPAlt = ""
	cfg.EnableRelay = false
	cfg.EnableMetrics = false

	proxy := NewProxy(cfg, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = proxy.Run(ctx)
	}()
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer shutdownCancel()
		_ = proxy.Shutdown(shutdownCtx)
	}()

	waitForUDP(t, listenAddr)

	clientConn, err := net.Dial("udp", listenAddr)
	if err != nil {
		t.Fatalf("dial transit udp: %v", err)
	}
	defer clientConn.Close()
	if _, err := clientConn.Write([]byte("ping")); err != nil {
		t.Fatalf("write transit udp: %v", err)
	}
	buf := make([]byte, 128)
	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("read transit udp: %v", err)
	}
	if got := string(buf[:n]); got != "udp:ping" {
		t.Fatalf("unexpected udp response: %q", got)
	}
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp addr: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve udp addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("reserve udp addr: %v", err)
	}
	actual := conn.LocalAddr().String()
	_ = conn.Close()
	return actual
}

func waitForTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("tcp listener %s did not become ready", addr)
}

func waitForUDP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("resolve udp addr %s: %v", addr, err)
	}
	for time.Now().Before(deadline) {
		conn, listenErr := net.ListenUDP("udp", udpAddr)
		if listenErr != nil {
			return
		}
		_ = conn.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("udp listener %s did not become ready", addr)
}
