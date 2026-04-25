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

	cfg := DefaultConfig()
	// Use ":0" so the kernel assigns a free ephemeral port at bind time.
	// The previous reserve-then-close-then-rebind pattern was racy on Linux
	// CI runners where another process could grab the port in between.
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.BackendTCP = backendLn.Addr().String()
	cfg.ListenUDP = "127.0.0.1:0"
	cfg.BackendUDP = "127.0.0.1:1"
	cfg.ListenUDPAlt = ""
	cfg.EnableRelay = false
	cfg.EnableMetrics = false

	proxy := NewProxy(cfg, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- proxy.Run(ctx)
	}()
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer shutdownCancel()
		_ = proxy.Shutdown(shutdownCtx)
	}()

	select {
	case <-proxy.Started():
	case err := <-runErrCh:
		t.Fatalf("proxy.Run returned before start: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("proxy did not signal Started within 3s")
	}

	listenAddr := proxy.tcpListenAddr("session_tcp")
	if listenAddr == "" {
		t.Fatal("session_tcp listener missing")
	}

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
	backendConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
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

	cfg := DefaultConfig()
	cfg.ListenTCP = "127.0.0.1:0"
	cfg.BackendTCP = "127.0.0.1:1"
	cfg.ListenUDP = "127.0.0.1:0"
	cfg.BackendUDP = backendConn.LocalAddr().String()
	cfg.ListenUDPAlt = ""
	cfg.EnableRelay = false
	cfg.EnableMetrics = false

	proxy := NewProxy(cfg, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- proxy.Run(ctx)
	}()
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer shutdownCancel()
		_ = proxy.Shutdown(shutdownCtx)
	}()

	select {
	case <-proxy.Started():
	case err := <-runErrCh:
		t.Fatalf("proxy.Run returned before start: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("proxy did not signal Started within 3s")
	}

	listenAddr := proxy.udpListenAddr("session_udp")
	if listenAddr == "" {
		t.Fatal("session_udp lane missing")
	}

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