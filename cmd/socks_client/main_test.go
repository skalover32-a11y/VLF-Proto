package main

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNegotiateSOCKS5ConnectDomain(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	resultCh := make(chan socksRequest, 1)
	errCh := make(chan error, 1)
	go func() {
		req, err := negotiateSOCKS5(server, authConfig{mode: authModeNone}, &clientMetrics{})
		if err == nil {
			resultCh <- req
		}
		errCh <- err
	}()

	_, _ = client.Write([]byte{socksVer5, 0x01, socksMethodNoAuth})
	methodReply := make([]byte, 2)
	if _, err := io.ReadFull(client, methodReply); err != nil {
		t.Fatalf("read method reply: %v", err)
	}
	if methodReply[0] != socksVer5 || methodReply[1] != socksMethodNoAuth {
		t.Fatalf("unexpected method reply: %v", methodReply)
	}

	host := "api.ipify.org"
	req := make([]byte, 0, 7+len(host))
	req = append(req, socksVer5, socksCmdConnect, 0x00, socksAtypDomain, byte(len(host)))
	req = append(req, []byte(host)...)
	portRaw := make([]byte, 2)
	binary.BigEndian.PutUint16(portRaw, uint16(443))
	req = append(req, portRaw...)
	_, _ = client.Write(req)

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("negotiate returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting negotiate result")
	}

	select {
	case req := <-resultCh:
		if req.Cmd != socksCmdConnect {
			t.Fatalf("unexpected cmd: %d", req.Cmd)
		}
		if req.Target.Host != host || req.Target.Port != 443 {
			t.Fatalf("unexpected target: %#v", req.Target)
		}
	default:
		t.Fatal("missing parsed target")
	}
}

func TestNegotiateSOCKS5RejectUnsupportedCommand(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := negotiateSOCKS5(server, authConfig{mode: authModeNone}, &clientMetrics{})
		errCh <- err
	}()

	_, _ = client.Write([]byte{socksVer5, 0x01, socksMethodNoAuth})
	methodReply := make([]byte, 2)
	if _, err := io.ReadFull(client, methodReply); err != nil {
		t.Fatalf("read method reply: %v", err)
	}
	if methodReply[1] != socksMethodNoAuth {
		t.Fatalf("unexpected method selected: %d", methodReply[1])
	}

	// CMD=0x09 should be rejected right after header parse.
	req := []byte{socksVer5, 0x09, 0x00, socksAtypIPv4}
	_, _ = client.Write(req)

	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read command reject reply: %v", err)
	}
	if reply[0] != socksVer5 || reply[1] != socksReplyCommandUnsupported {
		t.Fatalf("unexpected reject reply: %v", reply)
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error for unsupported command")
		}
		if !strings.Contains(err.Error(), "unsupported cmd") {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting negotiate error")
	}
}
