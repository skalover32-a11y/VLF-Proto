package main

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestBuildParseSocksUDPDatagramIPv4(t *testing.T) {
	target := socksTarget{
		Atyp: socksAtypIPv4,
		Host: "1.2.3.4",
		Port: 5300,
	}
	payload := []byte("hello-udp")

	raw, err := buildSocksUDPDatagram(target, payload)
	if err != nil {
		t.Fatalf("buildSocksUDPDatagram error: %v", err)
	}

	frag, gotTarget, gotPayload, err := parseSocksUDPDatagram(raw)
	if err != nil {
		t.Fatalf("parseSocksUDPDatagram error: %v", err)
	}
	if frag != 0 {
		t.Fatalf("unexpected frag=%d", frag)
	}
	if gotTarget.Atyp != target.Atyp || gotTarget.Host != target.Host || gotTarget.Port != target.Port {
		t.Fatalf("unexpected target: got=%+v want=%+v", gotTarget, target)
	}
	if string(gotPayload) != string(payload) {
		t.Fatalf("unexpected payload: got=%q want=%q", string(gotPayload), string(payload))
	}
}

func TestNegotiateSOCKS5UserPass(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	errCh := make(chan error, 1)
	reqCh := make(chan socksRequest, 1)
	go func() {
		req, err := negotiateSOCKS5(server, authConfig{
			mode:     authModeUserPass,
			username: "u",
			password: "p",
		}, &clientMetrics{})
		if err == nil {
			reqCh <- req
		}
		errCh <- err
	}()

	_, _ = client.Write([]byte{socksVer5, 0x01, socksMethodUserPass})
	methodReply := make([]byte, 2)
	if _, err := io.ReadFull(client, methodReply); err != nil {
		t.Fatalf("read method reply: %v", err)
	}
	if methodReply[0] != socksVer5 || methodReply[1] != socksMethodUserPass {
		t.Fatalf("unexpected method reply: %v", methodReply)
	}

	_, _ = client.Write([]byte{socksUserAuthVer, 0x01, 'u', 0x01, 'p'})
	authReply := make([]byte, 2)
	if _, err := io.ReadFull(client, authReply); err != nil {
		t.Fatalf("read auth reply: %v", err)
	}
	if authReply[0] != socksUserAuthVer || authReply[1] != 0x00 {
		t.Fatalf("unexpected auth reply: %v", authReply)
	}

	host := "example.com"
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
			t.Fatalf("negotiate failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting negotiate")
	}

	select {
	case gotReq := <-reqCh:
		if gotReq.Cmd != socksCmdConnect {
			t.Fatalf("unexpected cmd=%d", gotReq.Cmd)
		}
		if gotReq.Target.Host != host || gotReq.Target.Port != 443 {
			t.Fatalf("unexpected target: %+v", gotReq.Target)
		}
	default:
		t.Fatal("missing parsed request")
	}
}
