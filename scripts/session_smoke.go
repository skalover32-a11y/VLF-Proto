package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/quic-go/quic-go"

	"vlf-runtime/internal/auth"
	"vlf-runtime/internal/session"
)

func main() {
	addr := envOr("SESSION_ADDR", "localhost:443")
	clientID := envAny([]string{"VLF_CLIENT_ID", "VLF_CLIENT"}, "smoke-client")
	secret := envOr("VLF_SECRET", "smoke-secret")
	protoID := envOr("VLF_PROTO_ID", "vlf-runtime/0.1")
	pinSPKI := envOr("VLF_PIN_SPKI", "")
	dstTCPHost := envOr("DST_TCP_HOST", "tcp-echo")
	dstTCPPort := envOrInt("DST_TCP_PORT", 9000)
	dstUDPHost := envOr("DST_UDP_HOST", "udp-echo")
	dstUDPPort := envOrInt("DST_UDP_PORT", 9001)
	maxDgramPayload := envOrInt("MAX_DGRAM_PAYLOAD", 1200)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{protoID},
	}
	if strings.TrimSpace(pinSPKI) != "" {
		expectedPin, err := decodeSPKIPin(pinSPKI)
		if err != nil {
			log.Fatalf("invalid VLF_PIN_SPKI: %v", err)
		}
		log.Printf("TLS pinning enabled (SPKI sha256)")
		tlsConf.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("tls pinning failed: no server certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("tls pinning parse cert: %w", err)
			}
			hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			if !hmac.Equal(hash[:], expectedPin) {
				return fmt.Errorf(
					"tls pin mismatch: got=%s want=%s",
					base64.StdEncoding.EncodeToString(hash[:]),
					base64.StdEncoding.EncodeToString(expectedPin),
				)
			}
			return nil
		}
	}

	conn, err := quic.DialAddr(ctx, addr, tlsConf, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		log.Fatalf("dial QUIC: %v", err)
	}
	defer conn.CloseWithError(0, "smoke_done")

	control, err := conn.OpenStreamSync(ctx)
	if err != nil {
		log.Fatalf("open control stream: %v", err)
	}
	defer control.Close()

	controlReader := bufio.NewReader(control)

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		log.Fatalf("nonce generation failed: %v", err)
	}

	ts := uint64(time.Now().UnixMilli())
	caps := uint64(0b1111)
	sig := signSession(secret, auth.SessionAuthMaterial(clientID, ts, nonce, caps))

	authPayload := session.EncodeAuthPayload(session.AuthPayload{
		ClientID: clientID,
		TSMS:     ts,
		Nonce:    nonce,
		Sig:      sig,
		Caps:     caps,
	})
	if err := session.WriteFrame(control, session.FrameAUTH, authPayload); err != nil {
		log.Fatalf("send AUTH: %v", err)
	}

	frame, err := readControlFrame(controlReader, 5*time.Second)
	if err != nil {
		log.Fatalf("read AUTH response: %v", err)
	}
	if frame.Type == session.FrameAUTHFAIL {
		log.Fatalf("AUTH failed: %s", decodeAuthFailReason(frame.Payload))
	}
	if frame.Type != session.FrameAUTHOK {
		log.Fatalf("expected AUTH_OK, got frame type=%d", frame.Type)
	}

	const tcpFlowID = uint64(1001)
	openTCPPayload := session.EncodeOpenPayload(session.OpenPayload{
		FlowID:  tcpFlowID,
		DstHost: dstTCPHost,
		DstPort: uint16(dstTCPPort),
	})
	if err := session.WriteFrame(control, session.FrameOPENTCP, openTCPPayload); err != nil {
		log.Fatalf("send OPEN_TCP: %v", err)
	}

	frame, err = readControlFrame(controlReader, 5*time.Second)
	if err != nil {
		log.Fatalf("read OPEN_TCP response: %v", err)
	}
	if frame.Type != session.FrameOPENTCPOK {
		log.Fatalf("expected OPEN_TCP_OK, got %d payload=%s", frame.Type, hex.EncodeToString(frame.Payload))
	}

	openOK, err := session.DecodeOpenOKPayload(frame.Payload)
	if err != nil {
		log.Fatalf("decode OPEN_TCP_OK payload: %v", err)
	}
	if openOK.FlowID != tcpFlowID {
		log.Fatalf("unexpected flow_id in OPEN_TCP_OK: %d", openOK.FlowID)
	}

	tcpStream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		log.Fatalf("open tcp flow stream: %v", err)
	}
	defer tcpStream.Close()

	var flowHdr [8]byte
	binary.BigEndian.PutUint64(flowHdr[:], tcpFlowID)
	if _, err := tcpStream.Write(flowHdr[:]); err != nil {
		log.Fatalf("write tcp flow header: %v", err)
	}

	tcpPayload := []byte("hello-session-tcp")
	if _, err := tcpStream.Write(tcpPayload); err != nil {
		log.Fatalf("write tcp payload: %v", err)
	}

	tcpEcho := make([]byte, len(tcpPayload))
	if _, err := io.ReadFull(tcpStream, tcpEcho); err != nil {
		log.Fatalf("read tcp echo: %v", err)
	}
	if !bytes.Equal(tcpPayload, tcpEcho) {
		log.Fatalf("tcp echo mismatch: got=%q want=%q", string(tcpEcho), string(tcpPayload))
	}

	const udpFlowID = uint64(2001)
	openUDPPayload := session.EncodeOpenPayload(session.OpenPayload{
		FlowID:  udpFlowID,
		DstHost: dstUDPHost,
		DstPort: uint16(dstUDPPort),
	})
	if err := session.WriteFrame(control, session.FrameOPENUDP, openUDPPayload); err != nil {
		log.Fatalf("send OPEN_UDP: %v", err)
	}

	frame, err = readControlFrame(controlReader, 5*time.Second)
	if err != nil {
		log.Fatalf("read OPEN_UDP response: %v", err)
	}
	if frame.Type != session.FrameOPENUDPOK {
		log.Fatalf("expected OPEN_UDP_OK, got %d payload=%s", frame.Type, hex.EncodeToString(frame.Payload))
	}

	openUDP, err := session.DecodeOpenOKPayload(frame.Payload)
	if err != nil {
		log.Fatalf("decode OPEN_UDP_OK payload: %v", err)
	}
	if openUDP.FlowID != udpFlowID {
		log.Fatalf("unexpected flow_id in OPEN_UDP_OK: %d", openUDP.FlowID)
	}

	udpSmall := []byte("hello-session-udp")
	udpLarge := bytes.Repeat([]byte("L"), 3000)

	if err := sendDatagramPayload(conn, udpFlowID, 1, udpSmall, maxDgramPayload); err != nil {
		log.Fatalf("send small datagram: %v", err)
	}
	if err := sendDatagramPayload(conn, udpFlowID, 2, udpLarge, maxDgramPayload); err != nil {
		log.Fatalf("send large datagram: %v", err)
	}

	received := make([][]byte, 0, 2)
	reassembly := session.NewReassembly()
	deadline := time.Now().Add(10 * time.Second)
	for len(received) < 2 {
		if time.Now().After(deadline) {
			log.Fatalf("timeout waiting UDP echoes, received=%d", len(received))
		}

		pktRaw, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			log.Fatalf("receive UDP datagram: %v", err)
		}

		pkt, err := session.DecodeDatagramPacket(pktRaw)
		if err != nil {
			continue
		}
		if pkt.FlowID != udpFlowID {
			continue
		}

		payload, done := reassembly.Add(pkt)
		if !done {
			continue
		}

		received = append(received, payload)
	}

	if !comparePayloadSet(received, [][]byte{udpSmall, udpLarge}) {
		log.Fatalf("udp echo mismatch")
	}

	_ = session.WriteFrame(control, session.FrameCLOSEFLOW, session.EncodeCloseFlowPayload(session.CloseFlowPayload{FlowID: tcpFlowID}))
	_ = session.WriteFrame(control, session.FrameCLOSEFLOW, session.EncodeCloseFlowPayload(session.CloseFlowPayload{FlowID: udpFlowID}))

	fmt.Println("PASS session smoke")
}

func sendDatagramPayload(conn *quic.Conn, flowID uint64, seq uint32, payload []byte, maxPayload int) error {
	packets, err := session.FragmentDatagram(flowID, seq, payload, maxPayload)
	if err != nil {
		return err
	}
	for _, pkt := range packets {
		if err := conn.SendDatagram(pkt); err != nil {
			return err
		}
	}
	return nil
}

func readControlFrame(r *bufio.Reader, timeout time.Duration) (*session.Frame, error) {
	type result struct {
		frame *session.Frame
		err   error
	}

	ch := make(chan result, 1)
	go func() {
		frame, err := session.ReadFrame(r)
		ch <- result{frame: frame, err: err}
	}()

	select {
	case out := <-ch:
		return out.frame, out.err
	case <-time.After(timeout):
		return nil, errors.New("control frame timeout")
	}
}

func comparePayloadSet(got [][]byte, want [][]byte) bool {
	if len(got) != len(want) {
		return false
	}

	normalize := func(items [][]byte) []string {
		out := make([]string, 0, len(items))
		for _, p := range items {
			out = append(out, hex.EncodeToString(p))
		}
		sort.Strings(out)
		return out
	}

	g := normalize(got)
	w := normalize(want)

	for i := range g {
		if g[i] != w[i] {
			return false
		}
	}
	return true
}

func decodeAuthFailReason(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	// payload = uvarint(len(reason)) + reason bytes
	ln, n := binary.Uvarint(payload)
	if n <= 0 {
		return string(payload)
	}
	if int(ln)+n > len(payload) {
		return string(payload)
	}
	return string(payload[n : n+int(ln)])
}

func signSession(secret string, payload []byte) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func envAny(names []string, fallback string) string {
	for _, name := range names {
		if v := os.Getenv(name); v != "" {
			return v
		}
	}
	return fallback
}

func envOrInt(name string, fallback int) int {
	if v := os.Getenv(name); v != "" {
		var parsed int
		if _, err := fmt.Sscanf(v, "%d", &parsed); err == nil {
			return parsed
		}
	}
	return fallback
}

func decodeSPKIPin(raw string) ([]byte, error) {
	pin := strings.TrimSpace(raw)
	pin = strings.TrimPrefix(pin, "sha256/")
	if pin == "" {
		return nil, errors.New("empty pin")
	}

	decoded, err := base64.StdEncoding.DecodeString(pin)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(pin)
	}
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(decoded) != crypto.SHA256.Size() {
		return nil, fmt.Errorf("pin length must be %d bytes, got %d", crypto.SHA256.Size(), len(decoded))
	}
	return decoded, nil
}
