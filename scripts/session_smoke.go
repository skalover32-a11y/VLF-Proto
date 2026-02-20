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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"

	"vlf-runtime/internal/auth"
	"vlf-runtime/internal/session"
)

type smokeConfig struct {
	GatewayHost string
	GatewayUDP  int
	GatewayTCP  int
	QUICAddr    string
	TCPAddr     string
	RelayBase   string

	ClientID string
	Secret   []byte
	ProtoID  string
	PinSPKI  string

	DstTCPHost string
	DstTCPPort int
	DstUDPHost string
	DstUDPPort int

	RelayDialHost string
	RelayDialPort int

	MaxDgramPayload int
	QUICTimeout     time.Duration
	TCPTimeout      time.Duration
	AllowRelay      bool
	Debug           bool
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	if cfg.Debug {
		debugf(cfg, "config: gateway_host=%s quic_addr=%s tcp_addr=%s relay=%s", cfg.GatewayHost, cfg.QUICAddr, cfg.TCPAddr, cfg.RelayBase)
		debugf(cfg, "config: proto_id=%s dst_tcp=%s:%d dst_udp=%s:%d relay_dial=%s:%d", cfg.ProtoID, cfg.DstTCPHost, cfg.DstTCPPort, cfg.DstUDPHost, cfg.DstUDPPort, cfg.RelayDialHost, cfg.RelayDialPort)
	}

	transport, err := runWithFallback(cfg)
	if err != nil {
		log.Fatalf("session smoke failed: %v", err)
	}

	fmt.Printf("PASS session smoke (transport=%s)\n", transport)
}

func loadConfig() (smokeConfig, error) {
	clientID := envAny([]string{"VLF_CLIENT_ID", "VLF_CLIENT"}, "smoke-client")
	secretRaw := envOr("VLF_SECRET", "smoke-secret")
	secret, err := auth.ParseSecretString(secretRaw)
	if err != nil {
		return smokeConfig{}, fmt.Errorf("parse VLF_SECRET: %w", err)
	}

	protoID := envOr("VLF_PROTO_ID", "vlf-runtime/0.1")
	pin := envOr("VLF_PIN_SPKI", "")

	defaultPort := envOrInt("GATEWAY_PORT", 443)
	gatewayHost := envOr("GATEWAY_HOST", "")
	sessionAddr := envOr("SESSION_ADDR", "")

	if sessionAddr != "" {
		h, p, splitErr := splitHostPort(sessionAddr)
		if splitErr == nil {
			if gatewayHost == "" {
				gatewayHost = h
			}
			if os.Getenv("GATEWAY_PORT_UDP") == "" && os.Getenv("GATEWAY_PORT") == "" {
				defaultPort = p
			}
		}
	}
	if gatewayHost == "" {
		gatewayHost = "localhost"
	}

	gatewayUDP := envOrInt("GATEWAY_PORT_UDP", defaultPort)
	gatewayTCP := envOrInt("GATEWAY_PORT_TCP", defaultPort)
	if sessionAddr == "" {
		sessionAddr = net.JoinHostPort(gatewayHost, strconv.Itoa(gatewayUDP))
	}

	relayBase := envOr("RELAY_BASE", fmt.Sprintf("http://%s:8080", gatewayHost))

	cfg := smokeConfig{
		GatewayHost: gatewayHost,
		GatewayUDP:  gatewayUDP,
		GatewayTCP:  gatewayTCP,
		QUICAddr:    sessionAddr,
		TCPAddr:     net.JoinHostPort(gatewayHost, strconv.Itoa(gatewayTCP)),
		RelayBase:   relayBase,

		ClientID: clientID,
		Secret:   secret,
		ProtoID:  protoID,
		PinSPKI:  pin,

		DstTCPHost: envOr("DST_TCP_HOST", "tcp-echo"),
		DstTCPPort: envOrInt("DST_TCP_PORT", 9000),
		DstUDPHost: envOr("DST_UDP_HOST", "udp-echo"),
		DstUDPPort: envOrInt("DST_UDP_PORT", 9001),

		RelayDialHost: envAny([]string{"RELAY_DIAL_HOST", "DST_TCP_HOST"}, "tcp-echo"),
		RelayDialPort: envOrInt("RELAY_DIAL_PORT", envOrInt("DST_TCP_PORT", 9000)),

		MaxDgramPayload: envOrInt("MAX_DGRAM_PAYLOAD", 1200),
		QUICTimeout:     time.Duration(envOrInt("QUIC_CONNECT_TIMEOUT_MS", 1800)) * time.Millisecond,
		TCPTimeout:      time.Duration(envOrInt("TCP_CONNECT_TIMEOUT_MS", 1800)) * time.Millisecond,
		AllowRelay:      !envBool("VLF_DISABLE_RELAY_FALLBACK", false),
		Debug:           envBool("VLF_DEBUG", false),
	}

	if cfg.QUICTimeout < 500*time.Millisecond {
		cfg.QUICTimeout = 500 * time.Millisecond
	}
	if cfg.TCPTimeout < 500*time.Millisecond {
		cfg.TCPTimeout = 500 * time.Millisecond
	}

	return cfg, nil
}

func runWithFallback(cfg smokeConfig) (string, error) {
	quicHost, quicPort, err := splitHostPort(cfg.QUICAddr)
	if err == nil {
		dnsDebug(cfg, quicHost)
		probeErr := udpProbe(cfg, quicHost, quicPort)
		if probeErr != nil {
			debugf(cfg, "udp probe failed: %v", probeErr)
		} else {
			debugf(cfg, "udp probe ok to %s:%d", quicHost, quicPort)
		}
	}

	if err := runQUICSession(cfg); err == nil {
		return "quic", nil
	} else {
		debugf(cfg, "QUIC transport failed: %v", err)
	}

	if err := runTCPSession(cfg); err == nil {
		return "tcp-session", nil
	} else {
		debugf(cfg, "TCP session transport failed: %v", err)
	}

	if !cfg.AllowRelay {
		return "", errors.New("relay fallback disabled and session transports failed")
	}

	if err := runRelayFallback(cfg); err == nil {
		return "relay", nil
	} else {
		return "", fmt.Errorf("all transports failed, last relay error: %w", err)
	}
}

func runQUICSession(cfg smokeConfig) error {
	dialCtx, cancel := context.WithTimeout(context.Background(), cfg.QUICTimeout)
	defer cancel()

	tlsConf, err := buildTLSConfig(cfg)
	if err != nil {
		return err
	}
	tlsConf.NextProtos = []string{cfg.ProtoID}

	debugf(cfg, "attempting QUIC dial: addr=%s sni=%s alpn=%s timeout=%s", cfg.QUICAddr, cfg.GatewayHost, cfg.ProtoID, cfg.QUICTimeout)
	conn, err := quic.DialAddr(dialCtx, cfg.QUICAddr, tlsConf, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("dial QUIC: %w", err)
	}
	defer conn.CloseWithError(0, "smoke_done")

	ctx, cancelRun := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancelRun()

	control, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	defer control.Close()

	controlReader := bufio.NewReader(control)

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce generation failed: %w", err)
	}
	ts := uint64(time.Now().UnixMilli())
	caps := uint64(0b1111)
	sig := signSession(cfg.Secret, auth.SessionAuthMaterial(cfg.ClientID, ts, nonce, caps))

	authPayload := session.EncodeAuthPayload(session.AuthPayload{
		ClientID: cfg.ClientID,
		TSMS:     ts,
		Nonce:    nonce,
		Sig:      sig,
		Caps:     caps,
	})
	if err := session.WriteFrame(control, session.FrameAUTH, authPayload); err != nil {
		return fmt.Errorf("send AUTH: %w", err)
	}

	frame, err := readControlFrame(controlReader, 5*time.Second)
	if err != nil {
		return fmt.Errorf("read AUTH response: %w", err)
	}
	if frame.Type == session.FrameAUTHFAIL {
		return fmt.Errorf("AUTH failed: %s", decodeAuthFailReason(frame.Payload))
	}
	if frame.Type != session.FrameAUTHOK {
		return fmt.Errorf("expected AUTH_OK, got frame type=%d", frame.Type)
	}

	const tcpFlowID = uint64(1001)
	openTCPPayload := session.EncodeOpenPayload(session.OpenPayload{
		FlowID:  tcpFlowID,
		DstHost: cfg.DstTCPHost,
		DstPort: uint16(cfg.DstTCPPort),
	})
	if err := session.WriteFrame(control, session.FrameOPENTCP, openTCPPayload); err != nil {
		return fmt.Errorf("send OPEN_TCP: %w", err)
	}

	frame, err = readControlFrame(controlReader, 5*time.Second)
	if err != nil {
		return fmt.Errorf("read OPEN_TCP response: %w", err)
	}
	if frame.Type != session.FrameOPENTCPOK {
		return fmt.Errorf("expected OPEN_TCP_OK, got %d payload=%s", frame.Type, hex.EncodeToString(frame.Payload))
	}

	openOK, err := session.DecodeOpenOKPayload(frame.Payload)
	if err != nil {
		return fmt.Errorf("decode OPEN_TCP_OK payload: %w", err)
	}
	if openOK.FlowID != tcpFlowID {
		return fmt.Errorf("unexpected flow_id in OPEN_TCP_OK: %d", openOK.FlowID)
	}

	tcpStream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open tcp flow stream: %w", err)
	}
	defer tcpStream.Close()

	var flowHdr [8]byte
	binary.BigEndian.PutUint64(flowHdr[:], tcpFlowID)
	if _, err := tcpStream.Write(flowHdr[:]); err != nil {
		return fmt.Errorf("write tcp flow header: %w", err)
	}

	tcpPayload := []byte("hello-session-tcp")
	if _, err := tcpStream.Write(tcpPayload); err != nil {
		return fmt.Errorf("write tcp payload: %w", err)
	}

	tcpEcho := make([]byte, len(tcpPayload))
	if _, err := io.ReadFull(tcpStream, tcpEcho); err != nil {
		return fmt.Errorf("read tcp echo: %w", err)
	}
	if !bytes.Equal(tcpPayload, tcpEcho) {
		return fmt.Errorf("tcp echo mismatch: got=%q want=%q", string(tcpEcho), string(tcpPayload))
	}

	const udpFlowID = uint64(2001)
	openUDPPayload := session.EncodeOpenPayload(session.OpenPayload{
		FlowID:  udpFlowID,
		DstHost: cfg.DstUDPHost,
		DstPort: uint16(cfg.DstUDPPort),
	})
	if err := session.WriteFrame(control, session.FrameOPENUDP, openUDPPayload); err != nil {
		return fmt.Errorf("send OPEN_UDP: %w", err)
	}

	frame, err = readControlFrame(controlReader, 5*time.Second)
	if err != nil {
		return fmt.Errorf("read OPEN_UDP response: %w", err)
	}
	if frame.Type != session.FrameOPENUDPOK {
		return fmt.Errorf("expected OPEN_UDP_OK, got %d payload=%s", frame.Type, hex.EncodeToString(frame.Payload))
	}

	openUDP, err := session.DecodeOpenOKPayload(frame.Payload)
	if err != nil {
		return fmt.Errorf("decode OPEN_UDP_OK payload: %w", err)
	}
	if openUDP.FlowID != udpFlowID {
		return fmt.Errorf("unexpected flow_id in OPEN_UDP_OK: %d", openUDP.FlowID)
	}

	udpSmall := []byte("hello-session-udp")
	udpLarge := bytes.Repeat([]byte("L"), 3000)
	if err := sendDatagramPayload(conn, udpFlowID, 1, udpSmall, cfg.MaxDgramPayload); err != nil {
		return fmt.Errorf("send small datagram: %w", err)
	}
	if err := sendDatagramPayload(conn, udpFlowID, 2, udpLarge, cfg.MaxDgramPayload); err != nil {
		return fmt.Errorf("send large datagram: %w", err)
	}

	received := make([][]byte, 0, 2)
	reassembly := session.NewReassembly()
	deadline := time.Now().Add(10 * time.Second)
	for len(received) < 2 {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting UDP echoes, received=%d", len(received))
		}

		pktRaw, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return fmt.Errorf("receive UDP datagram: %w", err)
		}
		pkt, err := session.DecodeDatagramPacket(pktRaw)
		if err != nil || pkt.FlowID != udpFlowID {
			continue
		}
		payload, done := reassembly.Add(pkt)
		if !done {
			continue
		}
		received = append(received, payload)
	}

	if !comparePayloadSet(received, [][]byte{udpSmall, udpLarge}) {
		return errors.New("udp echo mismatch")
	}

	_ = session.WriteFrame(control, session.FrameCLOSEFLOW, session.EncodeCloseFlowPayload(session.CloseFlowPayload{FlowID: tcpFlowID}))
	_ = session.WriteFrame(control, session.FrameCLOSEFLOW, session.EncodeCloseFlowPayload(session.CloseFlowPayload{FlowID: udpFlowID}))
	return nil
}

func runTCPSession(cfg smokeConfig) error {
	tlsConf, err := buildTLSConfig(cfg)
	if err != nil {
		return err
	}
	tlsConf.NextProtos = []string{cfg.ProtoID}

	dialer := &net.Dialer{Timeout: cfg.TCPTimeout}
	debugf(cfg, "attempting TCP session dial: addr=%s sni=%s alpn=%s timeout=%s", cfg.TCPAddr, cfg.GatewayHost, cfg.ProtoID, cfg.TCPTimeout)
	conn, err := tls.DialWithDialer(dialer, "tcp", cfg.TCPAddr, tlsConf)
	if err != nil {
		return fmt.Errorf("dial TCP session: %w", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce generation failed: %w", err)
	}
	ts := uint64(time.Now().UnixMilli())
	caps := uint64(0b0011)
	sig := signSession(cfg.Secret, auth.SessionAuthMaterial(cfg.ClientID, ts, nonce, caps))

	authPayload := session.EncodeAuthPayload(session.AuthPayload{
		ClientID: cfg.ClientID,
		TSMS:     ts,
		Nonce:    nonce,
		Sig:      sig,
		Caps:     caps,
	})
	if err := session.WriteFrame(conn, session.FrameAUTH, authPayload); err != nil {
		return fmt.Errorf("send AUTH: %w", err)
	}

	frame, err := readControlFrame(reader, 5*time.Second)
	if err != nil {
		return fmt.Errorf("read AUTH response: %w", err)
	}
	if frame.Type == session.FrameAUTHFAIL {
		return fmt.Errorf("AUTH failed: %s", decodeAuthFailReason(frame.Payload))
	}
	if frame.Type != session.FrameAUTHOK {
		return fmt.Errorf("expected AUTH_OK, got frame type=%d", frame.Type)
	}

	const flowID = uint64(3001)
	openPayload := session.EncodeOpenPayload(session.OpenPayload{
		FlowID:  flowID,
		DstHost: cfg.DstTCPHost,
		DstPort: uint16(cfg.DstTCPPort),
	})
	if err := session.WriteFrame(conn, session.FrameOPENTCP, openPayload); err != nil {
		return fmt.Errorf("send OPEN_TCP: %w", err)
	}

	frame, err = readControlFrame(reader, 5*time.Second)
	if err != nil {
		return fmt.Errorf("read OPEN_TCP response: %w", err)
	}
	if frame.Type != session.FrameOPENTCPOK {
		return fmt.Errorf("expected OPEN_TCP_OK, got type=%d", frame.Type)
	}

	tcpPayload := []byte("hello-session-tcp-fallback")
	if err := session.WriteFrame(conn, session.FrameTCPDATA, session.EncodeTCPDataPayload(flowID, tcpPayload)); err != nil {
		return fmt.Errorf("send FrameTCPDATA: %w", err)
	}

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		frame, err = readControlFrame(reader, 2*time.Second)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				continue
			}
			return fmt.Errorf("read tcp-data frame: %w", err)
		}
		if frame.Type != session.FrameTCPDATA {
			continue
		}
		fid, data, err := session.DecodeTCPDataPayload(frame.Payload)
		if err != nil {
			continue
		}
		if fid == flowID && bytes.Equal(data, tcpPayload) {
			_ = session.WriteFrame(conn, session.FrameCLOSEFLOW, session.EncodeCloseFlowPayload(session.CloseFlowPayload{FlowID: flowID}))
			return nil
		}
	}

	return errors.New("tcp session fallback echo timeout")
}

func runRelayFallback(cfg smokeConfig) error {
	httpClient := &http.Client{Timeout: 8 * time.Second}
	baseURL := strings.TrimRight(cfg.RelayBase, "/")

	openBody, _ := jsonMarshal(map[string]any{
		"proto":    "tcp",
		"dst_host": cfg.RelayDialHost,
		"dst_port": cfg.RelayDialPort,
		"meta": map[string]string{
			"app": "session_smoke_fallback",
		},
	})

	openRaw, err := relayJSON(httpClient, cfg, http.MethodPost, baseURL+"/v1/relay/open", "/v1/relay/open", openBody)
	if err != nil {
		return fmt.Errorf("relay open: %w", err)
	}
	connID := extractJSONField(openRaw, "conn_id")
	if connID == "" {
		return fmt.Errorf("relay open missing conn_id: %s", string(openRaw))
	}

	payload := []byte("session-smoke-relay-fallback")
	sendPath := "/v1/relay/send?conn_id=" + url.QueryEscape(connID)
	_, err = relayJSON(httpClient, cfg, http.MethodPost, baseURL+sendPath, "/v1/relay/send", payload)
	if err != nil {
		return fmt.Errorf("relay send: %w", err)
	}

	recvPath := "/v1/relay/recv?conn_id=" + url.QueryEscape(connID) + "&max=32768"
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		req, err := relayRequest(cfg, http.MethodGet, baseURL+recvPath, "/v1/relay/recv", nil)
		if err != nil {
			return err
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusNoContent {
			time.Sleep(150 * time.Millisecond)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("relay recv status=%d body=%s", resp.StatusCode, string(body))
		}
		if bytes.Equal(body, payload) {
			closePath := "/v1/relay/close?conn_id=" + url.QueryEscape(connID)
			_, _ = relayJSON(httpClient, cfg, http.MethodPost, baseURL+closePath, "/v1/relay/close", []byte("{}"))
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}

	return errors.New("relay fallback echo timeout")
}

func relayJSON(client *http.Client, cfg smokeConfig, method, fullURL, signedPath string, body []byte) ([]byte, error) {
	req, err := relayRequest(cfg, method, fullURL, signedPath, body)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status=%d body=%s", resp.StatusCode, string(raw))
	}
	return raw, nil
}

func relayRequest(cfg smokeConfig, method, fullURL, signedPath string, body []byte) (*http.Request, error) {
	if body == nil {
		body = []byte{}
	}
	ts := time.Now().UnixMilli()
	nonce := fmt.Sprintf("%d-%d", ts, time.Now().UnixNano())
	material := fmt.Sprintf("%s|%s|%d|%s|%s", method, signedPath, ts, nonce, auth.HashBody(body))
	sigHex := hmacHex(cfg.Secret, material)

	req, err := http.NewRequest(method, fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-VLF-Client", cfg.ClientID)
	req.Header.Set("X-VLF-TS", strconv.FormatInt(ts, 10))
	req.Header.Set("X-VLF-Nonce", nonce)
	req.Header.Set("X-VLF-Sig", sigHex)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	return req, nil
}

func hmacHex(secret []byte, payload string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func buildTLSConfig(cfg smokeConfig) (*tls.Config, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         cfg.GatewayHost,
		MinVersion:         tls.VersionTLS13,
	}
	if strings.TrimSpace(cfg.PinSPKI) == "" {
		return tlsConf, nil
	}
	expectedPin, err := decodeSPKIPin(cfg.PinSPKI)
	if err != nil {
		return nil, fmt.Errorf("invalid VLF_PIN_SPKI: %w", err)
	}
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
			return fmt.Errorf("tls pin mismatch: got=%s want=%s", base64.StdEncoding.EncodeToString(hash[:]), base64.StdEncoding.EncodeToString(expectedPin))
		}
		return nil
	}
	return tlsConf, nil
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
		return nil, context.DeadlineExceeded
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
	ln, n := binary.Uvarint(payload)
	if n <= 0 || int(ln)+n > len(payload) {
		return string(payload)
	}
	return string(payload[n : n+int(ln)])
}

func signSession(secret []byte, payload []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func decodeSPKIPin(raw string) ([]byte, error) {
	pin := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "sha256/"))
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

func dnsDebug(cfg smokeConfig, host string) {
	if !cfg.Debug {
		return
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		debugf(cfg, "dns resolve failed for %s: %v", host, err)
		return
	}
	debugf(cfg, "dns resolve %s => %s", host, strings.Join(ips, ","))
}

func udpProbe(cfg smokeConfig, host string, port int) error {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(port)), 1200*time.Millisecond)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1200 * time.Millisecond))
	_, err = conn.Write([]byte("vlf-udp-probe"))
	return err
}

func debugf(cfg smokeConfig, format string, args ...any) {
	if !cfg.Debug {
		return
	}
	log.Printf("[DEBUG] "+format, args...)
}

func splitHostPort(addr string) (string, int, error) {
	host, portRaw, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func extractJSONField(raw []byte, field string) string {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	if v, ok := m[field].(string); ok {
		return v
	}
	return ""
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
		parsed, err := strconv.Atoi(v)
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "yes", "on", "y":
		return true
	case "0", "false", "no", "off", "n":
		return false
	default:
		return fallback
	}
}
