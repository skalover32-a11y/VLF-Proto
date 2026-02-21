package sessionclient

import (
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"vlf-runtime/internal/auth"
)

type Config struct {
	GatewayHost string
	GatewayUDP  int
	GatewayTCP  int
	RelayBase   string

	ClientID string
	Secret   []byte
	ProtoID  string
	PinSPKI  string

	MaxDgramPayload int
	QUICTimeout     time.Duration
	TCPTimeout      time.Duration

	PreferQUIC        bool
	DisableQUIC       bool
	DisableTCPSession bool
	AllowRelay        bool
	Debug             bool
}

func LoadConfigFromEnv() (Config, error) {
	clientID := envAny([]string{"VLF_CLIENT_ID", "VLF_CLIENT"}, "smoke-client")
	secretRaw := envOr("VLF_SECRET", "smoke-secret")
	secret, err := auth.ParseSecretString(secretRaw)
	if err != nil {
		return Config{}, fmt.Errorf("parse VLF_SECRET: %w", err)
	}

	protoID := envOr("VLF_PROTO_ID", "vlf-runtime/0.1")
	pin := envOr("VLF_PIN_SPKI", "")

	defaultPort := envOrInt("GATEWAY_PORT", 443)
	gatewayHost := envOr("GATEWAY_HOST", "")
	sessionAddr := envOr("SESSION_ADDR", "")

	if sessionAddr != "" {
		if h, p, splitErr := splitHostPort(sessionAddr); splitErr == nil {
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
	relayBase := envOr("RELAY_BASE", fmt.Sprintf("http://%s:8080", gatewayHost))

	cfg := Config{
		GatewayHost: gatewayHost,
		GatewayUDP:  gatewayUDP,
		GatewayTCP:  gatewayTCP,
		RelayBase:   relayBase,
		ClientID:    clientID,
		Secret:      secret,
		ProtoID:     protoID,
		PinSPKI:     pin,

		MaxDgramPayload:   envOrInt("MAX_DGRAM_PAYLOAD", 1200),
		QUICTimeout:       time.Duration(envOrInt("QUIC_CONNECT_TIMEOUT_MS", 1800)) * time.Millisecond,
		TCPTimeout:        time.Duration(envOrInt("TCP_CONNECT_TIMEOUT_MS", 1800)) * time.Millisecond,
		PreferQUIC:        envBool("VLF_PREFER_QUIC", true),
		DisableQUIC:       envBool("VLF_DISABLE_QUIC", false),
		DisableTCPSession: envBool("VLF_DISABLE_TCP_SESSION", false),
		AllowRelay:        !envBool("VLF_DISABLE_RELAY_FALLBACK", false),
		Debug:             envBool("VLF_DEBUG", false),
	}

	if cfg.QUICTimeout < 500*time.Millisecond {
		cfg.QUICTimeout = 500 * time.Millisecond
	}
	if cfg.TCPTimeout < 500*time.Millisecond {
		cfg.TCPTimeout = 500 * time.Millisecond
	}

	return cfg, nil
}

func (c Config) QUICAddr() string {
	return net.JoinHostPort(c.GatewayHost, strconv.Itoa(c.GatewayUDP))
}

func (c Config) TCPAddr() string {
	return net.JoinHostPort(c.GatewayHost, strconv.Itoa(c.GatewayTCP))
}

func (c Config) TLSConfig() (*tls.Config, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         c.GatewayHost,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{c.ProtoID},
	}

	if strings.TrimSpace(c.PinSPKI) == "" {
		return tlsConf, nil
	}

	expectedPin, err := decodeSPKIPin(c.PinSPKI)
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
		if !constantTimeEqual(hash[:], expectedPin) {
			return fmt.Errorf(
				"tls pin mismatch: got=%s want=%s",
				base64.StdEncoding.EncodeToString(hash[:]),
				base64.StdEncoding.EncodeToString(expectedPin),
			)
		}
		return nil
	}

	return tlsConf, nil
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
		if parsed, err := strconv.Atoi(v); err == nil {
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

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var out byte
	for i := range a {
		out |= a[i] ^ b[i]
	}
	return out == 0
}
