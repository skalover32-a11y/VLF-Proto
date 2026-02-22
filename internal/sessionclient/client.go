package sessionclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

type Transport string

const (
	TransportQUIC       Transport = "quic"
	TransportTCPSession Transport = "tcp-session"
	TransportRelay      Transport = "relay"
)

var ErrRTTProbeUnsupported = errors.New("rtt probe unsupported for current transport")

type DialError struct {
	QUICErr  error `json:"quic_err,omitempty"`
	TCPErr   error `json:"tcp_err,omitempty"`
	RelayErr error `json:"relay_err,omitempty"`
}

func (e *DialError) Error() string {
	parts := make([]string, 0, 3)
	if e.QUICErr != nil {
		parts = append(parts, "quic="+e.QUICErr.Error())
	}
	if e.TCPErr != nil {
		parts = append(parts, "tcp="+e.TCPErr.Error())
	}
	if e.RelayErr != nil {
		parts = append(parts, "relay="+e.RelayErr.Error())
	}
	return "all transports failed: " + strings.Join(parts, "; ")
}

type Client struct {
	cfg       Config
	transport Transport
	inner     clientInner
	nextFlow  atomic.Uint64
}

type clientInner interface {
	openTCPFlow(ctx context.Context, flowID uint64, dstHost string, dstPort int) (TCPFlow, error)
	openUDPFlow(ctx context.Context, flowID uint64, dstHost string, dstPort int) (UDPFlow, error)
	probeRTT(ctx context.Context) (time.Duration, error)
	close() error
}

type TCPFlow interface {
	io.ReadWriteCloser
	ID() uint64
}

type UDPFlow interface {
	ID() uint64
	Send(ctx context.Context, payload []byte) error
	Recv(ctx context.Context) ([]byte, error)
	Close() error
}

func Dial(ctx context.Context, cfg Config) (*Client, error) {
	debugf(
		cfg,
		"dial config: host=%s quic_addr=%s tcp_addr=%s relay=%s proto_id=%s alpn=%v prefer_quic=%t disable_quic=%t disable_tcp=%t allow_relay=%t force_ipv4=%t",
		cfg.GatewayHost,
		cfg.QUICAddr(),
		cfg.TCPAddr(),
		cfg.RelayBase,
		cfg.ProtoID,
		cfg.ProtoIDs,
		cfg.PreferQUIC,
		cfg.DisableQUIC,
		cfg.DisableTCPSession,
		cfg.AllowRelay,
		cfg.ForceIPv4,
	)

	var order []Transport
	if cfg.PreferQUIC {
		order = []Transport{TransportQUIC, TransportTCPSession, TransportRelay}
	} else {
		order = []Transport{TransportTCPSession, TransportQUIC, TransportRelay}
	}

	de := &DialError{}
	for _, transport := range order {
		switch transport {
		case TransportQUIC:
			if cfg.DisableQUIC {
				continue
			}
			inner, err := dialQUIC(ctx, cfg)
			if err == nil {
				return newClient(cfg, TransportQUIC, inner), nil
			}
			de.QUICErr = err
			debugf(cfg, "QUIC dial failed: %v", err)
		case TransportTCPSession:
			if cfg.DisableTCPSession {
				continue
			}
			inner, err := dialTCPSession(ctx, cfg)
			if err == nil {
				return newClient(cfg, TransportTCPSession, inner), nil
			}
			de.TCPErr = err
			debugf(cfg, "TCP session dial failed: %v", err)
		case TransportRelay:
			if !cfg.AllowRelay {
				continue
			}
			inner, err := dialRelay(ctx, cfg, &http.Client{Timeout: 10 * time.Second})
			if err == nil {
				return newClient(cfg, TransportRelay, inner), nil
			}
			de.RelayErr = err
			debugf(cfg, "relay fallback dial failed: %v", err)
		}
	}

	return nil, de
}

func newClient(cfg Config, t Transport, inner clientInner) *Client {
	c := &Client{
		cfg:       cfg,
		transport: t,
		inner:     inner,
	}
	c.nextFlow.Store(1000)
	return c
}

func (c *Client) Transport() Transport {
	return c.transport
}

func (c *Client) OpenTCPFlow(ctx context.Context, dstHost string, dstPort int) (TCPFlow, error) {
	flowID := c.nextFlow.Add(1)
	return c.inner.openTCPFlow(ctx, flowID, dstHost, dstPort)
}

func (c *Client) OpenUDPFlow(ctx context.Context, dstHost string, dstPort int) (UDPFlow, error) {
	flowID := c.nextFlow.Add(1)
	return c.inner.openUDPFlow(ctx, flowID, dstHost, dstPort)
}

func (c *Client) Close() error {
	if c.inner == nil {
		return nil
	}
	return c.inner.close()
}

func (c *Client) ProbeRTT(ctx context.Context) (time.Duration, error) {
	if c.inner == nil {
		return 0, io.EOF
	}
	return c.inner.probeRTT(ctx)
}

func debugf(cfg Config, format string, args ...any) {
	if !cfg.Debug {
		return
	}
	log.Printf("[sessionclient][DEBUG] "+format, args...)
}

func expectTimeout(ctx context.Context, fallback time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, fallback)
}

func wrapErr(stage string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", stage, err)
}
