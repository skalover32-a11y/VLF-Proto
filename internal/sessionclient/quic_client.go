package sessionclient

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"vlf-runtime/internal/auth"
	"vlf-runtime/internal/session"
)

type quicClient struct {
	cfg      Config
	conn     *quic.Conn
	control  *quic.Stream
	controlR *bufio.Reader

	ctx    context.Context
	cancel context.CancelFunc

	ctrlMu sync.Mutex

	udpMu    sync.RWMutex
	udpFlows map[uint64]*quicUDPFlow

	closeOnce sync.Once
}

type quicTCPFlow struct {
	id     uint64
	client *quicClient
	stream *quic.Stream

	closeOnce sync.Once
}

type quicUDPFlow struct {
	id     uint64
	client *quicClient

	seq        atomic.Uint32
	reassembly *session.Reassembly
	incoming   chan []byte
	errCh      chan error

	closeOnce sync.Once
}

func dialQUIC(ctx context.Context, cfg Config) (*quicClient, error) {
	dialCtx, cancelDial := context.WithTimeout(ctx, cfg.QUICTimeout)
	defer cancelDial()

	tlsConf, err := cfg.TLSConfig()
	if err != nil {
		return nil, err
	}

	conn, err := quic.DialAddr(dialCtx, cfg.QUICAddr(), tlsConf, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		return nil, wrapErr("dial quic", err)
	}

	clientCtx, cancelClient := context.WithCancel(context.Background())
	c := &quicClient{
		cfg:      cfg,
		conn:     conn,
		ctx:      clientCtx,
		cancel:   cancelClient,
		udpFlows: make(map[uint64]*quicUDPFlow),
	}

	control, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "open_control_failed")
		cancelClient()
		return nil, wrapErr("open control stream", err)
	}

	c.control = control
	c.controlR = bufio.NewReader(control)

	if err := c.auth(ctx); err != nil {
		_ = conn.CloseWithError(0, "auth_failed")
		cancelClient()
		return nil, err
	}

	go c.datagramLoop()
	return c, nil
}

func (c *quicClient) auth(ctx context.Context) error {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return wrapErr("nonce generation", err)
	}
	ts := uint64(time.Now().UnixMilli())
	caps := uint64(0b1111)
	sig := signSession(c.cfg.Secret, auth.SessionAuthMaterial(c.cfg.ClientID, ts, nonce, caps))

	payload := session.EncodeAuthPayload(session.AuthPayload{
		ClientID: c.cfg.ClientID,
		TSMS:     ts,
		Nonce:    nonce,
		Sig:      sig,
		Caps:     caps,
	})

	c.ctrlMu.Lock()
	defer c.ctrlMu.Unlock()

	if err := session.WriteFrame(c.control, session.FrameAUTH, payload); err != nil {
		return wrapErr("write AUTH", err)
	}

	frame, err := c.readControlFrameLocked(ctx, 6*time.Second)
	if err != nil {
		return wrapErr("read AUTH response", err)
	}

	if frame.Type == session.FrameAUTHFAIL {
		return fmt.Errorf("AUTH failed: %s", decodeAuthFailReason(frame.Payload))
	}
	if frame.Type != session.FrameAUTHOK {
		return fmt.Errorf("expected AUTH_OK, got %d", frame.Type)
	}

	return nil
}

func (c *quicClient) openTCPFlow(ctx context.Context, flowID uint64, dstHost string, dstPort int) (TCPFlow, error) {
	payload := session.EncodeOpenPayload(session.OpenPayload{
		FlowID:  flowID,
		DstHost: dstHost,
		DstPort: uint16(dstPort),
	})
	if err := c.openFlow(ctx, session.FrameOPENTCP, session.FrameOPENTCPOK, session.FrameOPENTCPFAIL, payload, flowID); err != nil {
		return nil, err
	}

	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, wrapErr("open tcp flow stream", err)
	}

	var flowHdr [8]byte
	binary.BigEndian.PutUint64(flowHdr[:], flowID)
	if _, err := stream.Write(flowHdr[:]); err != nil {
		_ = stream.Close()
		return nil, wrapErr("write tcp flow header", err)
	}

	return &quicTCPFlow{
		id:     flowID,
		client: c,
		stream: stream,
	}, nil
}

func (c *quicClient) openUDPFlow(ctx context.Context, flowID uint64, dstHost string, dstPort int) (UDPFlow, error) {
	payload := session.EncodeOpenPayload(session.OpenPayload{
		FlowID:  flowID,
		DstHost: dstHost,
		DstPort: uint16(dstPort),
	})
	if err := c.openFlow(ctx, session.FrameOPENUDP, session.FrameOPENUDPOK, session.FrameOPENUDPFAIL, payload, flowID); err != nil {
		return nil, err
	}

	flow := &quicUDPFlow{
		id:         flowID,
		client:     c,
		reassembly: session.NewReassembly(),
		incoming:   make(chan []byte, 8192),
		errCh:      make(chan error, 1),
	}

	c.udpMu.Lock()
	c.udpFlows[flowID] = flow
	c.udpMu.Unlock()

	return flow, nil
}

func (c *quicClient) openFlow(
	ctx context.Context,
	reqType uint64,
	okType uint64,
	failType uint64,
	payload []byte,
	flowID uint64,
) error {
	c.ctrlMu.Lock()
	defer c.ctrlMu.Unlock()

	if err := session.WriteFrame(c.control, reqType, payload); err != nil {
		return wrapErr("write open frame", err)
	}

	for {
		frame, err := c.readControlFrameLocked(ctx, 6*time.Second)
		if err != nil {
			return wrapErr("read open response", err)
		}

		switch frame.Type {
		case okType:
			okPayload, err := session.DecodeOpenOKPayload(frame.Payload)
			if err != nil {
				return wrapErr("decode open ok payload", err)
			}
			if okPayload.FlowID != flowID {
				continue
			}
			return nil
		case failType:
			failFlowID, reason := decodeFailPayload(frame.Payload)
			if failFlowID != flowID && failFlowID != 0 {
				continue
			}
			if reason == "" {
				reason = "open flow rejected"
			}
			return errors.New(reason)
		case session.FramePING:
			_ = session.WriteFrame(c.control, session.FramePONG, frame.Payload)
		}
	}
}

func (c *quicClient) readControlFrameLocked(ctx context.Context, timeout time.Duration) (*session.Frame, error) {
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	_ = c.control.SetReadDeadline(deadline)
	frame, err := session.ReadFrame(c.controlR)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, context.DeadlineExceeded
	}
	return frame, err
}

func (c *quicClient) datagramLoop() {
	for {
		raw, err := c.conn.ReceiveDatagram(c.ctx)
		if err != nil {
			c.udpMu.Lock()
			for _, flow := range c.udpFlows {
				flow.pushErr(err)
			}
			c.udpMu.Unlock()
			return
		}

		pkt, err := session.DecodeDatagramPacket(raw)
		if err != nil {
			continue
		}

		c.udpMu.RLock()
		flow := c.udpFlows[pkt.FlowID]
		c.udpMu.RUnlock()
		if flow == nil {
			continue
		}

		payload, done := flow.reassembly.Add(pkt)
		if !done {
			continue
		}
		flow.pushPayload(payload)
	}
}

func (c *quicClient) close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		c.cancel()
		c.udpMu.Lock()
		for _, flow := range c.udpFlows {
			flow.Close()
		}
		c.udpFlows = make(map[uint64]*quicUDPFlow)
		c.udpMu.Unlock()

		if c.control != nil {
			_ = c.control.Close()
		}
		if c.conn != nil {
			closeErr = c.conn.CloseWithError(0, "client_close")
		}
	})
	return closeErr
}

func (f *quicTCPFlow) ID() uint64 {
	return f.id
}

func (f *quicTCPFlow) Read(p []byte) (int, error) {
	return f.stream.Read(p)
}

func (f *quicTCPFlow) Write(p []byte) (int, error) {
	return f.stream.Write(p)
}

func (f *quicTCPFlow) Close() error {
	var closeErr error
	f.closeOnce.Do(func() {
		closeErr = f.stream.Close()
		_ = f.client.ctrlCloseFlow(f.id)
	})
	return closeErr
}

func (c *quicClient) ctrlCloseFlow(flowID uint64) error {
	c.ctrlMu.Lock()
	defer c.ctrlMu.Unlock()
	return session.WriteFrame(c.control, session.FrameCLOSEFLOW, session.EncodeCloseFlowPayload(session.CloseFlowPayload{
		FlowID: flowID,
	}))
}

func (f *quicUDPFlow) ID() uint64 {
	return f.id
}

func (f *quicUDPFlow) Send(ctx context.Context, payload []byte) error {
	seq := f.seq.Add(1)
	packets, err := session.FragmentDatagram(f.id, seq, payload, f.client.cfg.MaxDgramPayload)
	if err != nil {
		return err
	}

	for _, pkt := range packets {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := f.client.conn.SendDatagram(pkt); err != nil {
			return err
		}
	}
	return nil
}

func (f *quicUDPFlow) Recv(ctx context.Context) ([]byte, error) {
	select {
	case payload, ok := <-f.incoming:
		if !ok {
			return nil, io.EOF
		}
		return payload, nil
	case err := <-f.errCh:
		if err == nil {
			return nil, io.EOF
		}
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (f *quicUDPFlow) Close() error {
	f.closeOnce.Do(func() {
		f.client.udpMu.Lock()
		delete(f.client.udpFlows, f.id)
		f.client.udpMu.Unlock()
		close(f.incoming)
		_ = f.client.ctrlCloseFlow(f.id)
	})
	return nil
}

func (f *quicUDPFlow) pushPayload(payload []byte) {
	select {
	case f.incoming <- payload:
	default:
	}
}

func (f *quicUDPFlow) pushErr(err error) {
	select {
	case f.errCh <- err:
	default:
	}
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

func decodeFailPayload(payload []byte) (uint64, string) {
	if len(payload) < 8 {
		return 0, string(payload)
	}
	flowID := binary.BigEndian.Uint64(payload[:8])
	if len(payload) == 8 {
		return flowID, ""
	}
	ln, n := binary.Uvarint(payload[8:])
	if n <= 0 {
		return flowID, ""
	}
	start := 8 + n
	end := start + int(ln)
	if start > len(payload) || end > len(payload) {
		return flowID, ""
	}
	return flowID, string(payload[start:end])
}

func signSession(secret []byte, payload []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}
