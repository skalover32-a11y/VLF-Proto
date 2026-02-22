package sessionclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"vlf-runtime/internal/auth"
	"vlf-runtime/internal/session"
)

type tcpSessionClient struct {
	cfg    Config
	conn   net.Conn
	reader *bufio.Reader

	ctx    context.Context
	cancel context.CancelFunc

	writeMu sync.Mutex

	flowMu sync.RWMutex
	flows  map[uint64]*tcpFramedFlow

	pendingMu   sync.Mutex
	pendingTCP  map[uint64]chan openResult
	pendingUDP  map[uint64]chan openResult
	pendingPing map[string]chan error

	closeOnce sync.Once
}

type openResult struct {
	ok  bool
	err error
}

type tcpFramedFlow struct {
	id     uint64
	parent *tcpSessionClient

	bufMu sync.Mutex
	buf   bytes.Buffer

	dataCh chan []byte
	errCh  chan error

	closeOnce sync.Once
}

func dialTCPSession(ctx context.Context, cfg Config) (*tcpSessionClient, error) {
	tlsConf, err := cfg.TLSConfig()
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: cfg.TCPTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", cfg.TCPAddr(), tlsConf)
	if err != nil {
		return nil, wrapErr("dial tcp session", err)
	}

	clientCtx, cancelClient := context.WithCancel(context.Background())
	c := &tcpSessionClient{
		cfg:         cfg,
		conn:        conn,
		reader:      bufio.NewReader(conn),
		ctx:         clientCtx,
		cancel:      cancelClient,
		flows:       make(map[uint64]*tcpFramedFlow),
		pendingTCP:  make(map[uint64]chan openResult),
		pendingUDP:  make(map[uint64]chan openResult),
		pendingPing: make(map[string]chan error),
	}

	if err := c.auth(ctx); err != nil {
		cancelClient()
		_ = conn.Close()
		return nil, err
	}

	go c.readLoop()
	return c, nil
}

func (c *tcpSessionClient) auth(ctx context.Context) error {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return wrapErr("nonce generation", err)
	}

	ts := uint64(time.Now().UnixMilli())
	caps := uint64(0b0011)
	sig := signSession(c.cfg.Secret, auth.SessionAuthMaterial(c.cfg.ClientID, ts, nonce, caps))

	payload := session.EncodeAuthPayload(session.AuthPayload{
		ClientID: c.cfg.ClientID,
		TSMS:     ts,
		Nonce:    nonce,
		Sig:      sig,
		Caps:     caps,
	})

	if err := c.writeFrame(session.FrameAUTH, payload); err != nil {
		return wrapErr("write AUTH", err)
	}

	authCtx, cancel := expectTimeout(ctx, 6*time.Second)
	defer cancel()

	frame, err := c.readFrameWithContext(authCtx, 6*time.Second)
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

func (c *tcpSessionClient) openTCPFlow(ctx context.Context, flowID uint64, dstHost string, dstPort int) (TCPFlow, error) {
	respCh := make(chan openResult, 1)
	c.pendingMu.Lock()
	c.pendingTCP[flowID] = respCh
	c.pendingMu.Unlock()

	payload := session.EncodeOpenPayload(session.OpenPayload{
		FlowID:  flowID,
		DstHost: dstHost,
		DstPort: uint16(dstPort),
	})
	if err := c.writeFrame(session.FrameOPENTCP, payload); err != nil {
		c.unregisterPendingTCP(flowID)
		return nil, wrapErr("write OPEN_TCP", err)
	}

	waitCtx, cancel := expectTimeout(ctx, 8*time.Second)
	defer cancel()

	select {
	case out := <-respCh:
		if !out.ok {
			if out.err != nil {
				return nil, out.err
			}
			return nil, errors.New("OPEN_TCP failed")
		}
	case <-waitCtx.Done():
		c.unregisterPendingTCP(flowID)
		return nil, waitCtx.Err()
	}

	flow := &tcpFramedFlow{
		id:     flowID,
		parent: c,
		dataCh: make(chan []byte, 1024),
		errCh:  make(chan error, 1),
	}

	c.flowMu.Lock()
	c.flows[flowID] = flow
	c.flowMu.Unlock()
	return flow, nil
}

func (c *tcpSessionClient) openUDPFlow(ctx context.Context, flowID uint64, dstHost string, dstPort int) (UDPFlow, error) {
	respCh := make(chan openResult, 1)
	c.pendingMu.Lock()
	c.pendingUDP[flowID] = respCh
	c.pendingMu.Unlock()

	payload := session.EncodeOpenPayload(session.OpenPayload{
		FlowID:  flowID,
		DstHost: dstHost,
		DstPort: uint16(dstPort),
	})
	if err := c.writeFrame(session.FrameOPENUDP, payload); err != nil {
		c.unregisterPendingUDP(flowID)
		return nil, wrapErr("write OPEN_UDP", err)
	}

	waitCtx, cancel := expectTimeout(ctx, 8*time.Second)
	defer cancel()

	select {
	case out := <-respCh:
		if !out.ok {
			if out.err != nil {
				return nil, out.err
			}
			return nil, errors.New("OPEN_UDP failed")
		}
		return nil, errors.New("udp on tcp transport is not supported")
	case <-waitCtx.Done():
		c.unregisterPendingUDP(flowID)
		return nil, waitCtx.Err()
	}
}

func (c *tcpSessionClient) readLoop() {
	for {
		frame, err := session.ReadFrame(c.reader)
		if err != nil {
			c.closeWithError(err)
			return
		}

		switch frame.Type {
		case session.FramePING:
			_ = c.writeFrame(session.FramePONG, frame.Payload)
		case session.FramePONG:
			_ = c.resolvePendingPing(frame.Payload)
		case session.FrameOPENTCPOK:
			okPayload, err := session.DecodeOpenOKPayload(frame.Payload)
			if err != nil {
				continue
			}
			c.resolvePendingTCP(okPayload.FlowID, openResult{ok: true})
		case session.FrameOPENTCPFAIL:
			flowID, reason := decodeFailPayload(frame.Payload)
			if reason == "" {
				reason = "OPEN_TCP failed"
			}
			c.resolvePendingTCP(flowID, openResult{ok: false, err: errors.New(reason)})
		case session.FrameOPENUDPOK:
			okPayload, err := session.DecodeOpenOKPayload(frame.Payload)
			if err != nil {
				continue
			}
			c.resolvePendingUDP(okPayload.FlowID, openResult{ok: true})
		case session.FrameOPENUDPFAIL:
			flowID, reason := decodeFailPayload(frame.Payload)
			if reason == "" {
				reason = "OPEN_UDP failed"
			}
			c.resolvePendingUDP(flowID, openResult{ok: false, err: errors.New(reason)})
		case session.FrameTCPDATA:
			flowID, data, err := session.DecodeTCPDataPayload(frame.Payload)
			if err != nil {
				continue
			}
			c.flowMu.RLock()
			flow := c.flows[flowID]
			c.flowMu.RUnlock()
			if flow == nil {
				continue
			}
			flow.pushData(data)
		case session.FrameCLOSEFLOW:
			closePayload, err := session.DecodeCloseFlowPayload(frame.Payload)
			if err != nil {
				continue
			}
			c.flowMu.RLock()
			flow := c.flows[closePayload.FlowID]
			c.flowMu.RUnlock()
			if flow != nil {
				flow.pushErr(io.EOF)
			}
		}
	}
}

func (c *tcpSessionClient) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.cancel()
		_ = c.conn.Close()

		c.pendingMu.Lock()
		for flowID, ch := range c.pendingTCP {
			ch <- openResult{ok: false, err: err}
			close(ch)
			delete(c.pendingTCP, flowID)
		}
		for flowID, ch := range c.pendingUDP {
			ch <- openResult{ok: false, err: err}
			close(ch)
			delete(c.pendingUDP, flowID)
		}
		for key, ch := range c.pendingPing {
			select {
			case ch <- err:
			default:
			}
			close(ch)
			delete(c.pendingPing, key)
		}
		c.pendingMu.Unlock()

		c.flowMu.Lock()
		for flowID, flow := range c.flows {
			flow.pushErr(err)
			delete(c.flows, flowID)
		}
		c.flowMu.Unlock()
	})
}

func (c *tcpSessionClient) close() error {
	c.closeWithError(io.EOF)
	return nil
}

func (c *tcpSessionClient) probeRTT(ctx context.Context) (time.Duration, error) {
	probeCtx, cancel := expectTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	token := make([]byte, 12)
	if _, err := rand.Read(token); err != nil {
		return 0, wrapErr("random ping token", err)
	}
	key := string(token)
	waitCh := make(chan error, 1)

	c.pendingMu.Lock()
	c.pendingPing[key] = waitCh
	c.pendingMu.Unlock()

	start := time.Now()
	if err := c.writeFrame(session.FramePING, token); err != nil {
		c.unregisterPendingPing(key)
		return 0, err
	}

	select {
	case err, ok := <-waitCh:
		if !ok {
			return 0, io.EOF
		}
		if err != nil {
			return 0, err
		}
		return time.Since(start), nil
	case <-probeCtx.Done():
		c.unregisterPendingPing(key)
		return 0, probeCtx.Err()
	}
}

func (c *tcpSessionClient) writeFrame(frameType uint64, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return session.WriteFrame(c.conn, frameType, payload)
}

func (c *tcpSessionClient) readFrameWithContext(ctx context.Context, timeout time.Duration) (*session.Frame, error) {
	type frameResult struct {
		frame *session.Frame
		err   error
	}

	ch := make(chan frameResult, 1)
	go func() {
		frame, err := session.ReadFrame(c.reader)
		ch <- frameResult{frame: frame, err: err}
	}()

	select {
	case out := <-ch:
		return out.frame, out.err
	case <-time.After(timeout):
		return nil, context.DeadlineExceeded
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *tcpSessionClient) resolvePendingTCP(flowID uint64, out openResult) {
	c.pendingMu.Lock()
	ch := c.pendingTCP[flowID]
	delete(c.pendingTCP, flowID)
	c.pendingMu.Unlock()
	if ch == nil {
		return
	}
	ch <- out
	close(ch)
}

func (c *tcpSessionClient) resolvePendingUDP(flowID uint64, out openResult) {
	c.pendingMu.Lock()
	ch := c.pendingUDP[flowID]
	delete(c.pendingUDP, flowID)
	c.pendingMu.Unlock()
	if ch == nil {
		return
	}
	ch <- out
	close(ch)
}

func (c *tcpSessionClient) unregisterPendingTCP(flowID uint64) {
	c.pendingMu.Lock()
	ch := c.pendingTCP[flowID]
	delete(c.pendingTCP, flowID)
	c.pendingMu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func (c *tcpSessionClient) unregisterPendingUDP(flowID uint64) {
	c.pendingMu.Lock()
	ch := c.pendingUDP[flowID]
	delete(c.pendingUDP, flowID)
	c.pendingMu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func (c *tcpSessionClient) unregisterPendingPing(key string) {
	c.pendingMu.Lock()
	ch := c.pendingPing[key]
	delete(c.pendingPing, key)
	c.pendingMu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func (c *tcpSessionClient) resolvePendingPing(payload []byte) bool {
	key := string(payload)
	c.pendingMu.Lock()
	ch := c.pendingPing[key]
	if ch != nil {
		delete(c.pendingPing, key)
	}
	c.pendingMu.Unlock()
	if ch == nil {
		return false
	}
	select {
	case ch <- nil:
	default:
	}
	close(ch)
	return true
}

func (f *tcpFramedFlow) ID() uint64 {
	return f.id
}

func (f *tcpFramedFlow) Read(p []byte) (int, error) {
	f.bufMu.Lock()
	if f.buf.Len() > 0 {
		n, _ := f.buf.Read(p)
		f.bufMu.Unlock()
		return n, nil
	}
	f.bufMu.Unlock()

	select {
	case data := <-f.dataCh:
		if len(data) == 0 {
			return 0, io.EOF
		}
		f.bufMu.Lock()
		_, _ = f.buf.Write(data)
		n, _ := f.buf.Read(p)
		f.bufMu.Unlock()
		return n, nil
	case err := <-f.errCh:
		if err == nil {
			return 0, io.EOF
		}
		return 0, err
	case <-f.parent.ctx.Done():
		return 0, io.EOF
	}
}

func (f *tcpFramedFlow) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := f.parent.writeFrame(session.FrameTCPDATA, session.EncodeTCPDataPayload(f.id, p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (f *tcpFramedFlow) Close() error {
	f.closeOnce.Do(func() {
		f.parent.flowMu.Lock()
		delete(f.parent.flows, f.id)
		f.parent.flowMu.Unlock()
		_ = f.parent.writeFrame(session.FrameCLOSEFLOW, session.EncodeCloseFlowPayload(session.CloseFlowPayload{FlowID: f.id}))
		close(f.dataCh)
	})
	return nil
}

func (f *tcpFramedFlow) pushData(data []byte) {
	select {
	case f.dataCh <- data:
	default:
	}
}

func (f *tcpFramedFlow) pushErr(err error) {
	select {
	case f.errCh <- err:
	default:
	}
}
