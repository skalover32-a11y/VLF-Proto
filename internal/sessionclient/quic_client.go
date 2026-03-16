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

	tcpMu    sync.RWMutex
	tcpFlows map[uint64]*quicTCPFlow

	udpMu    sync.RWMutex
	udpFlows map[uint64]*quicUDPFlow

	pendingMu   sync.Mutex
	pendingOpen map[uint64]chan quicOpenResult
	pendingPing map[string]chan error

	leaseMu  sync.RWMutex
	lease    SessionLease
	hasLease bool

	unusableMu sync.RWMutex
	unusable   SessionUnusableState

	stateMu  sync.RWMutex
	closeErr error

	closeOnce sync.Once
}

type quicTCPFlow struct {
	id     uint64
	client *quicClient
	stream *quic.Stream

	streamMu sync.Mutex
	errMu    sync.RWMutex
	err      error

	closeOnce sync.Once
}

type quicUDPFlow struct {
	id     uint64
	client *quicClient

	seq        atomic.Uint32
	reassembly *session.Reassembly
	incoming   chan []byte
	errCh      chan error

	closeMu      sync.RWMutex
	closed       bool
	materialized bool
	closeErr     error

	closeOnce sync.Once
}

type quicOpenResult struct {
	ok  bool
	err error
}

func dialQUIC(ctx context.Context, cfg Config) (*quicClient, error) {
	dialCtx, cancelDial := context.WithTimeout(ctx, cfg.QUICTimeout)
	defer cancelDial()

	tlsConf, err := cfg.TLSConfig()
	if err != nil {
		return nil, err
	}
	debugf(cfg, "attempting QUIC dial: addr=%s sni=%s alpn=%v timeout=%s", cfg.QUICAddr(), tlsConf.ServerName, tlsConf.NextProtos, cfg.QUICTimeout)

	conn, err := quic.DialAddr(dialCtx, cfg.QUICAddr(), tlsConf, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		return nil, wrapErr("dial quic", err)
	}

	clientCtx, cancelClient := context.WithCancel(context.Background())
	c := &quicClient{
		cfg:         cfg,
		conn:        conn,
		ctx:         clientCtx,
		cancel:      cancelClient,
		tcpFlows:    make(map[uint64]*quicTCPFlow),
		udpFlows:    make(map[uint64]*quicUDPFlow),
		pendingOpen: make(map[uint64]chan quicOpenResult),
		pendingPing: make(map[string]chan error),
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

	go c.controlLoop()
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
		c.setUnusableReason("auth_failed", time.Now())
		return fmt.Errorf("AUTH failed: %s", decodeAuthFailReason(frame.Payload))
	}
	if frame.Type != session.FrameAUTHOK {
		return fmt.Errorf("expected AUTH_OK, got %d", frame.Type)
	}

	authOK, err := session.DecodeAuthOKPayload(frame.Payload)
	if err != nil {
		return wrapErr("decode AUTH_OK", err)
	}
	c.storeAuthLease(authOK, time.Now())

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

	flow := &quicTCPFlow{
		id:     flowID,
		client: c,
	}
	c.tcpMu.Lock()
	c.tcpFlows[flowID] = flow
	c.tcpMu.Unlock()

	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		c.closeTCPFlow(flowID, wrapErr("open tcp flow stream", err), false)
		return nil, wrapErr("open tcp flow stream", err)
	}

	var flowHdr [8]byte
	binary.BigEndian.PutUint64(flowHdr[:], flowID)
	flow.streamMu.Lock()
	if flow.currentErr() != nil {
		flow.streamMu.Unlock()
		_ = stream.Close()
		return nil, flow.currentErr()
	}
	flow.stream = stream
	flow.streamMu.Unlock()
	if _, err := stream.Write(flowHdr[:]); err != nil {
		c.closeTCPFlow(flowID, wrapErr("write tcp flow header", err), false)
		return nil, wrapErr("write tcp flow header", err)
	}

	if err := flow.currentErr(); err != nil {
		c.closeTCPFlow(flowID, err, false)
		return nil, err
	}

	return flow, nil
}

func (c *quicClient) openUDPFlow(ctx context.Context, flowID uint64, dstHost string, dstPort int) (UDPFlow, error) {
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

	payload := session.EncodeOpenPayload(session.OpenPayload{
		FlowID:  flowID,
		DstHost: dstHost,
		DstPort: uint16(dstPort),
	})
	if err := c.openFlow(ctx, session.FrameOPENUDP, session.FrameOPENUDPOK, session.FrameOPENUDPFAIL, payload, flowID); err != nil {
		_ = c.closeUDPFlow(flowID, err, false)
		return nil, err
	}

	flow.markMaterialized()
	if err := flow.currentErr(); err != nil {
		_ = c.closeUDPFlow(flowID, err, false)
		return nil, err
	}

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
	respCh, err := c.registerPendingOpen(flowID)
	if err != nil {
		return err
	}
	debugf(c.cfg, "control open_request_registered transport=quic flow_id=%d req_type=%d ok_type=%d fail_type=%d", flowID, reqType, okType, failType)

	if err := c.writeControlFrame(reqType, payload); err != nil {
		c.failPendingOpen(flowID, err)
		return wrapErr("write open frame", err)
	}

	waitCtx, cancel := expectTimeout(ctx, 6*time.Second)
	defer cancel()

	select {
	case out, ok := <-respCh:
		if !ok {
			if err := c.currentCloseErr(); err != nil {
				return err
			}
			return io.EOF
		}
		if out.ok {
			debugf(c.cfg, "control open_request_completed transport=quic flow_id=%d status=ok", flowID)
			return nil
		}
		debugf(c.cfg, "control open_request_completed transport=quic flow_id=%d status=fail err=%v", flowID, out.err)
		if out.err != nil {
			return out.err
		}
		return errors.New("open flow rejected")
	case <-waitCtx.Done():
		c.unregisterPendingOpen(flowID)
		debugf(c.cfg, "control open_request_timed_out transport=quic flow_id=%d", flowID)
		return wrapErr("read open response", waitCtx.Err())
	}
}

func (c *quicClient) probeRTT(ctx context.Context) (time.Duration, error) {
	if c.control == nil {
		return 0, io.EOF
	}

	probeCtx, cancel := expectTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	token := make([]byte, 12)
	if _, err := rand.Read(token); err != nil {
		binary.BigEndian.PutUint64(token[:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint32(token[8:], uint32(time.Now().UnixMilli()))
	}

	start := time.Now()
	key := string(token)
	waitCh := make(chan error, 1)

	c.pendingMu.Lock()
	c.pendingPing[key] = waitCh
	c.pendingMu.Unlock()

	if err := c.writeControlFrame(session.FramePING, token); err != nil {
		c.unregisterPendingPing(key)
		return 0, err
	}

	select {
	case err, ok := <-waitCh:
		if !ok {
			if err := c.currentCloseErr(); err != nil {
				return 0, err
			}
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

func (c *quicClient) controlLoop() {
	debugf(c.cfg, "control_loop_started transport=quic")
	defer debugf(c.cfg, "control_loop_stopped transport=quic")

	for {
		frame, err := session.ReadFrame(c.controlR)
		if err != nil {
			if c.ctx.Err() == nil {
				debugf(c.cfg, "control_read_error transport=quic err=%v", err)
				c.closeWithError(wrapErr("read control frame", err), "control_read_error", true)
			}
			return
		}
		c.touchLeaseNow()
		debugf(c.cfg, "control_msg_received transport=quic control_msg_type=%d", frame.Type)
		c.handleControlFrame(frame)
	}
}

func (c *quicClient) handleControlFrame(frame *session.Frame) {
	switch frame.Type {
	case session.FramePING:
		if err := c.writeControlFrame(session.FramePONG, frame.Payload); err != nil {
			debugf(c.cfg, "session_marked_unhealthy transport=quic reason=ping_reply_failed err=%v", err)
			c.closeWithError(wrapErr("write PONG", err), "ping_reply_failed", true)
		}
	case session.FramePONG:
		if !c.resolvePendingPing(frame.Payload) {
			debugf(c.cfg, "unsolicited_control_message transport=quic type=%d detail=unknown_pong", frame.Type)
		}
	case session.FrameOPENTCPOK:
		c.resolvePendingOpenOK(frame.Type, frame.Payload)
	case session.FrameOPENTCPFAIL:
		c.resolvePendingOpenFail(frame.Type, frame.Payload)
	case session.FrameOPENUDPOK:
		c.resolvePendingOpenOK(frame.Type, frame.Payload)
	case session.FrameOPENUDPFAIL:
		c.resolvePendingOpenFail(frame.Type, frame.Payload)
	case session.FrameCLOSEFLOW:
		payload, err := session.DecodeCloseFlowPayload(frame.Payload)
		if err != nil {
			debugf(c.cfg, "unsolicited_control_message transport=quic type=%d detail=invalid_closeflow err=%v", frame.Type, err)
			return
		}
		debugf(c.cfg, "closeflow_received transport=quic flow_id=%d", payload.FlowID)
		if !c.closeFlowLocal(payload.FlowID, io.EOF) {
			debugf(c.cfg, "unsolicited_control_message transport=quic type=%d flow_id=%d detail=closeflow_unknown_flow", frame.Type, payload.FlowID)
		}
	case session.FrameAUTHFAIL:
		reason := decodeAuthFailReason(frame.Payload)
		if reason == "" {
			reason = "server sent AUTH_FAIL after auth"
		}
		err := errors.New(reason)
		debugf(c.cfg, "session_marked_unhealthy transport=quic reason=authfail_after_auth err=%v", err)
		c.closeWithError(err, "authfail_after_auth", true)
	default:
		debugf(c.cfg, "unsolicited_control_message transport=quic type=%d", frame.Type)
	}
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
		c.touchLeaseNow()

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
	return c.closeWithError(io.EOF, "client_close", false)
}

func (c *quicClient) closeWithError(err error, reason string, markUnhealthy bool) error {
	var closeErr error
	c.closeOnce.Do(func() {
		if err == nil {
			err = io.EOF
		}
		c.setCloseErr(err)
		c.setUnusableReason(quicUnusableReason(reason), time.Now())
		if markUnhealthy {
			debugf(c.cfg, "session_marked_unhealthy transport=quic reason=%s err=%v", reason, err)
		}

		c.cancel()

		pendingOpen, pendingPing := c.drainPending()
		tcpFlows, udpFlows := c.snapshotFlows()

		for _, flow := range tcpFlows {
			flow.closeLocal(err)
		}
		for _, flow := range udpFlows {
			flow.closeLocal(err)
		}

		for _, ch := range pendingOpen {
			ch <- quicOpenResult{ok: false, err: err}
			close(ch)
		}
		for _, ch := range pendingPing {
			select {
			case ch <- err:
			default:
			}
			close(ch)
		}

		if c.control != nil {
			_ = c.control.Close()
		}
		if c.conn != nil {
			closeErr = c.conn.CloseWithError(0, reason)
		}
	})
	return closeErr
}

func (c *quicClient) snapshotFlows() ([]*quicTCPFlow, []*quicUDPFlow) {
	c.tcpMu.Lock()
	tcpFlows := make([]*quicTCPFlow, 0, len(c.tcpFlows))
	for _, flow := range c.tcpFlows {
		tcpFlows = append(tcpFlows, flow)
	}
	c.tcpFlows = make(map[uint64]*quicTCPFlow)
	c.tcpMu.Unlock()

	c.udpMu.Lock()
	udpFlows := make([]*quicUDPFlow, 0, len(c.udpFlows))
	for _, flow := range c.udpFlows {
		udpFlows = append(udpFlows, flow)
	}
	c.udpFlows = make(map[uint64]*quicUDPFlow)
	c.udpMu.Unlock()

	return tcpFlows, udpFlows
}

func (c *quicClient) drainPending() ([]chan quicOpenResult, []chan error) {
	c.pendingMu.Lock()
	openChans := make([]chan quicOpenResult, 0, len(c.pendingOpen))
	for flowID, ch := range c.pendingOpen {
		openChans = append(openChans, ch)
		delete(c.pendingOpen, flowID)
	}
	pingChans := make([]chan error, 0, len(c.pendingPing))
	for key, ch := range c.pendingPing {
		pingChans = append(pingChans, ch)
		delete(c.pendingPing, key)
	}
	c.pendingMu.Unlock()

	return openChans, pingChans
}

func (c *quicClient) registerPendingOpen(flowID uint64) (chan quicOpenResult, error) {
	respCh := make(chan quicOpenResult, 1)
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	if _, exists := c.pendingOpen[flowID]; exists {
		return nil, fmt.Errorf("open request already pending for flow %d", flowID)
	}
	c.pendingOpen[flowID] = respCh
	return respCh, nil
}

func (c *quicClient) resolvePendingOpenOK(frameType uint64, payload []byte) {
	okPayload, err := session.DecodeOpenOKPayload(payload)
	if err != nil {
		debugf(c.cfg, "unsolicited_control_message transport=quic type=%d detail=invalid_open_ok err=%v", frameType, err)
		return
	}

	c.pendingMu.Lock()
	ch := c.pendingOpen[okPayload.FlowID]
	if ch != nil {
		delete(c.pendingOpen, okPayload.FlowID)
	}
	c.pendingMu.Unlock()

	if ch == nil {
		debugf(c.cfg, "unsolicited_control_message transport=quic type=%d flow_id=%d detail=open_ok_without_pending", frameType, okPayload.FlowID)
		return
	}
	ch <- quicOpenResult{ok: true}
	close(ch)
}

func (c *quicClient) resolvePendingOpenFail(frameType uint64, payload []byte) {
	flowID, reason := decodeFailPayload(payload)
	if reason == "" {
		reason = "open flow rejected"
	}

	c.pendingMu.Lock()
	ch := c.pendingOpen[flowID]
	if ch != nil {
		delete(c.pendingOpen, flowID)
	}
	c.pendingMu.Unlock()

	if ch == nil {
		debugf(c.cfg, "unsolicited_control_message transport=quic type=%d flow_id=%d detail=open_fail_without_pending reason=%s", frameType, flowID, reason)
		return
	}
	ch <- quicOpenResult{ok: false, err: errors.New(reason)}
	close(ch)
}

func (c *quicClient) failPendingOpen(flowID uint64, err error) {
	c.pendingMu.Lock()
	ch := c.pendingOpen[flowID]
	if ch != nil {
		delete(c.pendingOpen, flowID)
	}
	c.pendingMu.Unlock()
	if ch == nil {
		return
	}
	ch <- quicOpenResult{ok: false, err: err}
	close(ch)
}

func (c *quicClient) leaseState() (SessionLease, bool) {
	c.leaseMu.RLock()
	defer c.leaseMu.RUnlock()
	if !c.hasLease {
		return SessionLease{}, false
	}
	return c.lease, true
}

func (c *quicClient) unusableState() (SessionUnusableState, bool) {
	c.unusableMu.RLock()
	defer c.unusableMu.RUnlock()
	if c.unusable.Reason == "" {
		return SessionUnusableState{}, false
	}
	return c.unusable, true
}

func (c *quicClient) storeAuthLease(payload session.AuthOKPayload, now time.Time) {
	ttl := time.Duration(payload.ExpiresMS) * time.Millisecond
	if ttl <= 0 {
		c.leaseMu.Lock()
		c.lease = SessionLease{}
		c.hasLease = false
		c.leaseMu.Unlock()
		return
	}

	lease := SessionLease{
		SessionID:      payload.SessionID,
		IssuedAt:       now,
		LastActivityAt: now,
		ExpiresAt:      now.Add(ttl),
		TTL:            ttl,
		UpKbps:         payload.UpKbps,
		DownKbps:       payload.DownKbps,
		MaxFlows:       payload.MaxFlows,
		MaxUDPPPS:      payload.MaxUDPPPS,
	}

	c.leaseMu.Lock()
	c.lease = lease
	c.hasLease = true
	c.leaseMu.Unlock()

	debugf(
		c.cfg,
		"auth_lease_received transport=quic session_id=%d ttl=%s issued_at=%s expires_at=%s",
		lease.SessionID,
		lease.TTL,
		lease.IssuedAt.UTC().Format(time.RFC3339Nano),
		lease.ExpiresAt.UTC().Format(time.RFC3339Nano),
	)
}

func (c *quicClient) touchLeaseNow() {
	c.touchLeaseAt(time.Now())
}

func (c *quicClient) touchLeaseAt(now time.Time) {
	c.leaseMu.Lock()
	if c.hasLease && c.lease.TTL > 0 {
		c.lease.LastActivityAt = now
		c.lease.ExpiresAt = now.Add(c.lease.TTL)
	}
	c.leaseMu.Unlock()
}

func (c *quicClient) setUnusableReason(reason string, now time.Time) {
	if reason == "" {
		return
	}
	c.unusableMu.Lock()
	if c.unusable.Reason == "" {
		c.unusable = SessionUnusableState{
			Reason: reason,
			Since:  now,
		}
	}
	c.unusableMu.Unlock()
}

func (c *quicClient) unregisterPendingOpen(flowID uint64) {
	c.pendingMu.Lock()
	ch := c.pendingOpen[flowID]
	if ch != nil {
		delete(c.pendingOpen, flowID)
	}
	c.pendingMu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func (c *quicClient) unregisterPendingPing(key string) {
	c.pendingMu.Lock()
	ch := c.pendingPing[key]
	if ch != nil {
		delete(c.pendingPing, key)
	}
	c.pendingMu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func (c *quicClient) resolvePendingPing(payload []byte) bool {
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

func (c *quicClient) setCloseErr(err error) {
	c.stateMu.Lock()
	if c.closeErr == nil {
		c.closeErr = err
	}
	c.stateMu.Unlock()
}

func (c *quicClient) currentCloseErr() error {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.closeErr
}

func (f *quicTCPFlow) ID() uint64 {
	return f.id
}

func (f *quicTCPFlow) Read(p []byte) (int, error) {
	if err := f.currentErr(); err != nil {
		return 0, err
	}
	n, err := f.stream.Read(p)
	if n > 0 {
		f.client.touchLeaseNow()
	}
	if err != nil {
		if closeErr := f.currentErr(); closeErr != nil {
			return n, closeErr
		}
	}
	return n, err
}

func (f *quicTCPFlow) Write(p []byte) (int, error) {
	if err := f.currentErr(); err != nil {
		return 0, err
	}
	n, err := f.stream.Write(p)
	if n > 0 {
		f.client.touchLeaseNow()
	}
	if err != nil {
		if closeErr := f.currentErr(); closeErr != nil {
			return n, closeErr
		}
	}
	return n, err
}

func (f *quicTCPFlow) Close() error {
	return f.client.closeTCPFlow(f.id, io.EOF, true)
}

func (f *quicTCPFlow) closeLocal(err error) {
	f.closeOnce.Do(func() {
		if err == nil {
			err = io.EOF
		}
		f.errMu.Lock()
		f.err = err
		f.errMu.Unlock()
		f.streamMu.Lock()
		if f.stream != nil {
			f.stream.CancelRead(quic.StreamErrorCode(0))
			f.stream.CancelWrite(quic.StreamErrorCode(0))
			_ = f.stream.Close()
		}
		f.streamMu.Unlock()
	})
}

func (f *quicTCPFlow) currentErr() error {
	f.errMu.RLock()
	defer f.errMu.RUnlock()
	return f.err
}

func (c *quicClient) ctrlCloseFlow(flowID uint64) error {
	return c.writeControlFrame(session.FrameCLOSEFLOW, session.EncodeCloseFlowPayload(session.CloseFlowPayload{
		FlowID: flowID,
	}))
}

func (c *quicClient) writeControlFrame(frameType uint64, payload []byte) error {
	if err := c.currentCloseErr(); err != nil {
		return err
	}
	c.ctrlMu.Lock()
	defer c.ctrlMu.Unlock()
	if err := c.currentCloseErr(); err != nil {
		return err
	}
	if err := session.WriteFrame(c.control, frameType, payload); err != nil {
		return err
	}
	c.touchLeaseNow()
	return nil
}

func (c *quicClient) closeTCPFlow(flowID uint64, err error, notify bool) error {
	c.tcpMu.Lock()
	flow := c.tcpFlows[flowID]
	if flow != nil {
		delete(c.tcpFlows, flowID)
	}
	c.tcpMu.Unlock()
	if flow == nil {
		return nil
	}
	flow.closeLocal(err)
	if notify {
		return c.ctrlCloseFlow(flowID)
	}
	return nil
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
	f.client.touchLeaseNow()
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
	return f.client.closeUDPFlow(f.id, io.EOF, true)
}

func (f *quicUDPFlow) closeLocal(err error) {
	f.closeOnce.Do(func() {
		f.closeMu.Lock()
		f.closed = true
		if err == nil {
			err = io.EOF
		}
		f.closeErr = err
		if err != nil {
			select {
			case f.errCh <- err:
			default:
			}
		}
		close(f.incoming)
		f.closeMu.Unlock()
	})
}

func (f *quicUDPFlow) pushPayload(payload []byte) {
	f.closeMu.RLock()
	if f.closed {
		f.closeMu.RUnlock()
		return
	}
	select {
	case f.incoming <- payload:
	default:
	}
	f.closeMu.RUnlock()
}

func (f *quicUDPFlow) pushErr(err error) {
	select {
	case f.errCh <- err:
	default:
	}
}

func (f *quicUDPFlow) markMaterialized() {
	f.closeMu.Lock()
	f.materialized = true
	f.closeMu.Unlock()
}

func (f *quicUDPFlow) isMaterialized() bool {
	f.closeMu.RLock()
	defer f.closeMu.RUnlock()
	return f.materialized
}

func (f *quicUDPFlow) currentErr() error {
	f.closeMu.RLock()
	defer f.closeMu.RUnlock()
	return f.closeErr
}

func (c *quicClient) closeUDPFlow(flowID uint64, err error, notify bool) error {
	c.udpMu.Lock()
	flow := c.udpFlows[flowID]
	if flow != nil {
		delete(c.udpFlows, flowID)
	}
	c.udpMu.Unlock()
	if flow == nil {
		return nil
	}
	flow.closeLocal(err)
	if notify {
		return c.ctrlCloseFlow(flowID)
	}
	return nil
}

func (c *quicClient) closeFlowLocal(flowID uint64, err error) bool {
	c.tcpMu.RLock()
	_, tcpExists := c.tcpFlows[flowID]
	c.tcpMu.RUnlock()
	if tcpExists {
		_ = c.closeTCPFlow(flowID, err, false)
		return true
	}
	c.udpMu.RLock()
	flow := c.udpFlows[flowID]
	c.udpMu.RUnlock()
	if flow != nil {
		if !flow.isMaterialized() {
			debugf(c.cfg, "early_closeflow_buffered_or_applied transport=quic flow_id=%d detail=applied_before_open_ok", flowID)
		}
		_ = c.closeUDPFlow(flowID, err, false)
		return true
	}
	return false
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

func quicUnusableReason(reason string) string {
	switch reason {
	case "control_read_error":
		return "control_loop_dead"
	case "authfail_after_auth":
		return "auth_failed"
	case "ping_reply_failed":
		return "transport_unhealthy"
	case "client_close":
		return "session_closed"
	default:
		if reason == "" {
			return ""
		}
		return "transport_unhealthy"
	}
}

func signSession(secret []byte, payload []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}
