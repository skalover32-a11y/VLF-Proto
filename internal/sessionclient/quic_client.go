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
	"math"
	mrand "math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"vlf-runtime/internal/auth"
	"vlf-runtime/internal/session"
	"vlf-runtime/internal/transport/health"
	"vlf-runtime/internal/transport/migration"
	"vlf-runtime/internal/transport/profile"
	"vlf-runtime/internal/transport/resume"
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

	pendingMu      sync.Mutex
	pendingOpen    map[uint64]chan quicOpenResult
	pendingPing    map[string]chan error
	pendingProfile chan quicProfileResult

	leaseMu  sync.RWMutex
	lease    SessionLease
	hasLease bool

	profileRegistry     *profile.Registry
	profileMu           sync.RWMutex
	currentProfileState profile.TransportProfile

	healthMu      sync.RWMutex
	healthEngine  *health.Engine
	lastRTTMs     float64
	hasRTTSample  bool
	scheduler     *migration.Scheduler
	resumeKey     string
	resumeAttempt bool
	debugState    clientDebugState

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

type quicProfileResult struct {
	profileID string
	err       error
}

func dialQUIC(ctx context.Context, cfg Config) (*quicClient, error) {
	useExtendedAuth := cfg.TransportProfilesEnabled || cfg.ResumeTokensEnabled
	client, err := dialQUICAttempt(ctx, cfg, useExtendedAuth)
	if err == nil {
		return client, nil
	}
	if useExtendedAuth && errors.Is(err, errLegacyPeerAuthUnsupported) {
		debugf(cfg, "auth_fallback_to_legacy transport=quic reason=legacy_peer_rejected_extended_auth")
		client, legacyErr := dialQUICAttempt(ctx, cfg, false)
		if legacyErr != nil {
			return nil, legacyErr
		}
		client.debugState.markLegacyFallback("legacy peer rejected extended auth")
		debugf(cfg, "transport_feature_fallback transport=quic feature=profiles_resume mode=legacy_auth")
		return client, nil
	}
	return nil, err
}

func dialQUICAttempt(ctx context.Context, cfg Config, useExtendedAuth bool) (*quicClient, error) {
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
	reg := cfg.ProfileRegistry
	if reg == nil {
		reg = profile.DefaultRegistry()
	}
	active := reg.MustGetOrDefault(cfg.TransportProfileID)
	c := &quicClient{
		cfg:                 cfg,
		conn:                conn,
		ctx:                 clientCtx,
		cancel:              cancelClient,
		tcpFlows:            make(map[uint64]*quicTCPFlow),
		udpFlows:            make(map[uint64]*quicUDPFlow),
		pendingOpen:         make(map[uint64]chan quicOpenResult),
		pendingPing:         make(map[string]chan error),
		profileRegistry:     reg,
		currentProfileState: active,
		resumeKey:           resume.Key(firstNonEmpty(cfg.GatewayHost, cfg.GatewayDialHost), cfg.ClientID),
	}
	c.debugState.init(active.ID, time.Now())
	if cfg.ProfileScoringEnabled {
		c.healthEngine = health.NewEngine(health.Config{})
	}
	if cfg.ProfileMigrationEnabled && cfg.TransportProfilesEnabled {
		c.scheduler = migration.NewScheduler(migration.Config{}, reg)
	}

	control, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "open_control_failed")
		cancelClient()
		return nil, wrapErr("open control stream", err)
	}

	c.control = control
	c.controlR = bufio.NewReader(control)

	if err := c.auth(ctx, useExtendedAuth); err != nil {
		_ = conn.CloseWithError(0, "auth_failed")
		cancelClient()
		return nil, err
	}

	go c.controlLoop()
	go c.datagramLoop()
	if c.scheduler != nil && c.healthEngine != nil {
		go c.migrationLoop()
	}
	return c, nil
}

func (c *quicClient) auth(ctx context.Context, useExtendedAuth bool) error {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return wrapErr("nonce generation", err)
	}
	ts := uint64(time.Now().UnixMilli())
	caps := uint64(0b1111)
	sig := signSession(c.cfg.Secret, auth.SessionAuthMaterial(c.cfg.ClientID, ts, nonce, caps))
	authPayload := session.AuthPayload{
		ClientID: c.cfg.ClientID,
		TSMS:     ts,
		Nonce:    nonce,
		Sig:      sig,
		Caps:     caps,
	}
	if useExtendedAuth && c.cfg.TransportProfilesEnabled {
		authPayload.ProfileID = c.activeProfileID()
	}
	if useExtendedAuth && c.cfg.ResumeTokensEnabled && c.cfg.ResumeStore != nil {
		if state, ok := c.cfg.ResumeStore.Load(c.resumeKey); ok && state.ExpiresAt.After(time.Now()) {
			authPayload.ResumeTag = append([]byte(nil), state.Tag...)
			authPayload.ResumeToken = append([]byte(nil), state.Token...)
			c.healthMu.Lock()
			c.resumeAttempt = true
			c.healthMu.Unlock()
		}
	}
	c.debugState.setResumePath(ResumePathFullAuth)

	payload := session.EncodeAuthPayload(authPayload)

	c.ctrlMu.Lock()
	defer c.ctrlMu.Unlock()

	if err := session.WriteFrame(c.control, session.FrameAUTH, payload); err != nil {
		return wrapErr("write AUTH", err)
	}

	frame, err := c.readControlFrameLocked(ctx, 6*time.Second)
	if err != nil {
		if useExtendedAuth && isLegacyAuthCloseBeforeOK(err) {
			return errLegacyPeerAuthUnsupported
		}
		return wrapErr("read AUTH response", err)
	}

	if frame.Type == session.FrameAUTHFAIL {
		reason := decodeAuthFailReason(frame.Payload)
		if useExtendedAuth && isLegacyAuthUnsupportedReason(reason) {
			return errLegacyPeerAuthUnsupported
		}
		c.setUnusableReason("auth_failed", time.Now())
		c.healthMu.RLock()
		resumeAttempt := c.resumeAttempt
		c.healthMu.RUnlock()
		c.observeHealth(health.Sample{At: time.Now(), ProfileID: c.activeProfileID(), PathFamily: "quic", IdleResumeFailure: resumeAttempt})
		return fmt.Errorf("AUTH failed: %s", reason)
	}
	if frame.Type != session.FrameAUTHOK {
		return fmt.Errorf("expected AUTH_OK, got %d", frame.Type)
	}

	authOK, err := session.DecodeAuthOKPayload(frame.Payload)
	if err != nil {
		return wrapErr("decode AUTH_OK", err)
	}
	c.storeAuthLease(authOK, time.Now())
	c.applyAuthOKProfile(authOK.ProfileID)
	resumeAccepted := c.storeResumeState(authOK)
	c.healthMu.RLock()
	resumeAttempt := c.resumeAttempt
	c.healthMu.RUnlock()
	if resumeAttempt {
		if resumeAccepted {
			c.debugState.setResumePath(ResumePathResumeFastPath)
			c.observeHealth(health.Sample{At: time.Now(), ProfileID: c.activeProfileID(), PathFamily: "quic", IdleResumeSuccess: true})
		} else {
			debugf(c.cfg, "transport_feature_fallback transport=quic feature=resume_tokens mode=full_auth reason=peer_did_not_confirm_resume")
		}
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

	waitTimeout := 6 * time.Second
	if retry := c.currentProfile().RetryPolicy.OpenBackoff; retry > 0 && retry > waitTimeout {
		waitTimeout = retry
	}
	waitCtx, cancel := expectTimeout(ctx, waitTimeout)
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
			c.observeHealth(health.Sample{At: time.Now(), ProfileID: c.activeProfileID(), PathFamily: "quic"})
			return nil
		}
		debugf(c.cfg, "control open_request_completed transport=quic flow_id=%d status=fail err=%v", flowID, out.err)
		if out.err != nil {
			c.observeHealth(health.Sample{At: time.Now(), ProfileID: c.activeProfileID(), PathFamily: "quic", TimeoutRate: 1, RecoveryEvent: true})
			return out.err
		}
		return errors.New("open flow rejected")
	case <-waitCtx.Done():
		c.unregisterPendingOpen(flowID)
		debugf(c.cfg, "control open_request_timed_out transport=quic flow_id=%d", flowID)
		c.observeHealth(health.Sample{At: time.Now(), ProfileID: c.activeProfileID(), PathFamily: "quic", TimeoutRate: 1, RecoveryEvent: true})
		return wrapErr("read open response", waitCtx.Err())
	}
}

func (c *quicClient) probeRTT(ctx context.Context) (time.Duration, error) {
	if c.control == nil {
		return 0, io.EOF
	}

	profileCfg := c.currentProfile()
	probeTimeout := profileProbeTimeout(profileCfg, 1500*time.Millisecond)
	probeCtx, cancel := expectTimeout(ctx, probeTimeout)
	defer cancel()

	token := make([]byte, 12)
	if _, err := rand.Read(token); err != nil {
		binary.BigEndian.PutUint64(token[:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint32(token[8:], uint32(time.Now().UnixMilli()))
	}

	start := time.Now()
	payload := profileProbePayload(token, profileCfg)
	key := string(payload)
	waitCh := make(chan error, 1)

	c.pendingMu.Lock()
	c.pendingPing[key] = waitCh
	c.pendingMu.Unlock()

	if err := c.writeControlFrame(session.FramePING, payload); err != nil {
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
			c.observeHealth(health.Sample{At: time.Now(), ProfileID: c.activeProfileID(), PathFamily: "quic", TimeoutRate: 1})
			return 0, err
		}
		rtt := time.Since(start)
		c.observeRTT(rtt, "quic")
		return rtt, nil
	case <-probeCtx.Done():
		c.unregisterPendingPing(key)
		c.observeHealth(health.Sample{At: time.Now(), ProfileID: c.activeProfileID(), PathFamily: "quic", TimeoutRate: 1, AckStarved: true})
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
	case session.FramePROFILEOK:
		c.resolvePendingProfile(frame.Type, frame.Payload, nil)
	case session.FramePROFILEFAIL:
		payload, err := session.DecodeProfilePayload(frame.Payload)
		if err != nil {
			c.resolvePendingProfile(frame.Type, nil, errors.New("invalid profile fail payload"))
			return
		}
		if payload.Reason == "" {
			payload.Reason = "profile switch rejected"
		}
		c.resolvePendingProfile(frame.Type, frame.Payload, errors.New(payload.Reason))
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

		pendingOpen, pendingPing, pendingProfile := c.drainPending()
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
		if pendingProfile != nil {
			pendingProfile <- quicProfileResult{err: err}
			close(pendingProfile)
		}

		if c.control != nil {
			_ = c.control.Close()
		}
		if c.conn != nil {
			closeErr = c.conn.CloseWithError(0, reason)
		}
		c.observeHealth(health.Sample{At: time.Now(), ProfileID: c.activeProfileID(), PathFamily: "quic", PathFlap: true, ReceiveStalled: true, RecoveryEvent: true})
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

func (c *quicClient) drainPending() ([]chan quicOpenResult, []chan error, chan quicProfileResult) {
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
	profileCh := c.pendingProfile
	c.pendingProfile = nil
	c.pendingMu.Unlock()

	return openChans, pingChans, profileCh
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

func (c *quicClient) activeProfile() string {
	return c.activeProfileID()
}

func (c *quicClient) activeProfileID() string {
	c.profileMu.RLock()
	defer c.profileMu.RUnlock()
	return c.currentProfileState.ID
}

func (c *quicClient) currentProfile() profile.TransportProfile {
	c.profileMu.RLock()
	defer c.profileMu.RUnlock()
	return c.currentProfileState
}

func (c *quicClient) setActiveProfileByID(id string) profile.TransportProfile {
	next := c.profileRegistry.MustGetOrDefault(id)
	c.profileMu.Lock()
	c.currentProfileState = next
	c.profileMu.Unlock()
	return next
}

func (c *quicClient) applyAuthOKProfile(id string) {
	if !c.cfg.TransportProfilesEnabled {
		return
	}
	if id == "" {
		return
	}
	applied := c.setActiveProfileByID(id)
	c.debugState.noteProfile(applied.ID, time.Now())
	debugf(c.cfg, "transport_profile_applied transport=quic profile_id=%s reason=auth_ok", applied.ID)
}

func (c *quicClient) healthSnapshot() (health.Snapshot, bool) {
	c.healthMu.RLock()
	engine := c.healthEngine
	c.healthMu.RUnlock()
	if engine == nil {
		return health.Snapshot{}, false
	}
	return engine.Evaluate(time.Now()), true
}

func (c *quicClient) debugSnapshot() (DebugSnapshot, bool) {
	now := time.Now()
	snapshot := c.debugState.snapshot(now)
	snapshot.ActiveProfile = c.activeProfileID()
	if lease, ok := c.leaseState(); ok {
		snapshot.SessionLease = lease
		snapshot.HasSessionLease = true
	}
	if unusable, ok := c.unusableState(); ok {
		snapshot.SessionUnusable = unusable
		snapshot.HasSessionUnusable = true
	}
	if healthSnap, ok := c.healthSnapshot(); ok {
		snapshot.HealthScore = healthSnap.Score
		snapshot.DegradationLevel = healthSnap.Level
		snapshot.DegradationReasonFlags = append([]health.ReasonFlag(nil), healthSnap.Flags...)
	}
	if c.scheduler != nil {
		sched := c.scheduler.Snapshot(now)
		snapshot.MigrationCooldownRemaining = sched.CooldownRemaining
		snapshot.MigrationCooldownActive = sched.CooldownRemaining > 0
	}
	return snapshot, true
}

func (c *quicClient) ApplyTransportProfile(ctx context.Context, profileID string) error {
	return c.applyTransportProfile(ctx, profileID)
}

func (c *quicClient) applyTransportProfile(ctx context.Context, profileID string) error {
	if !c.cfg.TransportProfilesEnabled {
		return nil
	}
	next, ok := c.profileRegistry.Get(profileID)
	if !ok {
		return fmt.Errorf("unknown transport profile %q", profileID)
	}
	if next.ID == c.activeProfileID() {
		return nil
	}
	if !c.cfg.ProfileMigrationEnabled {
		c.setActiveProfileByID(next.ID)
		c.debugState.noteProfile(next.ID, time.Now())
		return nil
	}
	if unsupported, reason := c.debugState.profileSwitchUnsupportedState(); unsupported {
		debugf(c.cfg, "transport_feature_fallback transport=quic feature=profile_migration requested=%s active=%s reason=%s", next.ID, c.activeProfileID(), reason)
		return ErrProfileSwitchUnsupported
	}

	c.debugState.noteMigrationAttempt("apply_transport_profile", time.Now())
	respCh, err := c.registerPendingProfile()
	if err != nil {
		return err
	}
	if err := c.writeControlFrame(session.FramePROFILESET, session.EncodeProfilePayload(session.ProfilePayload{ProfileID: next.ID})); err != nil {
		c.failPendingProfile(err)
		return wrapErr("write profile switch", err)
	}

	waitTimeout := 4 * time.Second
	if retry := c.currentProfile().RetryPolicy.OpenBackoff; retry > 0 {
		waitTimeout = retry
	}
	waitCtx, cancel := expectTimeout(ctx, waitTimeout)
	defer cancel()

	select {
	case out, ok := <-respCh:
		if !ok {
			if err := c.currentCloseErr(); err != nil {
				return err
			}
			return io.EOF
		}
		if out.err != nil {
			if errors.Is(out.err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(out.err.Error()), "migration disabled") {
				c.debugState.markProfileSwitchUnsupported(out.err.Error())
				debugf(c.cfg, "transport_feature_fallback transport=quic feature=profile_migration requested=%s reason=%s", next.ID, out.err)
				return fmt.Errorf("%w: %s", ErrProfileSwitchUnsupported, out.err)
			}
			return out.err
		}
		applied := c.setActiveProfileByID(firstNonEmpty(out.profileID, next.ID))
		c.debugState.noteProfile(applied.ID, time.Now())
		c.debugState.noteMigrationSuccess(time.Now())
		debugf(c.cfg, "transport_profile_applied transport=quic profile_id=%s reason=profile_ok", applied.ID)
		return nil
	case <-waitCtx.Done():
		c.unregisterPendingProfile()
		c.debugState.markProfileSwitchUnsupported(waitCtx.Err().Error())
		debugf(c.cfg, "transport_feature_fallback transport=quic feature=profile_migration requested=%s reason=%v", next.ID, waitCtx.Err())
		return fmt.Errorf("%w: %v", ErrProfileSwitchUnsupported, waitCtx.Err())
	}
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

func (c *quicClient) storeResumeState(payload session.AuthOKPayload) bool {
	if !c.cfg.ResumeTokensEnabled || c.cfg.ResumeStore == nil || len(payload.ResumeTag) == 0 || len(payload.ResumeToken) == 0 {
		return false
	}
	lease, ok := c.leaseState()
	if !ok {
		return false
	}
	c.cfg.ResumeStore.Save(c.resumeKey, resume.State{
		Tag:        append([]byte(nil), payload.ResumeTag...),
		Token:      append([]byte(nil), payload.ResumeToken...),
		ExpiresAt:  lease.ExpiresAt,
		ProfileID:  firstNonEmpty(payload.ProfileID, c.activeProfileID()),
		PathFamily: "quic",
		Lineage:    lease.SessionID,
	})
	return true
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

func (c *quicClient) observeHealth(sample health.Sample) {
	c.healthMu.RLock()
	engine := c.healthEngine
	c.healthMu.RUnlock()
	if engine == nil {
		return
	}
	if sample.At.IsZero() {
		sample.At = time.Now()
	}
	if sample.ProfileID == "" {
		sample.ProfileID = c.activeProfileID()
	}
	if sample.PathFamily == "" {
		sample.PathFamily = "quic"
	}
	engine.Observe(sample)
}

func (c *quicClient) observeRTT(rtt time.Duration, pathFamily string) {
	if rtt <= 0 {
		return
	}
	rttMs := float64(rtt.Milliseconds())
	if rttMs <= 0 {
		rttMs = float64(rtt) / float64(time.Millisecond)
	}
	c.healthMu.Lock()
	jitter := 0.0
	if c.hasRTTSample {
		jitter = math.Abs(c.lastRTTMs - rttMs)
	}
	c.lastRTTMs = rttMs
	c.hasRTTSample = true
	engine := c.healthEngine
	c.healthMu.Unlock()
	if engine == nil {
		return
	}
	engine.Observe(health.Sample{
		At:         time.Now(),
		ProfileID:  c.activeProfileID(),
		PathFamily: pathFamily,
		RTTMs:      rttMs,
		JitterMs:   jitter,
	})
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

func (c *quicClient) registerPendingProfile() (chan quicProfileResult, error) {
	respCh := make(chan quicProfileResult, 1)
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	if c.pendingProfile != nil {
		return nil, errors.New("profile switch already pending")
	}
	c.pendingProfile = respCh
	return respCh, nil
}

func (c *quicClient) resolvePendingProfile(frameType uint64, payload []byte, err error) {
	c.pendingMu.Lock()
	ch := c.pendingProfile
	if ch != nil {
		c.pendingProfile = nil
	}
	c.pendingMu.Unlock()
	if ch == nil {
		debugf(c.cfg, "unsolicited_control_message transport=quic type=%d detail=profile_response_without_pending", frameType)
		return
	}
	profileID := ""
	if len(payload) > 0 {
		if decoded, decodeErr := session.DecodeProfilePayload(payload); decodeErr == nil {
			profileID = decoded.ProfileID
			if err == nil && decoded.Reason != "" {
				err = errors.New(decoded.Reason)
			}
		}
	}
	ch <- quicProfileResult{profileID: profileID, err: err}
	close(ch)
}

func (c *quicClient) failPendingProfile(err error) {
	c.pendingMu.Lock()
	ch := c.pendingProfile
	if ch != nil {
		c.pendingProfile = nil
	}
	c.pendingMu.Unlock()
	if ch == nil {
		return
	}
	ch <- quicProfileResult{err: err}
	close(ch)
}

func (c *quicClient) unregisterPendingProfile() {
	c.pendingMu.Lock()
	ch := c.pendingProfile
	if ch != nil {
		c.pendingProfile = nil
	}
	c.pendingMu.Unlock()
	if ch != nil {
		close(ch)
	}
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

func (c *quicClient) migrationLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if unsupported, reason := c.debugState.profileSwitchUnsupportedState(); unsupported {
				debugf(c.cfg, "profile_migration_skipped transport=quic reason=%s", reason)
				continue
			}
			snap, ok := c.healthSnapshot()
			if !ok {
				continue
			}
			decision := c.scheduler.ChooseNextProfile(c.activeProfileID(), snap, migration.PathInfo{
				Family:         string(c.currentProfile().Family),
				DegradedPathOK: true,
			}, time.Now())
			if decision.Action != "switch" || decision.NextProfile == "" || decision.NextProfile == c.activeProfileID() {
				continue
			}
			debugf(c.cfg, "profile_migration_attempt transport=quic current=%s next=%s reason=%s", decision.CurrentProfile, decision.NextProfile, decision.Reason)
			result := c.scheduler.AttemptProfileMigration(c.ctx, c, decision.CurrentProfile, decision.NextProfile)
			c.scheduler.RecordSwitchResult(decision.CurrentProfile, decision.NextProfile, result.Err == nil, false, time.Now())
			if result.Err != nil {
				debugf(c.cfg, "profile_migration_failed transport=quic current=%s next=%s err=%v", decision.CurrentProfile, decision.NextProfile, result.Err)
				continue
			}
			debugf(c.cfg, "profile_migration_applied transport=quic current=%s next=%s", decision.CurrentProfile, decision.NextProfile)
		}
	}
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
	profileCfg := f.client.currentProfile()
	maxPayload := profileCfg.EffectiveDatagramPayload(f.client.cfg.MaxDgramPayload)
	packets, err := session.FragmentDatagram(f.id, seq, payload, maxPayload)
	if err != nil {
		return err
	}

	for i, pkt := range packets {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := f.client.conn.SendDatagram(pkt); err != nil {
			f.client.observeHealth(health.Sample{At: time.Now(), ProfileID: f.client.activeProfileID(), PathFamily: "quic", BurstDrop: true, TimeoutRate: 1})
			return err
		}
		if sleep := profileBurstPause(profileCfg, i, len(packets)); sleep > 0 {
			timer := time.NewTimer(sleep)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return ctx.Err()
			case <-timer.C:
			}
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

func profileSendGap(p profile.TransportProfile) time.Duration {
	base := p.InterPacketTimingStrategy.BaseGap
	jitter := p.InterPacketTimingStrategy.GapJitter
	if base <= 0 && jitter <= 0 {
		return 0
	}
	if jitter <= 0 {
		return base
	}
	delta := time.Duration(mrand.Int63n(int64(jitter)*2+1)) - jitter
	if base+delta <= 0 {
		return time.Millisecond
	}
	return base + delta
}
