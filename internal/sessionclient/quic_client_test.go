package sessionclient

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"vlf-runtime/internal/session"
)

func newTestQUICClient(t *testing.T) *quicClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	return &quicClient{
		cfg:         Config{},
		ctx:         ctx,
		cancel:      cancel,
		tcpFlows:    make(map[uint64]*quicTCPFlow),
		udpFlows:    make(map[uint64]*quicUDPFlow),
		pendingOpen: make(map[uint64]chan quicOpenResult),
		pendingPing: make(map[string]chan error),
	}
}

func TestQUICHandleControlFrameResolvesPendingOpenOK(t *testing.T) {
	c := newTestQUICClient(t)

	respCh, err := c.registerPendingOpen(42)
	if err != nil {
		t.Fatalf("registerPendingOpen: %v", err)
	}

	c.handleControlFrame(&session.Frame{
		Type:    session.FrameOPENTCPOK,
		Payload: session.EncodeOpenOKPayload(session.OpenOKPayload{FlowID: 42, Mode: 1}),
	})

	select {
	case out, ok := <-respCh:
		if !ok {
			t.Fatal("pending open channel closed without result")
		}
		if !out.ok || out.err != nil {
			t.Fatalf("unexpected open result: %+v", out)
		}
	default:
		t.Fatal("pending open result not delivered")
	}
}

func TestQUICHandleControlFrameResolvesPendingOpenFail(t *testing.T) {
	c := newTestQUICClient(t)

	respCh, err := c.registerPendingOpen(7)
	if err != nil {
		t.Fatalf("registerPendingOpen: %v", err)
	}

	c.handleControlFrame(&session.Frame{
		Type:    session.FrameOPENUDPFAIL,
		Payload: session.EncodeFailPayload(session.FailPayload{FlowID: 7, Reason: "udp blocked"}),
	})

	select {
	case out, ok := <-respCh:
		if !ok {
			t.Fatal("pending open fail channel closed without result")
		}
		if out.ok {
			t.Fatal("open fail unexpectedly returned ok")
		}
		if out.err == nil || out.err.Error() != "udp blocked" {
			t.Fatalf("unexpected fail result: %+v", out)
		}
	default:
		t.Fatal("pending open fail result not delivered")
	}
}

func TestQUICHandleControlFrameResolvesPendingPing(t *testing.T) {
	c := newTestQUICClient(t)
	token := []byte("ping-token-01")
	waitCh := make(chan error, 1)

	c.pendingMu.Lock()
	c.pendingPing[string(token)] = waitCh
	c.pendingMu.Unlock()

	c.handleControlFrame(&session.Frame{
		Type:    session.FramePONG,
		Payload: token,
	})

	select {
	case err := <-waitCh:
		if err != nil {
			t.Fatalf("unexpected ping error: %v", err)
		}
	default:
		t.Fatal("pending ping was not resolved")
	}
}

func TestQUICHandleControlFrameCloseFlowClosesUDPFlow(t *testing.T) {
	c := newTestQUICClient(t)
	flow := &quicUDPFlow{
		id:       11,
		client:   c,
		incoming: make(chan []byte, 1),
		errCh:    make(chan error, 1),
	}

	c.udpMu.Lock()
	c.udpFlows[flow.id] = flow
	c.udpMu.Unlock()

	c.handleControlFrame(&session.Frame{
		Type:    session.FrameCLOSEFLOW,
		Payload: session.EncodeCloseFlowPayload(session.CloseFlowPayload{FlowID: flow.id}),
	})

	c.udpMu.RLock()
	_, exists := c.udpFlows[flow.id]
	c.udpMu.RUnlock()
	if exists {
		t.Fatal("udp flow still registered after CLOSEFLOW")
	}

	select {
	case _, ok := <-flow.incoming:
		if ok {
			t.Fatal("udp flow incoming channel should be closed")
		}
	default:
		t.Fatal("udp flow incoming channel was not closed")
	}
}

func TestQUICHandleControlFrameCloseFlowClosesEarlyUDPPlaceholder(t *testing.T) {
	c := newTestQUICClient(t)
	flow := &quicUDPFlow{
		id:       12,
		client:   c,
		incoming: make(chan []byte, 1),
		errCh:    make(chan error, 1),
	}

	c.udpMu.Lock()
	c.udpFlows[flow.id] = flow
	c.udpMu.Unlock()

	c.handleControlFrame(&session.Frame{
		Type:    session.FrameCLOSEFLOW,
		Payload: session.EncodeCloseFlowPayload(session.CloseFlowPayload{FlowID: flow.id}),
	})

	if !errors.Is(flow.currentErr(), io.EOF) {
		t.Fatalf("udp placeholder close err = %v, want EOF", flow.currentErr())
	}
	if flow.isMaterialized() {
		t.Fatal("early-closed udp placeholder must remain non-materialized")
	}
}

func TestQUICHandleControlFrameCloseFlowClosesTCPFlow(t *testing.T) {
	c := newTestQUICClient(t)
	flow := &quicTCPFlow{id: 19, client: c}

	c.tcpMu.Lock()
	c.tcpFlows[flow.id] = flow
	c.tcpMu.Unlock()

	c.handleControlFrame(&session.Frame{
		Type:    session.FrameCLOSEFLOW,
		Payload: session.EncodeCloseFlowPayload(session.CloseFlowPayload{FlowID: flow.id}),
	})

	c.tcpMu.RLock()
	_, exists := c.tcpFlows[flow.id]
	c.tcpMu.RUnlock()
	if exists {
		t.Fatal("tcp flow still registered after CLOSEFLOW")
	}
	if !errors.Is(flow.currentErr(), io.EOF) {
		t.Fatalf("tcp flow close err = %v, want EOF", flow.currentErr())
	}
}

func TestQUICCloseWithErrorDrainsPendingAndFlows(t *testing.T) {
	c := newTestQUICClient(t)

	openCh, err := c.registerPendingOpen(5)
	if err != nil {
		t.Fatalf("registerPendingOpen: %v", err)
	}
	pingCh := make(chan error, 1)
	c.pendingMu.Lock()
	c.pendingPing["tok"] = pingCh
	c.pendingMu.Unlock()

	udpFlow := &quicUDPFlow{
		id:       29,
		client:   c,
		incoming: make(chan []byte, 1),
		errCh:    make(chan error, 1),
	}
	c.udpMu.Lock()
	c.udpFlows[udpFlow.id] = udpFlow
	c.udpMu.Unlock()

	wantErr := errors.New("boom")
	if err := c.closeWithError(wantErr, "test_close", true); err != nil {
		t.Fatalf("closeWithError returned unexpected err: %v", err)
	}

	select {
	case out := <-openCh:
		if out.err == nil || out.err.Error() != wantErr.Error() {
			t.Fatalf("open pending err = %v, want %v", out.err, wantErr)
		}
	default:
		t.Fatal("open pending channel was not drained")
	}

	select {
	case err := <-pingCh:
		if err == nil || err.Error() != wantErr.Error() {
			t.Fatalf("ping pending err = %v, want %v", err, wantErr)
		}
	default:
		t.Fatal("ping pending channel was not drained")
	}

	if !errors.Is(c.currentCloseErr(), wantErr) {
		t.Fatalf("client close err = %v, want %v", c.currentCloseErr(), wantErr)
	}
}

func TestQUICStoreAuthLease(t *testing.T) {
	c := newTestQUICClient(t)
	now := time.Unix(1700000000, 0).UTC()

	c.storeAuthLease(session.AuthOKPayload{
		SessionID: 77,
		ExpiresMS: 45000,
		UpKbps:    1000,
		DownKbps:  2000,
		MaxFlows:  8,
		MaxUDPPPS: 900,
	}, now)

	lease, ok := c.leaseState()
	if !ok {
		t.Fatal("leaseState returned no lease")
	}
	if lease.SessionID != 77 {
		t.Fatalf("lease session_id = %d, want 77", lease.SessionID)
	}
	if lease.IssuedAt != now {
		t.Fatalf("lease issued_at = %v, want %v", lease.IssuedAt, now)
	}
	if lease.LastActivityAt != now {
		t.Fatalf("lease last_activity = %v, want %v", lease.LastActivityAt, now)
	}
	if lease.TTL != 45*time.Second {
		t.Fatalf("lease ttl = %s, want 45s", lease.TTL)
	}
	if lease.ExpiresAt != now.Add(45*time.Second) {
		t.Fatalf("lease expires_at = %v, want %v", lease.ExpiresAt, now.Add(45*time.Second))
	}
}

func TestQUICCloseWithErrorSetsUnusableReason(t *testing.T) {
	c := newTestQUICClient(t)

	if err := c.closeWithError(errors.New("control dead"), "control_read_error", true); err != nil {
		t.Fatalf("closeWithError returned unexpected err: %v", err)
	}

	state, ok := c.unusableState()
	if !ok {
		t.Fatal("unusable state not recorded")
	}
	if state.Reason != "control_loop_dead" {
		t.Fatalf("unusable reason = %q, want control_loop_dead", state.Reason)
	}
	if state.Since.IsZero() {
		t.Fatal("unusable since must be set")
	}
}
