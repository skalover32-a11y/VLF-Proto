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

// TestQUICDuplicateCloseIsSafe verifies that calling close() multiple times is safe
func TestQUICDuplicateCloseIsSafe(t *testing.T) {
	c := newTestQUICClient(t)

	// First close should succeed
	if err := c.close(); err != nil {
		t.Fatalf("first close() failed: %v", err)
	}

	// Second close should be no-op and not panic
	if err := c.close(); err != nil {
		t.Fatalf("second close() failed: %v", err)
	}

	// Third close for good measure
	if err := c.close(); err != nil {
		t.Fatalf("third close() failed: %v", err)
	}
}

// TestQUICCloseWithActivePending verifies close() releases pending operations
func TestQUICCloseWithActivePending(t *testing.T) {
	c := newTestQUICClient(t)

	// Register pending open
	openCh, err := c.registerPendingOpen(100)
	if err != nil {
		t.Fatalf("registerPendingOpen: %v", err)
	}

	// Register pending ping
	pingCh := make(chan error, 1)
	c.pendingMu.Lock()
	c.pendingPing["test-token"] = pingCh
	c.pendingMu.Unlock()

	// Close should drain pending operations
	if err := c.close(); err != nil {
		t.Fatalf("close() failed: %v", err)
	}

	// Verify pending open was released with error
	select {
	case result := <-openCh:
		if result.err == nil {
			t.Fatal("pending open should have error after close()")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("pending open was not released")
	}

	// Verify pending ping was released with error
	select {
	case err := <-pingCh:
		if err == nil {
			t.Fatal("pending ping should have error after close()")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("pending ping was not released")
	}
}

// TestQUICCloseWithActiveFlows verifies close() cleans up active flows
func TestQUICCloseWithActiveFlows(t *testing.T) {
	c := newTestQUICClient(t)

	// Create active TCP flow
	tcpFlow := &quicTCPFlow{id: 200, client: c}
	c.tcpMu.Lock()
	c.tcpFlows[tcpFlow.id] = tcpFlow
	c.tcpMu.Unlock()

	// Create active UDP flow
	udpFlow := &quicUDPFlow{
		id:       201,
		client:   c,
		incoming: make(chan []byte, 1),
		errCh:    make(chan error, 1),
	}
	c.udpMu.Lock()
	c.udpFlows[udpFlow.id] = udpFlow
	c.udpMu.Unlock()

	// Close should clean up flows
	if err := c.close(); err != nil {
		t.Fatalf("close() failed: %v", err)
	}

	// Verify TCP flow has error
	if tcpFlow.currentErr() == nil {
		t.Fatal("TCP flow should have error after close()")
	}

	// Verify UDP flow has error
	if udpFlow.currentErr() == nil {
		t.Fatal("UDP flow should have error after close()")
	}

	// Verify flows are removed from maps
	c.tcpMu.RLock()
	if len(c.tcpFlows) != 0 {
		t.Fatalf("TCP flows not cleaned: %d remaining", len(c.tcpFlows))
	}
	c.tcpMu.RUnlock()

	c.udpMu.RLock()
	if len(c.udpFlows) != 0 {
		t.Fatalf("UDP flows not cleaned: %d remaining", len(c.udpFlows))
	}
	c.udpMu.RUnlock()
}

// TestQUICControlLoopErrorMarksUnusable verifies control loop errors mark client unusable
func TestQUICControlLoopErrorMarksUnusable(t *testing.T) {
	c := newTestQUICClient(t)

	// Simulate control loop read error using the same reason the production
	// controlLoop uses on any read failure.
	controlErr := errors.New("control stream died")
	if err := c.closeWithError(controlErr, "control_read_error", true); err != nil {
		t.Fatalf("closeWithError failed: %v", err)
	}

	// Verify client is marked unusable
	state, ok := c.unusableState()
	if !ok {
		t.Fatal("client should be marked unusable after control loop error")
	}
	if state.Reason != "control_loop_dead" {
		t.Fatalf("unusable reason = %q, want control_loop_dead", state.Reason)
	}

	// Verify subsequent register attempts fail (post-close guard).
	if _, err := c.registerPendingOpen(999); err == nil {
		t.Fatal("registerPendingOpen should fail on unusable client")
	}
}

// TestQUICConcurrentCloseAndPending verifies concurrent close() and pending operations
func TestQUICConcurrentCloseAndPending(t *testing.T) {
	c := newTestQUICClient(t)

	// Start goroutine that registers pending operations
	done := make(chan bool)
	go func() {
		for i := 0; i < 10; i++ {
			// After close, register returns an error and does not pollute the map.
			_, _ = c.registerPendingOpen(uint64(i))
			time.Sleep(time.Millisecond)
		}
		done <- true
	}()

	// Close concurrently
	time.Sleep(5 * time.Millisecond)
	if err := c.close(); err != nil {
		t.Fatalf("close() failed: %v", err)
	}

	<-done

	// Verify all pending operations are cleaned. After close, register guards
	// reject newcomers and the close drain handled prior entries.
	c.pendingMu.Lock()
	pendingCount := len(c.pendingOpen) + len(c.pendingPing)
	c.pendingMu.Unlock()

	if pendingCount != 0 {
		t.Fatalf("pending operations not cleaned: %d remaining", pendingCount)
	}
}

// TestQUICRegisterAfterCloseRejected verifies that pending registration is
// blocked once the client is closed - prevents goroutine leaks where openers
// race against control_loop teardown.
func TestQUICRegisterAfterCloseRejected(t *testing.T) {
	c := newTestQUICClient(t)
	if err := c.close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := c.registerPendingOpen(1); err == nil {
		t.Fatal("registerPendingOpen after close must fail")
	}
	if _, err := c.registerPendingProfile(); err == nil {
		t.Fatal("registerPendingProfile after close must fail")
	}
}

// TestQUICAuthFailureDoesNotTriggerLegacyFallback verifies that genuine
// AUTH_FAIL with a non-legacy reason is propagated as-is and never causes a
// silent legacy auth retry. This guards AUTHFAIL semantics on the extended
// auth path.
func TestQUICAuthFailureDoesNotTriggerLegacyFallback(t *testing.T) {
	// Plain auth failure reason -> not legacy unsupported.
	if isLegacyAuthUnsupportedReason("bad signature") {
		t.Fatal("plain auth failure must not be treated as legacy-unsupported")
	}
	if isLegacyAuthUnsupportedReason("replay detected") {
		t.Fatal("replay reason must not trigger legacy fallback")
	}
	// Sanity: the only reasons that DO trigger fallback are payload-shape
	// related and explicit.
	if !isLegacyAuthUnsupportedReason("invalid AUTH payload") {
		t.Fatal("invalid AUTH payload must be treated as legacy-unsupported")
	}
	if !isLegacyAuthUnsupportedReason("trailing bytes in AUTH payload") {
		t.Fatal("trailing bytes must be treated as legacy-unsupported")
	}
}

// TestQUICCloseAfterAuthOKDoesNotTriggerLegacyFallback verifies that a clean
// connection close happening AFTER AUTH_OK is treated as a normal session
// teardown (no resurrection of the legacy auth retry path).
func TestQUICCloseAfterAuthOKDoesNotTriggerLegacyFallback(t *testing.T) {
	c := newTestQUICClient(t)
	// Simulate a successful AUTH_OK by storing a lease.
	c.storeAuthLease(session.AuthOKPayload{
		SessionID: 1,
		ExpiresMS: 60000,
	}, time.Now())
	if _, ok := c.leaseState(); !ok {
		t.Fatal("expected lease after AUTH_OK")
	}

	// Now simulate a connection close.
	if err := c.close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Unusable reason must be the normal close reason, not auth_failed.
	state, ok := c.unusableState()
	if !ok {
		t.Fatal("unusable state expected after close")
	}
	if state.Reason == "auth_failed" {
		t.Fatal("close after AUTH_OK must not produce auth_failed reason")
	}
	if state.Reason != "session_closed" {
		t.Fatalf("unusable reason = %q, want session_closed", state.Reason)
	}
}

// TestQUICDoubleCloseWithErrorPreservesFirstError verifies that the first
// non-nil close reason wins; later concurrent failures do not overwrite it.
func TestQUICDoubleCloseWithErrorPreservesFirstError(t *testing.T) {
	c := newTestQUICClient(t)
	first := errors.New("first")
	second := errors.New("second")
	if err := c.closeWithError(first, "control_read_error", true); err != nil {
		t.Fatalf("closeWithError 1: %v", err)
	}
	if err := c.closeWithError(second, "ping_reply_failed", true); err != nil {
		t.Fatalf("closeWithError 2: %v", err)
	}
	if !errors.Is(c.currentCloseErr(), first) {
		t.Fatalf("close err = %v, want first %v", c.currentCloseErr(), first)
	}
	state, ok := c.unusableState()
	if !ok {
		t.Fatal("unusable state expected")
	}
	if state.Reason != "control_loop_dead" {
		t.Fatalf("unusable reason = %q, want control_loop_dead (first wins)", state.Reason)
	}
}

// TestQUICAuthFailDuringRunMarksUnusableAndDrainsPending verifies that an
// AUTHFAIL frame after AUTH_OK (server-side revoke) marks the client
// unusable, releases pending operations, and does not deadlock.
func TestQUICAuthFailDuringRunMarksUnusableAndDrainsPending(t *testing.T) {
	c := newTestQUICClient(t)
	openCh, err := c.registerPendingOpen(42)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	c.handleControlFrame(&session.Frame{
		Type:    session.FrameAUTHFAIL,
		Payload: session.EncodeAuthFail("revoked"),
	})

	select {
	case out := <-openCh:
		if out.err == nil {
			t.Fatal("pending open must surface error after AUTHFAIL")
		}
	case <-time.After(time.Second):
		t.Fatal("pending open not released after AUTHFAIL")
	}

	state, ok := c.unusableState()
	if !ok {
		t.Fatal("unusable state expected after AUTHFAIL during run")
	}
	if state.Reason != "auth_failed" {
		t.Fatalf("unusable reason = %q, want auth_failed", state.Reason)
	}
}

// TestQUICContextCancelOnClose verifies context is cancelled on close()
func TestQUICContextCancelOnClose(t *testing.T) {
	c := newTestQUICClient(t)

	// Verify context is not cancelled initially
	select {
	case <-c.ctx.Done():
		t.Fatal("context should not be cancelled initially")
	default:
	}

	// Close should cancel context
	if err := c.close(); err != nil {
		t.Fatalf("close() failed: %v", err)
	}

	// Verify context is cancelled
	select {
	case <-c.ctx.Done():
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Fatal("context was not cancelled after close()")
	}
}
