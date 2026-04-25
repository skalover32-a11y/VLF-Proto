package sessionclient

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// newTestTCPSessionClient builds a tcpSessionClient with a no-op net.Pipe
// connection so lifecycle paths can be exercised without a real TLS server.
func newTestTCPSessionClient(t *testing.T) (*tcpSessionClient, net.Conn) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	c := &tcpSessionClient{
		cfg:         Config{},
		conn:        clientConn,
		reader:      bufio.NewReader(clientConn),
		ctx:         ctx,
		cancel:      cancel,
		flows:       make(map[uint64]*tcpFramedFlow),
		pendingTCP:  make(map[uint64]chan openResult),
		pendingUDP:  make(map[uint64]chan openResult),
		pendingPing: make(map[string]chan error),
	}
	t.Cleanup(func() {
		_ = serverConn.Close()
	})
	return c, serverConn
}

func TestTCPSessionDuplicateCloseIsSafe(t *testing.T) {
	c, _ := newTestTCPSessionClient(t)
	if err := c.close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := c.close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if err := c.close(); err != nil {
		t.Fatalf("third close: %v", err)
	}
}

func TestTCPSessionCloseCancelsContextAndDrainsPending(t *testing.T) {
	c, _ := newTestTCPSessionClient(t)

	openCh := make(chan openResult, 1)
	c.pendingMu.Lock()
	c.pendingTCP[1] = openCh
	c.pendingMu.Unlock()

	pingCh := make(chan error, 1)
	c.pendingMu.Lock()
	c.pendingPing["tok"] = pingCh
	c.pendingMu.Unlock()

	flow := &tcpFramedFlow{
		id:     5,
		parent: c,
		dataCh: make(chan []byte, 1),
		errCh:  make(chan error, 1),
	}
	c.flowMu.Lock()
	c.flows[flow.id] = flow
	c.flowMu.Unlock()

	if err := c.close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case <-c.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("ctx not cancelled after close")
	}

	select {
	case out := <-openCh:
		if out.err == nil {
			t.Fatal("pending TCP open must have error after close")
		}
	case <-time.After(time.Second):
		t.Fatal("pending TCP open not released")
	}

	select {
	case err := <-pingCh:
		if err == nil {
			t.Fatal("pending ping must have error after close")
		}
	case <-time.After(time.Second):
		t.Fatal("pending ping not released")
	}

	select {
	case err := <-flow.errCh:
		if err == nil {
			t.Fatal("flow err channel must contain non-nil error")
		}
	case <-time.After(time.Second):
		t.Fatal("flow not notified of close error")
	}
}

func TestTCPSessionRegisterAfterCloseRejected(t *testing.T) {
	c, _ := newTestTCPSessionClient(t)
	if err := c.close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := c.openTCPFlow(context.Background(), 1, "h", 1); err == nil {
		t.Fatal("openTCPFlow after close must fail")
	}
	if _, err := c.openUDPFlow(context.Background(), 2, "h", 1); err == nil {
		t.Fatal("openUDPFlow after close must fail")
	}
	if _, err := c.registerPendingProfile(); err == nil {
		t.Fatal("registerPendingProfile after close must fail")
	}
	if err := c.writeFrame(1, nil); err == nil {
		t.Fatal("writeFrame after close must fail")
	}
}

func TestTCPSessionConcurrentCloseAndPending(t *testing.T) {
	c, _ := newTestTCPSessionClient(t)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			_, _ = c.openTCPFlow(context.Background(), uint64(i), "h", 1)
			time.Sleep(time.Millisecond)
		}
	}()

	time.Sleep(3 * time.Millisecond)
	if err := c.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	wg.Wait()

	c.pendingMu.Lock()
	pending := len(c.pendingTCP) + len(c.pendingUDP) + len(c.pendingPing)
	c.pendingMu.Unlock()
	if pending != 0 {
		t.Fatalf("pending count = %d, want 0", pending)
	}
}

func TestTCPSessionUnusableReasonClassifies(t *testing.T) {
	if got := tcpSessionUnusableReason(io.EOF, nil); got != "session_closed" {
		t.Fatalf("EOF reason = %q, want session_closed", got)
	}
	if got := tcpSessionUnusableReason(net.ErrClosed, nil); got != "session_closed" {
		t.Fatalf("ErrClosed reason = %q, want session_closed", got)
	}
	if got := tcpSessionUnusableReason(context.Canceled, nil); got != "session_closed" {
		t.Fatalf("Canceled reason = %q, want session_closed", got)
	}
	if got := tcpSessionUnusableReason(errors.New("frame parse error"), nil); got != "control_loop_dead" {
		t.Fatalf("generic err reason = %q, want control_loop_dead", got)
	}
}

func TestTCPSessionDoubleCloseWithErrorPreservesFirst(t *testing.T) {
	c, _ := newTestTCPSessionClient(t)
	first := errors.New("first")
	second := errors.New("second")
	c.closeWithError(first, "control_loop_dead")
	c.closeWithError(second, "session_closed")
	if !errors.Is(c.currentCloseErr(), first) {
		t.Fatalf("close err = %v, want first", c.currentCloseErr())
	}
	state, ok := c.unusableState()
	if !ok {
		t.Fatal("unusable state expected")
	}
	if state.Reason != "control_loop_dead" {
		t.Fatalf("unusable reason = %q, want control_loop_dead", state.Reason)
	}
}
