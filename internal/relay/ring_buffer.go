package relay

import "sync"

// RingBuffer is a lock-protected fixed-capacity circular byte buffer.
type RingBuffer struct {
	mu     sync.Mutex
	buf    []byte
	r      int
	w      int
	size   int
	closed bool
}

func NewRingBuffer(capacity int) *RingBuffer {
	if capacity < 1 {
		capacity = 1
	}
	return &RingBuffer{buf: make([]byte, capacity)}
}

func (r *RingBuffer) Cap() int {
	return len(r.buf)
}

func (r *RingBuffer) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.size
}

func (r *RingBuffer) Write(p []byte) (n int, overflow bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed || len(p) == 0 {
		return 0, false
	}

	free := len(r.buf) - r.size
	if free <= 0 {
		return 0, true
	}

	if len(p) > free {
		overflow = true
		p = p[:free]
	}

	n = len(p)
	if n == 0 {
		return 0, overflow
	}

	first := minInt(n, len(r.buf)-r.w)
	copy(r.buf[r.w:r.w+first], p[:first])
	second := n - first
	if second > 0 {
		copy(r.buf[:second], p[first:])
	}

	r.w = (r.w + n) % len(r.buf)
	r.size += n
	return n, overflow
}

func (r *RingBuffer) Read(max int) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if max <= 0 || r.size == 0 {
		return nil, r.closed && r.size == 0
	}

	n := minInt(max, r.size)
	out := make([]byte, n)

	first := minInt(n, len(r.buf)-r.r)
	copy(out[:first], r.buf[r.r:r.r+first])
	second := n - first
	if second > 0 {
		copy(out[first:], r.buf[:second])
	}

	r.r = (r.r + n) % len(r.buf)
	r.size -= n

	eos := r.closed && r.size == 0
	return out, eos
}

func (r *RingBuffer) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
}

func (r *RingBuffer) IsClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
