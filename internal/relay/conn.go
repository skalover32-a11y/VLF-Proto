package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

var ErrConnClosed = errors.New("relay connection closed")

type relayConn struct {
	id       string
	clientID string

	target net.Conn

	downstream *RingBuffer

	upstreamQueue chan []byte
	upstreamBytes atomic.Int64
	sendWindow    int

	idleTimeout time.Duration

	lastActive atomic.Int64
	eos        atomic.Bool
	closed     atomic.Bool

	ctx    context.Context
	cancel context.CancelFunc

	closeOnce sync.Once
	wg        sync.WaitGroup

	logger *zap.Logger

	onClosed func(connID, clientID string)
}

func newRelayConn(
	id string,
	clientID string,
	target net.Conn,
	recvWindow int,
	sendWindow int,
	idleTimeout time.Duration,
	logger *zap.Logger,
	onClosed func(connID, clientID string),
) *relayConn {
	if recvWindow < 1 {
		recvWindow = 1
	}
	if sendWindow < 1 {
		sendWindow = 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	nowMS := time.Now().UnixMilli()

	c := &relayConn{
		id:            id,
		clientID:      clientID,
		target:        target,
		downstream:    NewRingBuffer(recvWindow),
		upstreamQueue: make(chan []byte, 256),
		sendWindow:    sendWindow,
		idleTimeout:   idleTimeout,
		logger:        logger,
		onClosed:      onClosed,
		ctx:           ctx,
		cancel:        cancel,
	}
	c.lastActive.Store(nowMS)
	return c
}

func (c *relayConn) Start() {
	c.wg.Add(2)
	go c.readLoop()
	go c.writeLoop()
}

func (c *relayConn) Enqueue(data []byte) (accepted int, queued int, err error) {
	if len(data) == 0 {
		return 0, int(c.upstreamBytes.Load()), nil
	}
	if c.closed.Load() || c.eos.Load() {
		return 0, int(c.upstreamBytes.Load()), ErrConnClosed
	}

	// Chunk to keep queue responsive under burst traffic.
	const chunk = 4096

	for offset := 0; offset < len(data); {
		if c.closed.Load() || c.eos.Load() {
			break
		}

		end := offset + chunk
		if end > len(data) {
			end = len(data)
		}

		partLen := end - offset
		currentQueued := int(c.upstreamBytes.Load())
		if currentQueued+partLen > c.sendWindow {
			break
		}

		part := make([]byte, partLen)
		copy(part, data[offset:end])

		select {
		case c.upstreamQueue <- part:
			c.upstreamBytes.Add(int64(partLen))
			accepted += partLen
			offset = end
		default:
			offset = len(data)
		}
	}

	queued = int(c.upstreamBytes.Load())
	if accepted == 0 && len(data) > 0 {
		return 0, queued, nil
	}

	c.touch()
	return accepted, queued, nil
}

func (c *relayConn) Recv(max int) ([]byte, bool, error) {
	if c.closed.Load() {
		return nil, true, ErrConnClosed
	}

	data, eos := c.downstream.Read(max)
	if len(data) > 0 {
		c.touch()
	}
	return data, eos, nil
}

func (c *relayConn) Ping() {
	if !c.closed.Load() {
		c.touch()
	}
}

func (c *relayConn) ExpiresInMS() int64 {
	last := time.UnixMilli(c.lastActive.Load())
	remaining := c.idleTimeout - time.Since(last)
	if remaining < 0 {
		return 0
	}
	return remaining.Milliseconds()
}

func (c *relayConn) MarkEOS(reason string) {
	if c.eos.Swap(true) {
		return
	}

	c.logger.Info("relay target reached EOS", zap.String("conn_id", c.id), zap.String("reason", reason))
	c.downstream.Close()
	_ = c.target.Close()
	c.cancel()
}

func (c *relayConn) Close(reason string) {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.eos.Store(true)
		c.logger.Info("closing relay connection", zap.String("conn_id", c.id), zap.String("reason", reason))

		c.cancel()
		_ = c.target.Close()
		c.downstream.Close()
		close(c.upstreamQueue)
		c.wg.Wait()

		if c.onClosed != nil {
			c.onClosed(c.id, c.clientID)
		}
	})
}

func (c *relayConn) readLoop() {
	defer c.wg.Done()

	buf := make([]byte, 32*1024)
	for {
		if c.closed.Load() {
			return
		}

		n, err := c.target.Read(buf)
		if n > 0 {
			c.touch()
			_, overflow := c.downstream.Write(buf[:n])
			if overflow {
				c.Close("downstream_overflow")
				return
			}
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				c.MarkEOS("target_eof")
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			c.MarkEOS("target_read_error")
			return
		}
	}
}

func (c *relayConn) writeLoop() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		case chunk, ok := <-c.upstreamQueue:
			if !ok {
				return
			}
			c.upstreamBytes.Add(-int64(len(chunk)))
			if len(chunk) == 0 {
				continue
			}

			if c.closed.Load() || c.eos.Load() {
				return
			}

			if err := c.target.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
				c.MarkEOS("set_write_deadline")
				return
			}

			_, err := c.target.Write(chunk)
			if err != nil {
				c.MarkEOS("target_write_error")
				return
			}
			_ = c.target.SetWriteDeadline(time.Time{})
			c.touch()
		}
	}
}

func (c *relayConn) touch() {
	c.lastActive.Store(time.Now().UnixMilli())
}
