package iobased

import (
	"context"
	"errors"
	"io"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	defaultOutQueueLen = 1 << 10
)

type Endpoint struct {
	*channel.Endpoint

	rw     io.ReadWriter
	mtu    uint32
	offset int

	once sync.Once
	wg   sync.WaitGroup
}

func New(rw io.ReadWriter, mtu uint32, offset int) (*Endpoint, error) {
	if rw == nil {
		return nil, errors.New("rw is nil")
	}
	if mtu == 0 {
		return nil, errors.New("mtu must be non-zero")
	}
	if offset < 0 {
		return nil, errors.New("offset must be non-negative")
	}

	return &Endpoint{
		Endpoint: channel.New(defaultOutQueueLen, mtu, ""),
		rw:       rw,
		mtu:      mtu,
		offset:   offset,
	}, nil
}

func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.Endpoint.Attach(dispatcher)
	e.once.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())

		e.wg.Add(2)
		go func() {
			defer e.wg.Done()
			e.outboundLoop(ctx)
		}()
		go func() {
			defer e.wg.Done()
			e.dispatchLoop(cancel)
		}()
	})
}

func (e *Endpoint) Wait() {
	e.wg.Wait()
}

func (e *Endpoint) dispatchLoop(cancel context.CancelFunc) {
	defer cancel()

	offset := e.offset
	mtu := int(e.mtu)
	for {
		buf := make([]byte, offset+mtu)
		n, err := e.rw.Read(buf)
		if err != nil {
			return
		}
		if n <= 0 || n > mtu {
			continue
		}
		if !e.IsAttached() {
			continue
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(buf[offset : offset+n]),
		})

		switch header.IPVersion(buf[offset:]) {
		case header.IPv4Version:
			e.InjectInbound(header.IPv4ProtocolNumber, pkt)
		case header.IPv6Version:
			e.InjectInbound(header.IPv6ProtocolNumber, pkt)
		}
		pkt.DecRef()
	}
}

func (e *Endpoint) outboundLoop(ctx context.Context) {
	for {
		pkt := e.ReadContext(ctx)
		if pkt == nil {
			return
		}
		_ = e.writePacket(pkt)
	}
}

func (e *Endpoint) writePacket(pkt *stack.PacketBuffer) tcpip.Error {
	defer pkt.DecRef()

	buf := pkt.ToBuffer()
	defer buf.Release()

	if e.offset > 0 {
		prefix := buffer.NewViewWithData(make([]byte, e.offset))
		_ = buf.Prepend(prefix)
	}

	if _, err := e.rw.Write(buf.Flatten()); err != nil {
		return &tcpip.ErrInvalidEndpointState{}
	}
	return nil
}
