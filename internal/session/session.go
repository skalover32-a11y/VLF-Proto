package session

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"vlf-runtime/internal/limits"
)

type tcpFlow struct {
	id        uint64
	target    net.Conn
	streamMu  sync.Mutex
	stream    *quic.Stream
	closeOnce sync.Once
}

type udpFlow struct {
	id        uint64
	conn      *net.UDPConn
	seq       atomic.Uint32
	closeOnce sync.Once
}

type Session struct {
	id     uint64
	conn   *quic.Conn
	server *Server
	logger *zap.Logger

	ctx    context.Context
	cancel context.CancelFunc

	closeOnce sync.Once

	clientID string
	authed   bool

	control   *quic.Stream
	controlR  *bufio.Reader
	controlMu sync.Mutex

	wg sync.WaitGroup

	reassembly *Reassembly

	flowsMu  sync.RWMutex
	tcpFlows map[uint64]*tcpFlow
	udpFlows map[uint64]*udpFlow
}

func newSession(id uint64, conn *quic.Conn, server *Server, logger *zap.Logger) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	return &Session{
		id:         id,
		conn:       conn,
		server:     server,
		logger:     logger,
		ctx:        ctx,
		cancel:     cancel,
		reassembly: NewReassembly(),
		tcpFlows:   make(map[uint64]*tcpFlow),
		udpFlows:   make(map[uint64]*udpFlow),
	}
}

func (s *Session) Run() error {
	defer s.Close("run_exit")

	ctrlCtx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
	defer cancel()

	stream, err := s.conn.AcceptStream(ctrlCtx)
	if err != nil {
		return fmt.Errorf("accept control stream: %w", err)
	}

	s.control = stream
	s.controlR = bufio.NewReader(stream)

	first, err := ReadFrame(s.controlR)
	if err != nil {
		return fmt.Errorf("read first frame: %w", err)
	}
	if first.Type != FrameAUTH {
		_ = s.writeFrame(FrameAUTHFAIL, EncodeAuthFail("first frame must be AUTH"))
		return errors.New("first frame is not AUTH")
	}

	authPayload, err := DecodeAuthPayload(first.Payload)
	if err != nil {
		_ = s.writeFrame(FrameAUTHFAIL, EncodeAuthFail("invalid AUTH payload"))
		return fmt.Errorf("decode AUTH payload: %w", err)
	}

	if err := s.server.verifier.VerifySession(authPayload.ClientID, authPayload.TSMS, authPayload.Nonce, authPayload.Sig, authPayload.Caps); err != nil {
		_ = s.writeFrame(FrameAUTHFAIL, EncodeAuthFail("AUTH verification failed"))
		return fmt.Errorf("verify AUTH: %w", err)
	}

	s.clientID = authPayload.ClientID
	s.authed = true

	s.server.registerSession(s)
	defer s.server.unregisterSession(s.id)

	if err := s.writeFrame(FrameAUTHOK, EncodeAuthOKPayload(AuthOKPayload{
		SessionID: s.id,
		ExpiresMS: uint32(s.server.cfg.IdleTimeout.Milliseconds()),
		UpKbps:    uint32(s.server.cfg.UpKbps),
		DownKbps:  uint32(s.server.cfg.DownKbps),
		MaxFlows:  uint32(s.server.cfg.MaxFlows),
		MaxUDPPPS: uint32(s.server.cfg.MaxUDPPPS),
	})); err != nil {
		return fmt.Errorf("write AUTH_OK: %w", err)
	}

	s.touch()
	s.logger.Info("session authenticated", zap.String("client_id", s.clientID))

	s.wg.Add(4)
	go s.controlLoop()
	go s.acceptFlowStreams()
	go s.datagramLoop()
	go s.pingLoop()

	<-s.ctx.Done()
	s.wg.Wait()
	return nil
}

func (s *Session) Close(reason string) {
	s.closeOnce.Do(func() {
		s.logger.Info("closing session", zap.String("reason", reason))
		s.cancel()

		_ = s.conn.CloseWithError(0, reason)

		if s.control != nil {
			_ = s.control.Close()
		}

		s.flowsMu.Lock()
		tcp := make([]*tcpFlow, 0, len(s.tcpFlows))
		for _, f := range s.tcpFlows {
			tcp = append(tcp, f)
		}
		udp := make([]*udpFlow, 0, len(s.udpFlows))
		for _, f := range s.udpFlows {
			udp = append(udp, f)
		}
		s.tcpFlows = make(map[uint64]*tcpFlow)
		s.udpFlows = make(map[uint64]*udpFlow)
		s.flowsMu.Unlock()

		for _, f := range tcp {
			f.closeOnce.Do(func() {
				_ = f.target.Close()
				f.streamMu.Lock()
				if f.stream != nil {
					_ = f.stream.Close()
				}
				f.streamMu.Unlock()
			})
		}
		for _, f := range udp {
			f.closeOnce.Do(func() {
				_ = f.conn.Close()
			})
		}
	})
}

func (s *Session) controlLoop() {
	defer s.wg.Done()

	for {
		frame, err := ReadFrame(s.controlR)
		if err != nil {
			if s.ctx.Err() == nil {
				if isExpectedSessionCloseErr(err) {
					s.logger.Debug("control stream closed", zap.Error(err))
				} else {
					s.logger.Warn("control stream read failed", zap.Error(err))
				}
			}
			s.Close("control_read_end")
			return
		}

		s.touch()

		switch frame.Type {
		case FramePING:
			_ = s.writeFrame(FramePONG, frame.Payload)
		case FramePONG:
			// Keepalive response.
		case FrameOPENTCP:
			payload, err := DecodeOpenPayload(frame.Payload)
			if err != nil {
				_ = s.writeFrame(FrameOPENTCPFAIL, EncodeFailPayload(FailPayload{FlowID: 0, Reason: "invalid OPEN_TCP payload"}))
				continue
			}
			s.handleOpenTCP(payload)
		case FrameOPENUDP:
			payload, err := DecodeOpenPayload(frame.Payload)
			if err != nil {
				_ = s.writeFrame(FrameOPENUDPFAIL, EncodeFailPayload(FailPayload{FlowID: 0, Reason: "invalid OPEN_UDP payload"}))
				continue
			}
			s.handleOpenUDP(payload)
		case FrameCLOSEFLOW:
			payload, err := DecodeCloseFlowPayload(frame.Payload)
			if err != nil {
				continue
			}
			s.closeFlow(payload.FlowID, "client_close_flow", false)
		default:
			s.logger.Warn("unknown control frame", zap.Uint64("type", frame.Type))
		}
	}
}

func (s *Session) acceptFlowStreams() {
	defer s.wg.Done()

	for {
		stream, err := s.conn.AcceptStream(s.ctx)
		if err != nil {
			if s.ctx.Err() == nil {
				if isExpectedSessionCloseErr(err) {
					s.logger.Debug("accept flow stream closed", zap.Error(err))
					s.Close("accept_flow_stream_end")
				} else {
					s.logger.Warn("accept flow stream failed", zap.Error(err))
					s.Close("accept_flow_stream_error")
				}
			}
			return
		}

		s.wg.Add(1)
		go s.handleFlowStream(stream)
	}
}

func (s *Session) handleFlowStream(stream *quic.Stream) {
	defer s.wg.Done()

	var flowRaw [8]byte
	if _, err := io.ReadFull(stream, flowRaw[:]); err != nil {
		_ = stream.Close()
		return
	}
	flowID := binary.BigEndian.Uint64(flowRaw[:])

	s.flowsMu.RLock()
	flow, ok := s.tcpFlows[flowID]
	s.flowsMu.RUnlock()
	if !ok {
		_ = stream.Close()
		return
	}

	flow.streamMu.Lock()
	if flow.stream != nil {
		flow.streamMu.Unlock()
		_ = stream.Close()
		return
	}
	flow.stream = stream
	flow.streamMu.Unlock()

	s.metricsTCPStreamInc()
	defer s.metricsTCPStreamDec()

	s.pumpTCPFlow(flow)
}

func (s *Session) pumpTCPFlow(flow *tcpFlow) {
	errCh := make(chan error, 2)

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := flow.stream.Read(buf)
			if n > 0 {
				if limitErr := s.server.limits.AllowSessionBytes(s.id, n); limitErr != nil {
					errCh <- limitErr
					return
				}
				if _, writeErr := flow.target.Write(buf[:n]); writeErr != nil {
					errCh <- writeErr
					return
				}
				s.server.metrics.BytesIn.WithLabelValues("session").Add(float64(n))
				s.touch()
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					errCh <- nil
					return
				}
				errCh <- err
				return
			}
		}
	}()

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := flow.target.Read(buf)
			if n > 0 {
				if limitErr := s.server.limits.AllowSessionBytes(s.id, n); limitErr != nil {
					errCh <- limitErr
					return
				}
				if _, writeErr := flow.stream.Write(buf[:n]); writeErr != nil {
					errCh <- writeErr
					return
				}
				s.server.metrics.BytesOut.WithLabelValues("session").Add(float64(n))
				s.touch()
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					errCh <- nil
					return
				}
				errCh <- err
				return
			}
		}
	}()

	if err := <-errCh; err != nil {
		if s.ctx.Err() == nil {
			if isExpectedSessionCloseErr(err) {
				s.logger.Debug("tcp flow pump ended", zap.Uint64("flow_id", flow.id), zap.Error(err))
			} else {
				s.logger.Warn("tcp flow pump ended with error", zap.Uint64("flow_id", flow.id), zap.Error(err))
			}
		}
		if errors.Is(err, limits.ErrMaxBytesPerMinuteSess) {
			s.Close("session_bytes_limit")
			return
		}
	}

	s.closeFlow(flow.id, "tcp_flow_end", true)
}

func (s *Session) datagramLoop() {
	defer s.wg.Done()

	for {
		raw, err := s.conn.ReceiveDatagram(s.ctx)
		if err != nil {
			if s.ctx.Err() == nil {
				if isExpectedSessionCloseErr(err) {
					s.logger.Debug("receive datagram loop closed", zap.Error(err))
				} else {
					s.logger.Warn("receive datagram failed", zap.Error(err))
				}
			}
			return
		}

		pkt, err := DecodeDatagramPacket(raw)
		if err != nil {
			continue
		}

		s.touch()

		if err := s.server.limits.AllowUDPPacket(s.id); err != nil {
			continue
		}

		payload, done := s.reassembly.Add(pkt)
		if !done {
			continue
		}

		if err := s.server.limits.AllowSessionBytes(s.id, len(payload)); err != nil {
			s.Close("session_bytes_limit")
			return
		}

		s.flowsMu.RLock()
		flow := s.udpFlows[pkt.FlowID]
		s.flowsMu.RUnlock()
		if flow == nil {
			continue
		}

		if _, err := flow.conn.Write(payload); err != nil {
			s.closeFlow(pkt.FlowID, "udp_write_failed", true)
			continue
		}

		s.server.metrics.BytesIn.WithLabelValues("session").Add(float64(len(payload)))
		s.server.metrics.ObserveUDPPacket()
	}
}

func (s *Session) pingLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(12 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			_ = s.writeFrame(FramePING, nil)
		}
	}
}

func (s *Session) handleOpenTCP(p OpenPayload) {
	if p.FlowID == 0 {
		_ = s.writeFrame(FrameOPENTCPFAIL, EncodeFailPayload(FailPayload{FlowID: p.FlowID, Reason: "flow_id must be non-zero"}))
		return
	}

	if s.flowCount() >= s.server.cfg.MaxFlows {
		_ = s.writeFrame(FrameOPENTCPFAIL, EncodeFailPayload(FailPayload{FlowID: p.FlowID, Reason: "max_flows_per_session exceeded"}))
		return
	}

	addr, err := resolveTargetAddress(p)
	if err != nil {
		_ = s.writeFrame(FrameOPENTCPFAIL, EncodeFailPayload(FailPayload{FlowID: p.FlowID, Reason: err.Error()}))
		return
	}

	d := net.Dialer{Timeout: s.server.cfg.DialTimeout}
	target, err := d.DialContext(s.ctx, "tcp", addr)
	if err != nil {
		s.server.metrics.OpenFailures.WithLabelValues("session", "tcp_dial").Inc()
		_ = s.writeFrame(FrameOPENTCPFAIL, EncodeFailPayload(FailPayload{FlowID: p.FlowID, Reason: err.Error()}))
		return
	}

	flow := &tcpFlow{id: p.FlowID, target: target}

	s.flowsMu.Lock()
	if _, exists := s.tcpFlows[p.FlowID]; exists {
		s.flowsMu.Unlock()
		_ = target.Close()
		_ = s.writeFrame(FrameOPENTCPFAIL, EncodeFailPayload(FailPayload{FlowID: p.FlowID, Reason: "flow_id already exists"}))
		return
	}
	s.tcpFlows[p.FlowID] = flow
	s.flowsMu.Unlock()

	if err := s.writeFrame(FrameOPENTCPOK, EncodeOpenOKPayload(OpenOKPayload{FlowID: p.FlowID, Mode: 1})); err != nil {
		s.closeFlow(p.FlowID, "open_tcp_ok_write_failed", false)
		return
	}

	s.logger.Info("opened TCP flow", zap.Uint64("flow_id", p.FlowID), zap.String("dst", addr))
}

func (s *Session) handleOpenUDP(p OpenPayload) {
	if p.FlowID == 0 {
		_ = s.writeFrame(FrameOPENUDPFAIL, EncodeFailPayload(FailPayload{FlowID: p.FlowID, Reason: "flow_id must be non-zero"}))
		return
	}

	if s.flowCount() >= s.server.cfg.MaxFlows {
		_ = s.writeFrame(FrameOPENUDPFAIL, EncodeFailPayload(FailPayload{FlowID: p.FlowID, Reason: "max_flows_per_session exceeded"}))
		return
	}

	addr, err := resolveTargetAddress(p)
	if err != nil {
		_ = s.writeFrame(FrameOPENUDPFAIL, EncodeFailPayload(FailPayload{FlowID: p.FlowID, Reason: err.Error()}))
		return
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		s.server.metrics.OpenFailures.WithLabelValues("session", "udp_resolve").Inc()
		_ = s.writeFrame(FrameOPENUDPFAIL, EncodeFailPayload(FailPayload{FlowID: p.FlowID, Reason: err.Error()}))
		return
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		s.server.metrics.OpenFailures.WithLabelValues("session", "udp_dial").Inc()
		_ = s.writeFrame(FrameOPENUDPFAIL, EncodeFailPayload(FailPayload{FlowID: p.FlowID, Reason: err.Error()}))
		return
	}

	flow := &udpFlow{id: p.FlowID, conn: conn}

	s.flowsMu.Lock()
	if _, exists := s.udpFlows[p.FlowID]; exists {
		s.flowsMu.Unlock()
		_ = conn.Close()
		_ = s.writeFrame(FrameOPENUDPFAIL, EncodeFailPayload(FailPayload{FlowID: p.FlowID, Reason: "flow_id already exists"}))
		return
	}
	s.udpFlows[p.FlowID] = flow
	s.flowsMu.Unlock()

	if err := s.writeFrame(FrameOPENUDPOK, EncodeOpenOKPayload(OpenOKPayload{FlowID: p.FlowID, Mode: 0})); err != nil {
		s.closeFlow(p.FlowID, "open_udp_ok_write_failed", false)
		return
	}

	s.wg.Add(1)
	go s.udpReadLoop(flow)

	s.logger.Info("opened UDP flow", zap.Uint64("flow_id", p.FlowID), zap.String("dst", addr))
}

func (s *Session) udpReadLoop(flow *udpFlow) {
	defer s.wg.Done()

	buf := make([]byte, 64*1024)
	for {
		n, err := flow.conn.Read(buf)
		if n > 0 {
			payload := make([]byte, n)
			copy(payload, buf[:n])

			if err := s.server.limits.AllowSessionBytes(s.id, len(payload)); err != nil {
				s.Close("session_bytes_limit")
				return
			}

			seq := flow.seq.Add(1)
			packets, fragErr := FragmentDatagram(flow.id, seq, payload, s.server.cfg.MaxDgramPayload)
			if fragErr != nil {
				s.closeFlow(flow.id, "udp_fragmentation_error", true)
				return
			}

			for _, pkt := range packets {
				if sendErr := s.conn.SendDatagram(pkt); sendErr != nil {
					s.closeFlow(flow.id, "udp_send_datagram_failed", true)
					return
				}
				s.server.metrics.ObserveUDPPacket()
			}

			s.server.metrics.BytesOut.WithLabelValues("session").Add(float64(len(payload)))
			s.touch()
		}

		if err != nil {
			if s.ctx.Err() == nil {
				s.closeFlow(flow.id, "udp_target_read_end", true)
			}
			return
		}
	}
}

func (s *Session) closeFlow(flowID uint64, reason string, notify bool) {
	var tcp *tcpFlow
	var udp *udpFlow

	s.flowsMu.Lock()
	if f, ok := s.tcpFlows[flowID]; ok {
		tcp = f
		delete(s.tcpFlows, flowID)
	}
	if f, ok := s.udpFlows[flowID]; ok {
		udp = f
		delete(s.udpFlows, flowID)
	}
	s.flowsMu.Unlock()

	if tcp == nil && udp == nil {
		return
	}

	if tcp != nil {
		tcp.closeOnce.Do(func() {
			_ = tcp.target.Close()
			tcp.streamMu.Lock()
			if tcp.stream != nil {
				_ = tcp.stream.Close()
			}
			tcp.streamMu.Unlock()
		})
	}
	if udp != nil {
		udp.closeOnce.Do(func() {
			_ = udp.conn.Close()
		})
	}

	s.logger.Info("closed flow", zap.Uint64("flow_id", flowID), zap.String("reason", reason))

	if notify {
		_ = s.writeFrame(FrameCLOSEFLOW, EncodeCloseFlowPayload(CloseFlowPayload{FlowID: flowID}))
	}
}

func (s *Session) flowCount() int {
	s.flowsMu.RLock()
	defer s.flowsMu.RUnlock()
	return len(s.tcpFlows) + len(s.udpFlows)
}

func (s *Session) touch() {
	s.server.touchSession(s.id)
}

func (s *Session) writeFrame(frameType uint64, payload []byte) error {
	if s.control == nil {
		return errors.New("control stream not initialized")
	}

	s.controlMu.Lock()
	defer s.controlMu.Unlock()

	return WriteFrame(s.control, frameType, payload)
}

func (s *Session) metricsTCPStreamInc() {
	s.server.metrics.TCPStreams.Inc()
}

func (s *Session) metricsTCPStreamDec() {
	s.server.metrics.TCPStreams.Dec()
}

func resolveTargetAddress(p OpenPayload) (string, error) {
	if p.DstPort == 0 {
		return "", errors.New("dst_port must be non-zero")
	}

	host := p.DstHost
	if host == "" {
		if len(p.DstIP) == 0 {
			return "", errors.New("either dst_host or dst_ip must be set")
		}
		ip := net.IP(p.DstIP)
		if ip == nil {
			return "", errors.New("invalid dst_ip")
		}
		host = ip.String()
	}

	return net.JoinHostPort(host, fmt.Sprintf("%d", p.DstPort)), nil
}

func isExpectedSessionCloseErr(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return true
	}

	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) && appErr.ErrorCode == 0 {
		return true
	}

	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) && streamErr.ErrorCode == 0 {
		return true
	}

	return false
}
