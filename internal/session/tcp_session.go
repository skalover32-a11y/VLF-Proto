package session

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"

	"vlf-runtime/internal/limits"
)

type tcpFlowInline struct {
	id        uint64
	target    net.Conn
	closeOnce sync.Once
}

type TCPSession struct {
	id     uint64
	conn   net.Conn
	server *Server
	logger *zap.Logger

	ctx    context.Context
	cancel context.CancelFunc

	closeOnce sync.Once

	clientID string

	controlR *bufio.Reader
	writeMu  sync.Mutex

	flowsMu  sync.RWMutex
	tcpFlows map[uint64]*tcpFlowInline

	wg sync.WaitGroup
}

func newTCPSession(id uint64, conn net.Conn, server *Server, logger *zap.Logger) *TCPSession {
	ctx, cancel := context.WithCancel(context.Background())
	return &TCPSession{
		id:       id,
		conn:     conn,
		server:   server,
		logger:   logger,
		ctx:      ctx,
		cancel:   cancel,
		controlR: bufio.NewReader(conn),
		tcpFlows: make(map[uint64]*tcpFlowInline),
	}
}

func (s *TCPSession) ID() uint64 {
	return s.id
}

func (s *TCPSession) ClientID() string {
	return s.clientID
}

func (s *TCPSession) Run() error {
	defer s.Close("run_exit")

	if err := s.conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return fmt.Errorf("set auth read deadline: %w", err)
	}
	first, err := ReadFrame(s.controlR)
	if err != nil {
		return fmt.Errorf("read first frame: %w", err)
	}
	_ = s.conn.SetReadDeadline(time.Time{})

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
	s.logger.Info("tcp session authenticated", zap.String("client_id", s.clientID))

	for {
		frame, err := ReadFrame(s.controlR)
		if err != nil {
			if s.ctx.Err() == nil {
				if isExpectedTCPSessionCloseErr(err) {
					s.logger.Debug("tcp control stream closed", zap.Error(err))
				} else {
					s.logger.Warn("tcp control stream read failed", zap.Error(err))
				}
			}
			return nil
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
			flowID := uint64(0)
			if err == nil {
				flowID = payload.FlowID
			}
			_ = s.writeFrame(FrameOPENUDPFAIL, EncodeFailPayload(FailPayload{FlowID: flowID, Reason: "udp is not supported on tcp transport"}))
		case FrameCLOSEFLOW:
			payload, err := DecodeCloseFlowPayload(frame.Payload)
			if err != nil {
				continue
			}
			s.closeFlow(payload.FlowID, "client_close_flow", false)
		case FrameTCPDATA:
			flowID, data, err := DecodeTCPDataPayload(frame.Payload)
			if err != nil {
				continue
			}
			if err := s.handleClientTCPData(flowID, data); err != nil {
				if errors.Is(err, limits.ErrMaxBytesPerMinuteSess) {
					s.Close("session_bytes_limit")
					return nil
				}
				s.closeFlow(flowID, "client_tcp_data_error", true)
			}
		default:
			s.logger.Warn("unknown tcp control frame", zap.Uint64("type", frame.Type))
		}
	}
}

func (s *TCPSession) Close(reason string) {
	s.closeOnce.Do(func() {
		s.logger.Info("closing tcp session", zap.String("reason", reason))
		s.cancel()
		_ = s.conn.Close()

		s.flowsMu.Lock()
		flows := make([]*tcpFlowInline, 0, len(s.tcpFlows))
		for _, flow := range s.tcpFlows {
			flows = append(flows, flow)
		}
		s.tcpFlows = make(map[uint64]*tcpFlowInline)
		s.flowsMu.Unlock()

		for _, flow := range flows {
			flow.closeOnce.Do(func() {
				_ = flow.target.Close()
			})
			s.server.metrics.TCPStreams.Dec()
		}

		s.wg.Wait()
	})
}

func (s *TCPSession) handleOpenTCP(p OpenPayload) {
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

	dialer := net.Dialer{Timeout: s.server.cfg.DialTimeout}
	target, err := dialer.DialContext(s.ctx, "tcp", addr)
	if err != nil {
		s.server.metrics.OpenFailures.WithLabelValues("session", "tcp_dial").Inc()
		_ = s.writeFrame(FrameOPENTCPFAIL, EncodeFailPayload(FailPayload{FlowID: p.FlowID, Reason: err.Error()}))
		return
	}

	flow := &tcpFlowInline{id: p.FlowID, target: target}
	s.flowsMu.Lock()
	if _, exists := s.tcpFlows[p.FlowID]; exists {
		s.flowsMu.Unlock()
		_ = target.Close()
		_ = s.writeFrame(FrameOPENTCPFAIL, EncodeFailPayload(FailPayload{FlowID: p.FlowID, Reason: "flow_id already exists"}))
		return
	}
	s.tcpFlows[p.FlowID] = flow
	s.flowsMu.Unlock()

	s.server.metrics.TCPStreams.Inc()

	if err := s.writeFrame(FrameOPENTCPOK, EncodeOpenOKPayload(OpenOKPayload{FlowID: p.FlowID, Mode: 3})); err != nil {
		s.closeFlow(p.FlowID, "open_tcp_ok_write_failed", false)
		return
	}

	s.wg.Add(1)
	go s.targetToClientLoop(flow)
	s.logger.Info("opened TCP flow on tcp transport", zap.Uint64("flow_id", p.FlowID), zap.String("dst", addr))
}

func (s *TCPSession) targetToClientLoop(flow *tcpFlowInline) {
	defer s.wg.Done()

	buf := make([]byte, 32*1024)
	for {
		n, err := flow.target.Read(buf)
		if n > 0 {
			if limitErr := s.server.limits.AllowSessionBytes(s.id, n); limitErr != nil {
				s.Close("session_bytes_limit")
				return
			}
			if writeErr := s.writeFrame(FrameTCPDATA, EncodeTCPDataPayload(flow.id, buf[:n])); writeErr != nil {
				s.Close("tcp_data_write_failed")
				return
			}
			s.server.metrics.BytesOut.WithLabelValues("session").Add(float64(n))
			s.touch()
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && s.ctx.Err() == nil {
				s.logger.Debug("tcp target read ended", zap.Uint64("flow_id", flow.id), zap.Error(err))
			}
			s.closeFlow(flow.id, "tcp_target_read_end", true)
			return
		}
	}
}

func (s *TCPSession) handleClientTCPData(flowID uint64, data []byte) error {
	s.flowsMu.RLock()
	flow := s.tcpFlows[flowID]
	s.flowsMu.RUnlock()
	if flow == nil {
		return errors.New("unknown tcp flow")
	}
	if len(data) == 0 {
		return nil
	}
	if err := s.server.limits.AllowSessionBytes(s.id, len(data)); err != nil {
		return err
	}
	if _, err := flow.target.Write(data); err != nil {
		return err
	}
	s.server.metrics.BytesIn.WithLabelValues("session").Add(float64(len(data)))
	s.touch()
	return nil
}

func (s *TCPSession) closeFlow(flowID uint64, reason string, notify bool) {
	s.flowsMu.Lock()
	flow, ok := s.tcpFlows[flowID]
	if ok {
		delete(s.tcpFlows, flowID)
	}
	s.flowsMu.Unlock()
	if !ok {
		return
	}

	flow.closeOnce.Do(func() {
		_ = flow.target.Close()
	})
	s.server.metrics.TCPStreams.Dec()
	s.logger.Info("closed tcp flow", zap.Uint64("flow_id", flowID), zap.String("reason", reason))

	if notify {
		_ = s.writeFrame(FrameCLOSEFLOW, EncodeCloseFlowPayload(CloseFlowPayload{FlowID: flowID}))
	}
}

func (s *TCPSession) flowCount() int {
	s.flowsMu.RLock()
	defer s.flowsMu.RUnlock()
	return len(s.tcpFlows)
}

func (s *TCPSession) writeFrame(frameType uint64, payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return WriteFrame(s.conn, frameType, payload)
}

func (s *TCPSession) touch() {
	s.server.touchSession(s.id)
}

func isExpectedTCPSessionCloseErr(err error) bool {
	if err == nil {
		return true
	}
	return errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed)
}
