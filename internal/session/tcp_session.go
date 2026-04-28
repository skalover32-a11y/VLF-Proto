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
	"vlf-runtime/internal/transport/profile"
	"vlf-runtime/internal/transport/resume"
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

	clientID   string
	pathFamily string

	controlR *bufio.Reader
	writeMu  sync.Mutex

	profileMu     sync.RWMutex
	activeProfile profile.TransportProfile

	flowsMu  sync.RWMutex
	tcpFlows map[uint64]*tcpFlowInline

	wg sync.WaitGroup
}

func newTCPSession(id uint64, conn net.Conn, server *Server, logger *zap.Logger) *TCPSession {
	ctx, cancel := context.WithCancel(context.Background())
	return &TCPSession{
		id:            id,
		conn:          conn,
		server:        server,
		logger:        logger,
		ctx:           ctx,
		cancel:        cancel,
		controlR:      bufio.NewReader(conn),
		tcpFlows:      make(map[uint64]*tcpFlowInline),
		pathFamily:    "tcp-session",
		activeProfile: server.profiles.MustGetOrDefault(server.cfg.DefaultProfileID),
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
		s.logger.Warn("AUTH failed", zap.String("client_id", authPayload.ClientID), zap.Error(err))
		_ = s.writeFrame(FrameAUTHFAIL, EncodeAuthFail("AUTH verification failed"))
		return fmt.Errorf("verify AUTH client=%q: %w", authPayload.ClientID, err)
	}

	s.clientID = authPayload.ClientID
	acceptedProfile := s.resolveRequestedProfile(authPayload.ProfileID)
	s.setActiveProfile(acceptedProfile)
	clientSupportsProfile := authPayload.ProfileID != ""
	clientSupportsResume := len(authPayload.ResumeTag) > 0 || len(authPayload.ResumeToken) > 0

	var resumeState resume.State
	if s.server.cfg.ResumeTokensEnabled && s.server.resumeManager != nil {
		if len(authPayload.ResumeTag) > 0 && len(authPayload.ResumeToken) > 0 {
			s.server.metrics.ResumeAttempts.WithLabelValues(s.pathFamily, "server").Inc()
			if _, err := s.server.resumeManager.Validate(authPayload.ResumeTag, authPayload.ResumeToken, authPayload.ClientID, s.pathFamily); err != nil {
				switch {
				case errors.Is(err, resume.ErrTokenReplay):
					s.server.metrics.ResumeReplayReject.WithLabelValues(s.pathFamily, "server").Inc()
				case errors.Is(err, resume.ErrTokenExpired):
					s.server.metrics.ResumeExpiredReject.WithLabelValues(s.pathFamily, "server").Inc()
				default:
					s.server.metrics.ResumeReject.WithLabelValues(s.pathFamily, "server").Inc()
				}
				s.logger.Debug("resume validation rejected", zap.Error(err))
			} else {
				s.server.metrics.ResumeSuccess.WithLabelValues(s.pathFamily, "server").Inc()
				s.logger.Debug("resume validation accepted", zap.String("profile_id", acceptedProfile.ID))
			}
		}
		state, err := s.server.resumeManager.Issue(resume.Context{
			ClientID:   authPayload.ClientID,
			ProfileID:  acceptedProfile.ID,
			PathFamily: s.pathFamily,
			Lineage:    s.id,
		})
		if err == nil {
			resumeState = state
		} else {
			s.logger.Debug("resume token issuance skipped", zap.Error(err))
		}
	}
	s.server.registerSession(s)
	defer s.server.unregisterSession(s.id)

	authOKPayload := AuthOKPayload{
		SessionID: s.id,
		ExpiresMS: uint32(s.server.cfg.IdleTimeout.Milliseconds()),
		UpKbps:    uint32(s.server.cfg.UpKbps),
		DownKbps:  uint32(s.server.cfg.DownKbps),
		MaxFlows:  uint32(s.server.cfg.MaxFlows),
		MaxUDPPPS: uint32(s.server.cfg.MaxUDPPPS),
	}
	if s.server.cfg.TransportProfilesEnabled && clientSupportsProfile {
		authOKPayload.ProfileID = acceptedProfile.ID
	}
	if s.server.cfg.ResumeTokensEnabled && clientSupportsResume {
		authOKPayload.ResumeTag = resumeState.Tag
		authOKPayload.ResumeToken = resumeState.Token
	}
	if err := s.writeFrame(FrameAUTHOK, EncodeAuthOKPayload(authOKPayload)); err != nil {
		return fmt.Errorf("write AUTH_OK: %w", err)
	}

	s.touch()
	s.server.metrics.ActiveProfile.WithLabelValues(acceptedProfile.ID, s.pathFamily, "server").Inc()
	s.logger.Info("tcp session authenticated", zap.String("client_id", s.clientID), zap.String("profile_id", acceptedProfile.ID))

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
		case FramePROFILESET:
			payload, err := DecodeProfilePayload(frame.Payload)
			if err != nil {
				_ = s.writeFrame(FramePROFILEFAIL, EncodeProfilePayload(ProfilePayload{Reason: "invalid PROFILE_SET payload"}))
				continue
			}
			s.handleProfileSet(payload)
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
		if s.clientID != "" {
			s.server.metrics.ActiveProfile.WithLabelValues(s.activeProfile.ID, s.pathFamily, "server").Dec()
		}
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

func (s *TCPSession) resolveRequestedProfile(requested string) profile.TransportProfile {
	if !s.server.cfg.TransportProfilesEnabled {
		return s.server.profiles.MustGetOrDefault(s.server.cfg.DefaultProfileID)
	}
	if requested == "" {
		requested = s.server.cfg.DefaultProfileID
	}
	return s.server.profiles.MustGetOrDefault(requested)
}

func (s *TCPSession) setActiveProfile(next profile.TransportProfile) {
	var previous profile.TransportProfile
	s.profileMu.Lock()
	previous = s.activeProfile
	s.activeProfile = next
	s.profileMu.Unlock()
	if s.clientID != "" && previous.ID != "" && previous.ID != next.ID {
		s.server.metrics.ActiveProfile.WithLabelValues(previous.ID, s.pathFamily, "server").Dec()
		s.server.metrics.ActiveProfile.WithLabelValues(next.ID, s.pathFamily, "server").Inc()
	}
}

func (s *TCPSession) handleProfileSet(p ProfilePayload) {
	if !s.server.cfg.TransportProfilesEnabled || !s.server.cfg.ProfileMigrationEnabled {
		s.server.metrics.ProfileSwitchAttempts.WithLabelValues(p.ProfileID, s.pathFamily, "server").Inc()
		_ = s.writeFrame(FramePROFILEFAIL, EncodeProfilePayload(ProfilePayload{ProfileID: p.ProfileID, Reason: "profile migration disabled"}))
		return
	}
	s.server.metrics.ProfileSwitchAttempts.WithLabelValues(p.ProfileID, s.pathFamily, "server").Inc()
	next, ok := s.server.profiles.Get(p.ProfileID)
	if !ok {
		_ = s.writeFrame(FramePROFILEFAIL, EncodeProfilePayload(ProfilePayload{ProfileID: p.ProfileID, Reason: "unknown profile"}))
		return
	}
	s.setActiveProfile(next)
	s.server.metrics.ProfileSwitchSuccess.WithLabelValues(next.ID, s.pathFamily, "server").Inc()
	s.logger.Info("tcp session transport profile updated", zap.String("profile_id", next.ID))
	_ = s.writeFrame(FramePROFILEOK, EncodeProfilePayload(ProfilePayload{ProfileID: next.ID}))
}

func isExpectedTCPSessionCloseErr(err error) bool {
	if err == nil {
		return true
	}
	return errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed)
}
