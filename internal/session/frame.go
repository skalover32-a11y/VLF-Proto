package session

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	FrameAUTH uint64 = iota + 1
	FrameAUTHOK
	FrameAUTHFAIL
	FrameOPENTCP
	FrameOPENTCPOK
	FrameOPENTCPFAIL
	FrameOPENUDP
	FrameOPENUDPOK
	FrameOPENUDPFAIL
	FrameCLOSEFLOW
	FramePING
	FramePONG
	FrameTCPDATA
	FramePROFILESET
	FramePROFILEOK
	FramePROFILEFAIL
)

const (
	DatagramFlagFragmented uint8 = 1 << 0
	DatagramFlagLast       uint8 = 1 << 1
)

const (
	// MaxFramePayload is the absolute bound for framed control payloads. The
	// current protocol uses small AUTH/OPEN/PING/PROFILE frames; 64 KiB leaves
	// operational headroom without allowing attacker-controlled OOM allocation.
	MaxFramePayload        uint64 = 64 * 1024
	MaxAuthPayload         int    = 16 * 1024
	MaxOpenPayload         int    = 4 * 1024
	MaxProfilePayload      int    = 4 * 1024
	MaxFailPayload         int    = 4 * 1024
	MaxControlFieldPayload uint64 = 16 * 1024
)

var (
	ErrFrameTooLarge     = errors.New("frame payload too large")
	ErrProtocolViolation = errors.New("protocol violation")
)

type Frame struct {
	Type    uint64
	Payload []byte
}

func ReadFrame(r *bufio.Reader) (*Frame, error) {
	return ReadFrameLimited(r, MaxFramePayload)
}

func ReadFrameLimited(r *bufio.Reader, maxPayload uint64) (*Frame, error) {
	typ, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}

	ln, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	if ln > maxPayload {
		return nil, fmt.Errorf("%w: type=%d len=%d max=%d", ErrFrameTooLarge, typ, ln, maxPayload)
	}

	payload := make([]byte, ln)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	return &Frame{Type: typ, Payload: payload}, nil
}

func WriteFrame(w io.Writer, frameType uint64, payload []byte) error {
	var head [20]byte

	nType := binary.PutUvarint(head[:], frameType)
	if _, err := w.Write(head[:nType]); err != nil {
		return err
	}

	nLen := binary.PutUvarint(head[:], uint64(len(payload)))
	if _, err := w.Write(head[:nLen]); err != nil {
		return err
	}

	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

type AuthPayload struct {
	ClientID    string
	TSMS        uint64
	Nonce       []byte
	Sig         []byte
	Caps        uint64
	ProfileID   string
	ResumeTag   []byte
	ResumeToken []byte
}

func EncodeAuthPayload(p AuthPayload) []byte {
	b := &bytes.Buffer{}
	writeString(b, p.ClientID)
	_ = binary.Write(b, binary.BigEndian, p.TSMS)
	writeBytes(b, p.Nonce)
	writeBytes(b, p.Sig)
	_ = binary.Write(b, binary.BigEndian, p.Caps)
	if p.ProfileID != "" || len(p.ResumeTag) > 0 || len(p.ResumeToken) > 0 {
		writeString(b, p.ProfileID)
		writeBytes(b, p.ResumeTag)
		writeBytes(b, p.ResumeToken)
	}
	return b.Bytes()
}

func DecodeAuthPayload(raw []byte) (AuthPayload, error) {
	if err := validatePayloadSize("AUTH", len(raw), MaxAuthPayload); err != nil {
		return AuthPayload{}, err
	}
	r := bytes.NewReader(raw)

	clientID, err := readString(r)
	if err != nil {
		return AuthPayload{}, fmt.Errorf("decode client_id: %w", err)
	}

	var ts uint64
	if err := binary.Read(r, binary.BigEndian, &ts); err != nil {
		return AuthPayload{}, fmt.Errorf("decode ts_ms: %w", err)
	}

	nonce, err := readBytes(r)
	if err != nil {
		return AuthPayload{}, fmt.Errorf("decode nonce: %w", err)
	}

	sig, err := readBytes(r)
	if err != nil {
		return AuthPayload{}, fmt.Errorf("decode sig: %w", err)
	}

	var caps uint64
	if err := binary.Read(r, binary.BigEndian, &caps); err != nil {
		return AuthPayload{}, fmt.Errorf("decode caps: %w", err)
	}

	payload := AuthPayload{
		ClientID: clientID,
		TSMS:     ts,
		Nonce:    nonce,
		Sig:      sig,
		Caps:     caps,
	}

	if r.Len() == 0 {
		return payload, nil
	}

	profileID, err := readString(r)
	if err != nil {
		return AuthPayload{}, fmt.Errorf("decode profile_id: %w", err)
	}
	resumeTag, err := readBytes(r)
	if err != nil {
		return AuthPayload{}, fmt.Errorf("decode resume_tag: %w", err)
	}
	resumeToken, err := readBytes(r)
	if err != nil {
		return AuthPayload{}, fmt.Errorf("decode resume_token: %w", err)
	}
	if r.Len() != 0 {
		return AuthPayload{}, errors.New("trailing bytes in AUTH payload")
	}
	payload.ProfileID = profileID
	payload.ResumeTag = resumeTag
	payload.ResumeToken = resumeToken
	return payload, nil
}

type AuthOKPayload struct {
	SessionID   uint64
	ExpiresMS   uint32
	UpKbps      uint32
	DownKbps    uint32
	MaxFlows    uint32
	MaxUDPPPS   uint32
	ProfileID   string
	ResumeTag   []byte
	ResumeToken []byte
}

func EncodeAuthOKPayload(p AuthOKPayload) []byte {
	b := &bytes.Buffer{}
	_ = binary.Write(b, binary.BigEndian, p.SessionID)
	_ = binary.Write(b, binary.BigEndian, p.ExpiresMS)
	_ = binary.Write(b, binary.BigEndian, p.UpKbps)
	_ = binary.Write(b, binary.BigEndian, p.DownKbps)
	_ = binary.Write(b, binary.BigEndian, p.MaxFlows)
	_ = binary.Write(b, binary.BigEndian, p.MaxUDPPPS)
	if p.ProfileID != "" || len(p.ResumeTag) > 0 || len(p.ResumeToken) > 0 {
		writeString(b, p.ProfileID)
		writeBytes(b, p.ResumeTag)
		writeBytes(b, p.ResumeToken)
	}
	return b.Bytes()
}

func DecodeAuthOKPayload(raw []byte) (AuthOKPayload, error) {
	if err := validatePayloadSize("AUTH_OK", len(raw), MaxAuthPayload); err != nil {
		return AuthOKPayload{}, err
	}
	r := bytes.NewReader(raw)

	var payload AuthOKPayload
	if err := binary.Read(r, binary.BigEndian, &payload.SessionID); err != nil {
		return AuthOKPayload{}, fmt.Errorf("decode session_id: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &payload.ExpiresMS); err != nil {
		return AuthOKPayload{}, fmt.Errorf("decode expires_ms: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &payload.UpKbps); err != nil {
		return AuthOKPayload{}, fmt.Errorf("decode up_kbps: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &payload.DownKbps); err != nil {
		return AuthOKPayload{}, fmt.Errorf("decode down_kbps: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &payload.MaxFlows); err != nil {
		return AuthOKPayload{}, fmt.Errorf("decode max_flows: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &payload.MaxUDPPPS); err != nil {
		return AuthOKPayload{}, fmt.Errorf("decode max_udp_pps: %w", err)
	}
	if r.Len() == 0 {
		return payload, nil
	}
	profileID, err := readString(r)
	if err != nil {
		return AuthOKPayload{}, fmt.Errorf("decode profile_id: %w", err)
	}
	resumeTag, err := readBytes(r)
	if err != nil {
		return AuthOKPayload{}, fmt.Errorf("decode resume_tag: %w", err)
	}
	resumeToken, err := readBytes(r)
	if err != nil {
		return AuthOKPayload{}, fmt.Errorf("decode resume_token: %w", err)
	}
	if r.Len() != 0 {
		return AuthOKPayload{}, errors.New("trailing bytes in AUTH_OK payload")
	}
	payload.ProfileID = profileID
	payload.ResumeTag = resumeTag
	payload.ResumeToken = resumeToken
	return payload, nil
}

type OpenPayload struct {
	FlowID  uint64
	DstHost string
	DstIP   []byte
	DstPort uint16
}

func EncodeOpenPayload(p OpenPayload) []byte {
	b := &bytes.Buffer{}
	_ = binary.Write(b, binary.BigEndian, p.FlowID)
	writeString(b, p.DstHost)
	writeBytes(b, p.DstIP)
	_ = binary.Write(b, binary.BigEndian, p.DstPort)
	return b.Bytes()
}

func DecodeOpenPayload(raw []byte) (OpenPayload, error) {
	if err := validatePayloadSize("OPEN", len(raw), MaxOpenPayload); err != nil {
		return OpenPayload{}, err
	}
	r := bytes.NewReader(raw)

	var flowID uint64
	if err := binary.Read(r, binary.BigEndian, &flowID); err != nil {
		return OpenPayload{}, fmt.Errorf("decode flow_id: %w", err)
	}

	dstHost, err := readString(r)
	if err != nil {
		return OpenPayload{}, fmt.Errorf("decode dst_host: %w", err)
	}

	dstIP, err := readBytes(r)
	if err != nil {
		return OpenPayload{}, fmt.Errorf("decode dst_ip: %w", err)
	}

	var dstPort uint16
	if err := binary.Read(r, binary.BigEndian, &dstPort); err != nil {
		return OpenPayload{}, fmt.Errorf("decode dst_port: %w", err)
	}

	if r.Len() != 0 {
		return OpenPayload{}, errors.New("trailing bytes in OPEN payload")
	}

	return OpenPayload{
		FlowID:  flowID,
		DstHost: dstHost,
		DstIP:   dstIP,
		DstPort: dstPort,
	}, nil
}

type OpenOKPayload struct {
	FlowID uint64
	Mode   uint8
}

func EncodeOpenOKPayload(p OpenOKPayload) []byte {
	b := &bytes.Buffer{}
	_ = binary.Write(b, binary.BigEndian, p.FlowID)
	_ = b.WriteByte(p.Mode)
	return b.Bytes()
}

func DecodeOpenOKPayload(raw []byte) (OpenOKPayload, error) {
	r := bytes.NewReader(raw)
	var flowID uint64
	if err := binary.Read(r, binary.BigEndian, &flowID); err != nil {
		return OpenOKPayload{}, err
	}
	mode, err := r.ReadByte()
	if err != nil {
		return OpenOKPayload{}, err
	}
	return OpenOKPayload{FlowID: flowID, Mode: mode}, nil
}

type CloseFlowPayload struct {
	FlowID uint64
}

func EncodeCloseFlowPayload(p CloseFlowPayload) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, p.FlowID)
	return out
}

func DecodeCloseFlowPayload(raw []byte) (CloseFlowPayload, error) {
	if len(raw) != 8 {
		return CloseFlowPayload{}, fmt.Errorf("close flow payload must be 8 bytes, got %d", len(raw))
	}
	return CloseFlowPayload{FlowID: binary.BigEndian.Uint64(raw)}, nil
}

type ProfilePayload struct {
	ProfileID string
	Reason    string
}

func EncodeProfilePayload(p ProfilePayload) []byte {
	b := &bytes.Buffer{}
	writeString(b, p.ProfileID)
	writeString(b, p.Reason)
	return b.Bytes()
}

func DecodeProfilePayload(raw []byte) (ProfilePayload, error) {
	if err := validatePayloadSize("PROFILE", len(raw), MaxProfilePayload); err != nil {
		return ProfilePayload{}, err
	}
	r := bytes.NewReader(raw)
	profileID, err := readString(r)
	if err != nil {
		return ProfilePayload{}, fmt.Errorf("decode profile_id: %w", err)
	}
	reason, err := readString(r)
	if err != nil {
		return ProfilePayload{}, fmt.Errorf("decode reason: %w", err)
	}
	if r.Len() != 0 {
		return ProfilePayload{}, errors.New("trailing bytes in PROFILE payload")
	}
	return ProfilePayload{ProfileID: profileID, Reason: reason}, nil
}

type FailPayload struct {
	FlowID uint64
	Reason string
}

func EncodeFailPayload(p FailPayload) []byte {
	b := &bytes.Buffer{}
	_ = binary.Write(b, binary.BigEndian, p.FlowID)
	writeString(b, p.Reason)
	return b.Bytes()
}

func EncodeAuthFail(reason string) []byte {
	b := &bytes.Buffer{}
	writeString(b, reason)
	return b.Bytes()
}

func EncodeTCPDataPayload(flowID uint64, data []byte) []byte {
	out := make([]byte, 8+len(data))
	binary.BigEndian.PutUint64(out[:8], flowID)
	copy(out[8:], data)
	return out
}

func DecodeTCPDataPayload(raw []byte) (flowID uint64, data []byte, err error) {
	if len(raw) < 8 {
		return 0, nil, fmt.Errorf("tcp data payload too short: %d", len(raw))
	}
	return binary.BigEndian.Uint64(raw[:8]), append([]byte(nil), raw[8:]...), nil
}

func writeString(w io.Writer, s string) {
	writeBytes(w, []byte(s))
}

func writeBytes(w io.Writer, data []byte) {
	var head [10]byte
	n := binary.PutUvarint(head[:], uint64(len(data)))
	_, _ = w.Write(head[:n])
	if len(data) > 0 {
		_, _ = w.Write(data)
	}
}

func readBytes(r *bytes.Reader) ([]byte, error) {
	ln, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	if ln == 0 {
		return nil, nil
	}
	if ln > MaxControlFieldPayload {
		return nil, fmt.Errorf("%w: field len=%d max=%d", ErrFrameTooLarge, ln, MaxControlFieldPayload)
	}
	if ln > uint64(r.Len()) {
		return nil, fmt.Errorf("%w: field len=%d remaining=%d", ErrProtocolViolation, ln, r.Len())
	}
	out := make([]byte, ln)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func readString(r *bytes.Reader) (string, error) {
	raw, err := readBytes(r)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func validatePayloadSize(name string, got int, max int) error {
	if got > max {
		return fmt.Errorf("%w: %s len=%d max=%d", ErrFrameTooLarge, name, got, max)
	}
	return nil
}
