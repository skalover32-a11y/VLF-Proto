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
)

const (
	DatagramFlagFragmented uint8 = 1 << 0
	DatagramFlagLast       uint8 = 1 << 1
)

type Frame struct {
	Type    uint64
	Payload []byte
}

func ReadFrame(r *bufio.Reader) (*Frame, error) {
	typ, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}

	ln, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
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
	ClientID string
	TSMS     uint64
	Nonce    []byte
	Sig      []byte
	Caps     uint64
}

func EncodeAuthPayload(p AuthPayload) []byte {
	b := &bytes.Buffer{}
	writeString(b, p.ClientID)
	_ = binary.Write(b, binary.BigEndian, p.TSMS)
	writeBytes(b, p.Nonce)
	writeBytes(b, p.Sig)
	_ = binary.Write(b, binary.BigEndian, p.Caps)
	return b.Bytes()
}

func DecodeAuthPayload(raw []byte) (AuthPayload, error) {
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

	if r.Len() != 0 {
		return AuthPayload{}, errors.New("trailing bytes in AUTH payload")
	}

	return AuthPayload{
		ClientID: clientID,
		TSMS:     ts,
		Nonce:    nonce,
		Sig:      sig,
		Caps:     caps,
	}, nil
}

type AuthOKPayload struct {
	SessionID uint64
	ExpiresMS uint32
	UpKbps    uint32
	DownKbps  uint32
	MaxFlows  uint32
	MaxUDPPPS uint32
}

func EncodeAuthOKPayload(p AuthOKPayload) []byte {
	b := &bytes.Buffer{}
	_ = binary.Write(b, binary.BigEndian, p.SessionID)
	_ = binary.Write(b, binary.BigEndian, p.ExpiresMS)
	_ = binary.Write(b, binary.BigEndian, p.UpKbps)
	_ = binary.Write(b, binary.BigEndian, p.DownKbps)
	_ = binary.Write(b, binary.BigEndian, p.MaxFlows)
	_ = binary.Write(b, binary.BigEndian, p.MaxUDPPPS)
	return b.Bytes()
}

func DecodeAuthOKPayload(raw []byte) (AuthOKPayload, error) {
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
	if r.Len() != 0 {
		return AuthOKPayload{}, errors.New("trailing bytes in AUTH_OK payload")
	}
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
