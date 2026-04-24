package session

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestAuthPayloadRoundTripLegacy(t *testing.T) {
	payload := AuthPayload{
		ClientID: "client-a",
		TSMS:     123456789,
		Nonce:    []byte("nonce"),
		Sig:      []byte("sig"),
		Caps:     7,
	}
	encoded := EncodeAuthPayload(payload)
	decoded, err := DecodeAuthPayload(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.ProfileID != "" || len(decoded.ResumeTag) != 0 || len(decoded.ResumeToken) != 0 {
		t.Fatalf("unexpected optional tail: %+v", decoded)
	}
	if decoded.ClientID != payload.ClientID || decoded.TSMS != payload.TSMS || decoded.Caps != payload.Caps {
		t.Fatalf("decoded=%+v", decoded)
	}
}

func TestAuthPayloadRoundTripWithOptionalTail(t *testing.T) {
	payload := AuthPayload{
		ClientID:    "client-a",
		TSMS:        123456789,
		Nonce:       []byte("nonce"),
		Sig:         []byte("sig"),
		Caps:        7,
		ProfileID:   "balanced",
		ResumeTag:   []byte{1, 2, 3},
		ResumeToken: []byte{4, 5, 6, 7},
	}
	decoded, err := DecodeAuthPayload(EncodeAuthPayload(payload))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.ProfileID != payload.ProfileID {
		t.Fatalf("profile=%s, want %s", decoded.ProfileID, payload.ProfileID)
	}
	if !bytes.Equal(decoded.ResumeTag, payload.ResumeTag) {
		t.Fatalf("resume_tag=%v, want %v", decoded.ResumeTag, payload.ResumeTag)
	}
	if !bytes.Equal(decoded.ResumeToken, payload.ResumeToken) {
		t.Fatalf("resume_token=%v, want %v", decoded.ResumeToken, payload.ResumeToken)
	}
}

func TestAuthOKPayloadRoundTripWithOptionalTail(t *testing.T) {
	payload := AuthOKPayload{
		SessionID:   42,
		ExpiresMS:   60000,
		UpKbps:      20000,
		DownKbps:    15000,
		MaxFlows:    32,
		MaxUDPPPS:   900,
		ProfileID:   "survival",
		ResumeTag:   []byte{8, 9},
		ResumeToken: []byte{10, 11, 12},
	}
	decoded, err := DecodeAuthOKPayload(EncodeAuthOKPayload(payload))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.ProfileID != payload.ProfileID {
		t.Fatalf("profile=%s, want %s", decoded.ProfileID, payload.ProfileID)
	}
	if !bytes.Equal(decoded.ResumeTag, payload.ResumeTag) {
		t.Fatalf("resume_tag=%v, want %v", decoded.ResumeTag, payload.ResumeTag)
	}
	if !bytes.Equal(decoded.ResumeToken, payload.ResumeToken) {
		t.Fatalf("resume_token=%v, want %v", decoded.ResumeToken, payload.ResumeToken)
	}
}

func TestProfilePayloadRoundTrip(t *testing.T) {
	payload := ProfilePayload{ProfileID: "low_observable", Reason: "migration accepted"}
	decoded, err := DecodeProfilePayload(EncodeProfilePayload(payload))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded != payload {
		t.Fatalf("decoded=%+v, want %+v", decoded, payload)
	}
}

func TestReadFrameRejectsOversizedPayloadBeforeAllocation(t *testing.T) {
	var raw bytes.Buffer
	var head [20]byte
	n := binary.PutUvarint(head[:], FramePING)
	raw.Write(head[:n])
	n = binary.PutUvarint(head[:], MaxFramePayload+1)
	raw.Write(head[:n])

	_, err := ReadFrame(bufio.NewReader(bytes.NewReader(raw.Bytes())))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("ReadFrame err=%v, want ErrFrameTooLarge", err)
	}
}

func TestDecodeAuthRejectsOversizedNestedFieldBeforeAllocation(t *testing.T) {
	var raw bytes.Buffer
	var head [10]byte
	n := binary.PutUvarint(head[:], MaxControlFieldPayload+1)
	raw.Write(head[:n])

	_, err := DecodeAuthPayload(raw.Bytes())
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("DecodeAuthPayload err=%v, want ErrFrameTooLarge", err)
	}
}
