package session

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

const datagramHeaderSize = 8 + 1 + 4

type DatagramPacket struct {
	FlowID  uint64
	Flags   uint8
	Seq     uint32
	Payload []byte
}

func EncodeDatagramPacket(pkt DatagramPacket) []byte {
	out := make([]byte, datagramHeaderSize+len(pkt.Payload))
	binary.BigEndian.PutUint64(out[:8], pkt.FlowID)
	out[8] = pkt.Flags
	binary.BigEndian.PutUint32(out[9:13], pkt.Seq)
	copy(out[13:], pkt.Payload)
	return out
}

func DecodeDatagramPacket(raw []byte) (DatagramPacket, error) {
	if len(raw) < datagramHeaderSize {
		return DatagramPacket{}, fmt.Errorf("datagram too short: %d", len(raw))
	}

	pkt := DatagramPacket{
		FlowID:  binary.BigEndian.Uint64(raw[:8]),
		Flags:   raw[8],
		Seq:     binary.BigEndian.Uint32(raw[9:13]),
		Payload: append([]byte(nil), raw[13:]...),
	}
	return pkt, nil
}

func FragmentDatagram(flowID uint64, seq uint32, payload []byte, maxDatagramPayload int) ([][]byte, error) {
	if maxDatagramPayload <= datagramHeaderSize {
		return nil, errors.New("maxDatagramPayload too small")
	}

	maxChunk := maxDatagramPayload - datagramHeaderSize
	if len(payload) <= maxChunk {
		return [][]byte{EncodeDatagramPacket(DatagramPacket{FlowID: flowID, Flags: 0, Seq: seq, Payload: payload})}, nil
	}

	out := make([][]byte, 0, (len(payload)+maxChunk-1)/maxChunk)
	for i := 0; i < len(payload); i += maxChunk {
		end := i + maxChunk
		if end > len(payload) {
			end = len(payload)
		}

		flags := DatagramFlagFragmented
		if end == len(payload) {
			flags |= DatagramFlagLast
		}

		out = append(out, EncodeDatagramPacket(DatagramPacket{
			FlowID:  flowID,
			Flags:   flags,
			Seq:     seq,
			Payload: payload[i:end],
		}))
	}
	return out, nil
}

type fragmentState struct {
	data      []byte
	updatedAt time.Time
}

type Reassembly struct {
	mu    sync.Mutex
	parts map[uint64]map[uint32]*fragmentState
}

func NewReassembly() *Reassembly {
	return &Reassembly{parts: make(map[uint64]map[uint32]*fragmentState)}
}

// Add returns (payload, true) when packet is complete.
func (r *Reassembly) Add(pkt DatagramPacket) ([]byte, bool) {
	if pkt.Flags&DatagramFlagFragmented == 0 {
		return pkt.Payload, true
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	r.cleanupLocked(now)

	bySeq := r.parts[pkt.FlowID]
	if bySeq == nil {
		bySeq = make(map[uint32]*fragmentState)
		r.parts[pkt.FlowID] = bySeq
	}

	st := bySeq[pkt.Seq]
	if st == nil {
		st = &fragmentState{}
		bySeq[pkt.Seq] = st
	}

	st.data = append(st.data, pkt.Payload...)
	st.updatedAt = now

	if pkt.Flags&DatagramFlagLast == 0 {
		return nil, false
	}

	payload := append([]byte(nil), st.data...)
	delete(bySeq, pkt.Seq)
	if len(bySeq) == 0 {
		delete(r.parts, pkt.FlowID)
	}

	return payload, true
}

func (r *Reassembly) cleanupLocked(now time.Time) {
	cutoff := now.Add(-5 * time.Second)
	for flowID, bySeq := range r.parts {
		for seq, st := range bySeq {
			if st.updatedAt.Before(cutoff) {
				delete(bySeq, seq)
			}
		}
		if len(bySeq) == 0 {
			delete(r.parts, flowID)
		}
	}
}
