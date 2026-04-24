package sessionclient

import (
	"time"

	"vlf-runtime/internal/transport/profile"
)

func profileProbeTimeout(p profile.TransportProfile, fallback time.Duration) time.Duration {
	timeout := fallback
	if retry := p.RetryPolicy.ProbeBackoff; retry > timeout {
		timeout = retry
	}
	if !p.AckHintPolicy.Enabled {
		return timeout
	}
	hinted := p.AckHintPolicy.ExpectedAckGap + p.AckHintPolicy.AckDelayBudget + 500*time.Millisecond
	if hinted > timeout {
		timeout = hinted
	}
	return timeout
}

func profileProbePayload(token []byte, p profile.TransportProfile) []byte {
	out := append([]byte(nil), token...)
	if !p.PaddingPolicy.Enabled || p.PaddingPolicy.MaxPaddingBytes <= 0 {
		return out
	}
	target := p.PacketSizeStrategy.PaddingTargetBytes
	if target <= len(out) {
		target = len(out) + p.PaddingPolicy.MaxPaddingBytes
	}
	if target-len(out) > p.PaddingPolicy.MaxPaddingBytes {
		target = len(out) + p.PaddingPolicy.MaxPaddingBytes
	}
	for len(out) < target {
		out = append(out, 0)
	}
	return out
}

func profileBurstPause(p profile.TransportProfile, sentIndex, totalPackets int) time.Duration {
	if sentIndex >= totalPackets-1 {
		return 0
	}
	if p.CoalescingPolicy.Enabled && p.CoalescingPolicy.MaxFrames > 1 {
		if (sentIndex+1)%p.CoalescingPolicy.MaxFrames != 0 {
			return 0
		}
		if p.CoalescingPolicy.FlushInterval > 0 {
			return p.CoalescingPolicy.FlushInterval
		}
		if p.InterPacketTimingStrategy.BurstCooldown > 0 {
			return p.InterPacketTimingStrategy.BurstCooldown
		}
	}
	return profileSendGap(p)
}
