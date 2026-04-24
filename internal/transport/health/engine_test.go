package health

import (
	"testing"
	"time"
)

func TestStablePathScoresHealthy(t *testing.T) {
	eng := NewEngine(Config{})
	now := time.Unix(1700000000, 0)
	for i := 0; i < 6; i++ {
		eng.Observe(Sample{At: now.Add(time.Duration(i) * time.Second), RTTMs: 42, JitterMs: 6, ThroughputBps: 8_000_000, SentPackets: 100, AckedPackets: 99, DeliveredPackets: 99})
	}
	snap := eng.Evaluate(now.Add(6 * time.Second))
	if snap.Level != DegradationHealthy {
		t.Fatalf("level = %s, want healthy", snap.Level)
	}
	if snap.Score < 90 {
		t.Fatalf("score = %d, want >= 90", snap.Score)
	}
}

func TestHighLossScoresDegraded(t *testing.T) {
	eng := NewEngine(Config{})
	now := time.Unix(1700000000, 0)
	for i := 0; i < 6; i++ {
		eng.Observe(Sample{At: now.Add(time.Duration(i) * time.Second), LossRatio: 0.22, RTTMs: 120, JitterMs: 35, TimeoutRate: 0.10, ThroughputBps: 2_000_000})
	}
	snap := eng.Evaluate(now.Add(6 * time.Second))
	if snap.Level != DegradationDegraded && snap.Level != DegradationCritical {
		t.Fatalf("level = %s, want degraded or critical", snap.Level)
	}
	if len(snap.Flags) == 0 || snap.Flags[0] != ReasonHighLoss {
		t.Fatalf("flags = %v, want high_loss present", snap.Flags)
	}
}

func TestJitterSpikeMarksSuspect(t *testing.T) {
	eng := NewEngine(Config{})
	now := time.Unix(1700000000, 0)
	for i := 0; i < 5; i++ {
		eng.Observe(Sample{At: now.Add(time.Duration(i) * time.Second), RTTMs: 70, JitterMs: 90, ThroughputBps: 6_000_000})
	}
	snap := eng.Evaluate(now.Add(5 * time.Second))
	if snap.Level != DegradationSuspect && snap.Level != DegradationDegraded {
		t.Fatalf("level = %s, want suspect/degraded", snap.Level)
	}
	found := false
	for _, flag := range snap.Flags {
		if flag == ReasonHighJitter {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("flags = %v, want high_jitter", snap.Flags)
	}
}

func TestIdleResumeFailuresFlagged(t *testing.T) {
	eng := NewEngine(Config{})
	now := time.Unix(1700000000, 0)
	for i := 0; i < 4; i++ {
		eng.Observe(Sample{At: now.Add(time.Duration(i) * time.Second), IdleResumeFailure: true, TimeoutRate: 0.05})
	}
	snap := eng.Evaluate(now.Add(4 * time.Second))
	found := false
	for _, flag := range snap.Flags {
		if flag == ReasonIdleResumeFailures {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("flags = %v, want idle_resume_failures", snap.Flags)
	}
}
