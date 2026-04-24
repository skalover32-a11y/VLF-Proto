package health

import (
	"math"
	"sort"
	"sync"
	"time"
)

type DegradationLevel string

const (
	DegradationHealthy  DegradationLevel = "healthy"
	DegradationSuspect  DegradationLevel = "suspect"
	DegradationDegraded DegradationLevel = "degraded"
	DegradationCritical DegradationLevel = "critical"
)

type ReasonFlag string

const (
	ReasonHighLoss               ReasonFlag = "high_loss"
	ReasonHighJitter             ReasonFlag = "high_jitter"
	ReasonIdleResumeFailures     ReasonFlag = "idle_resume_failures"
	ReasonBurstSuppression       ReasonFlag = "burst_suppression_detected"
	ReasonAckStarvation          ReasonFlag = "ack_starvation"
	ReasonThroughputCollapse     ReasonFlag = "throughput_collapse"
	ReasonPathInstability        ReasonFlag = "path_instability"
	ReasonTimeoutPressure        ReasonFlag = "timeout_pressure"
	ReasonReceiveStall           ReasonFlag = "receive_stall"
	ReasonRecoveryEvents         ReasonFlag = "recovery_events"
	ReasonAckDelayAnomaly        ReasonFlag = "ack_delay_anomalies"
	ReasonReorderRate            ReasonFlag = "reorder_rate"
	ReasonDeliveryPressure       ReasonFlag = "delivery_pressure"
	ReasonInsufficientConfidence ReasonFlag = "insufficient_confidence"
)

type Sample struct {
	At time.Time

	ProfileID  string
	PathFamily string

	RTTMs            float64
	JitterMs         float64
	LossRatio        float64
	TimeoutRate      float64
	ReorderRate      float64
	AckDelayMs       float64
	ThroughputBps    float64
	SentPackets      uint64
	AckedPackets     uint64
	DeliveredPackets uint64

	IdleResumeSuccess bool
	IdleResumeFailure bool
	AckStarved        bool
	ReceiveStalled    bool
	RecoveryEvent     bool
	BurstDrop         bool
	PathFlap          bool
}

type Reason struct {
	Flag        ReasonFlag
	Severity    DegradationLevel
	Value       float64
	Threshold   float64
	Sustained   bool
	Description string
	Penalty     int
}

type Snapshot struct {
	At               time.Time
	Score            int
	Level            DegradationLevel
	Flags            []ReasonFlag
	Reasons          []Reason
	SampleCount      int
	Confidence       float64
	Window           time.Duration
	ProfileID        string
	PathFamily       string
	LossRatio        float64
	JitterP95Ms      float64
	RTTP95Ms         float64
	RTTDriftMs       float64
	TimeoutRate      float64
	ReorderRate      float64
	AckDelayP95Ms    float64
	ThroughputEMA    float64
	ThroughputRecent float64
}

type Config struct {
	Window     time.Duration
	EMAAlpha   float64
	MinSamples int

	LossSuspect             float64
	LossDegraded            float64
	LossCritical            float64
	JitterSuspect           float64
	JitterDegraded          float64
	RTTDriftSuspect         float64
	RTTDriftCritical        float64
	TimeoutSuspect          float64
	TimeoutDegraded         float64
	ReorderSuspect          float64
	AckDelayBudgetMs        float64
	ThroughputCollapseRatio float64
}

type Engine struct {
	cfg Config

	mu            sync.Mutex
	samples       []Sample
	emaRTTMs      float64
	emaJitterMs   float64
	emaThroughput float64
}

func DefaultConfig() Config {
	return Config{
		Window:                  45 * time.Second,
		EMAAlpha:                0.2,
		MinSamples:              4,
		LossSuspect:             0.03,
		LossDegraded:            0.08,
		LossCritical:            0.16,
		JitterSuspect:           35,
		JitterDegraded:          75,
		RTTDriftSuspect:         35,
		RTTDriftCritical:        100,
		TimeoutSuspect:          0.03,
		TimeoutDegraded:         0.08,
		ReorderSuspect:          0.05,
		AckDelayBudgetMs:        120,
		ThroughputCollapseRatio: 0.45,
	}
}

func NewEngine(cfg Config) *Engine {
	def := DefaultConfig()
	if cfg.Window <= 0 {
		cfg.Window = def.Window
	}
	if cfg.EMAAlpha <= 0 || cfg.EMAAlpha >= 1 {
		cfg.EMAAlpha = def.EMAAlpha
	}
	if cfg.MinSamples <= 0 {
		cfg.MinSamples = def.MinSamples
	}
	if cfg.LossSuspect <= 0 {
		cfg.LossSuspect = def.LossSuspect
	}
	if cfg.LossDegraded <= 0 {
		cfg.LossDegraded = def.LossDegraded
	}
	if cfg.LossCritical <= 0 {
		cfg.LossCritical = def.LossCritical
	}
	if cfg.JitterSuspect <= 0 {
		cfg.JitterSuspect = def.JitterSuspect
	}
	if cfg.JitterDegraded <= 0 {
		cfg.JitterDegraded = def.JitterDegraded
	}
	if cfg.RTTDriftSuspect <= 0 {
		cfg.RTTDriftSuspect = def.RTTDriftSuspect
	}
	if cfg.RTTDriftCritical <= 0 {
		cfg.RTTDriftCritical = def.RTTDriftCritical
	}
	if cfg.TimeoutSuspect <= 0 {
		cfg.TimeoutSuspect = def.TimeoutSuspect
	}
	if cfg.TimeoutDegraded <= 0 {
		cfg.TimeoutDegraded = def.TimeoutDegraded
	}
	if cfg.ReorderSuspect <= 0 {
		cfg.ReorderSuspect = def.ReorderSuspect
	}
	if cfg.AckDelayBudgetMs <= 0 {
		cfg.AckDelayBudgetMs = def.AckDelayBudgetMs
	}
	if cfg.ThroughputCollapseRatio <= 0 || cfg.ThroughputCollapseRatio >= 1 {
		cfg.ThroughputCollapseRatio = def.ThroughputCollapseRatio
	}
	return &Engine{cfg: cfg}
}

func (e *Engine) Observe(sample Sample) {
	if e == nil {
		return
	}
	if sample.At.IsZero() {
		sample.At = time.Now()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.samples = append(e.samples, sample)
	e.trimLocked(sample.At)
	e.emaRTTMs = ema(e.emaRTTMs, sample.RTTMs, e.cfg.EMAAlpha)
	e.emaJitterMs = ema(e.emaJitterMs, sample.JitterMs, e.cfg.EMAAlpha)
	e.emaThroughput = ema(e.emaThroughput, sample.ThroughputBps, e.cfg.EMAAlpha)
}

func (e *Engine) Evaluate(now time.Time) Snapshot {
	if e == nil {
		return Snapshot{At: now, Score: 100, Level: DegradationHealthy}
	}
	if now.IsZero() {
		now = time.Now()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.trimLocked(now)
	samples := append([]Sample(nil), e.samples...)
	snap := Snapshot{
		At:          now,
		Score:       100,
		Level:       DegradationHealthy,
		SampleCount: len(samples),
		Window:      e.cfg.Window,
	}
	if len(samples) == 0 {
		snap.Flags = []ReasonFlag{ReasonInsufficientConfidence}
		snap.Reasons = []Reason{{
			Flag:        ReasonInsufficientConfidence,
			Severity:    DegradationSuspect,
			Value:       0,
			Threshold:   float64(e.cfg.MinSamples),
			Sustained:   false,
			Description: "no recent transport samples",
			Penalty:     5,
		}}
		snap.Score = 95
		snap.Confidence = 0
		return snap
	}

	var (
		losses      []float64
		jitters     []float64
		rtts        []float64
		reorders    []float64
		ackDelays   []float64
		timeoutSum  float64
		lossSum     float64
		reorderSum  float64
		ackRatioSum float64
		sentSum     uint64
		ackedSum    uint64
		delivSum    uint64
		resumeFail  int
		resumeOK    int
		burstDrops  int
		pathFlaps   int
		recovery    int
		stalled     int
		ackStarved  int
	)
	for _, sample := range samples {
		if sample.ProfileID != "" {
			snap.ProfileID = sample.ProfileID
		}
		if sample.PathFamily != "" {
			snap.PathFamily = sample.PathFamily
		}
		if sample.LossRatio > 0 {
			losses = append(losses, sample.LossRatio)
		}
		if sample.JitterMs > 0 {
			jitters = append(jitters, sample.JitterMs)
		}
		if sample.RTTMs > 0 {
			rtts = append(rtts, sample.RTTMs)
		}
		if sample.ReorderRate > 0 {
			reorders = append(reorders, sample.ReorderRate)
		}
		if sample.AckDelayMs > 0 {
			ackDelays = append(ackDelays, sample.AckDelayMs)
		}
		lossSum += sample.LossRatio
		timeoutSum += sample.TimeoutRate
		reorderSum += sample.ReorderRate
		sentSum += sample.SentPackets
		ackedSum += sample.AckedPackets
		delivSum += sample.DeliveredPackets
		if sample.IdleResumeFailure {
			resumeFail++
		}
		if sample.IdleResumeSuccess {
			resumeOK++
		}
		if sample.BurstDrop {
			burstDrops++
		}
		if sample.PathFlap {
			pathFlaps++
		}
		if sample.RecoveryEvent {
			recovery++
		}
		if sample.ReceiveStalled {
			stalled++
		}
		if sample.AckStarved {
			ackStarved++
		}
	}

	avgLoss := lossSum / float64(len(samples))
	avgTimeout := timeoutSum / float64(len(samples))
	avgReorder := reorderSum / float64(len(samples))
	if sentSum > 0 {
		ackRatioSum = float64(ackedSum) / float64(sentSum)
	}
	deliveryRatio := 1.0
	if sentSum > 0 {
		deliveryRatio = float64(delivSum) / float64(sentSum)
	}
	p95Jitter := percentile(jitters, 0.95)
	p95RTT := percentile(rtts, 0.95)
	p95Ack := percentile(ackDelays, 0.95)
	rttDrift := 0.0
	if e.emaRTTMs > 0 && p95RTT > 0 {
		rttDrift = math.Max(0, p95RTT-e.emaRTTMs)
	}
	throughputRecent := recentAverage(samples)
	snap.LossRatio = avgLoss
	snap.TimeoutRate = avgTimeout
	snap.ReorderRate = avgReorder
	snap.JitterP95Ms = p95Jitter
	snap.RTTP95Ms = p95RTT
	snap.RTTDriftMs = rttDrift
	snap.AckDelayP95Ms = p95Ack
	snap.ThroughputEMA = e.emaThroughput
	snap.ThroughputRecent = throughputRecent
	snap.Confidence = math.Min(1, float64(len(samples))/float64(e.cfg.MinSamples))

	reasons := make([]Reason, 0, 12)
	addReason := func(flag ReasonFlag, severity DegradationLevel, value, threshold float64, sustained bool, penalty int, description string) {
		reasons = append(reasons, Reason{
			Flag:        flag,
			Severity:    severity,
			Value:       value,
			Threshold:   threshold,
			Sustained:   sustained,
			Description: description,
			Penalty:     penalty,
		})
	}

	if avgLoss >= e.cfg.LossCritical {
		addReason(ReasonHighLoss, DegradationCritical, avgLoss, e.cfg.LossCritical, true, 45, "packet loss is at critical level")
	} else if avgLoss >= e.cfg.LossDegraded {
		addReason(ReasonHighLoss, DegradationDegraded, avgLoss, e.cfg.LossDegraded, true, 28, "packet loss is persistently elevated")
	} else if avgLoss >= e.cfg.LossSuspect {
		addReason(ReasonHighLoss, DegradationSuspect, avgLoss, e.cfg.LossSuspect, false, 12, "packet loss is above the healthy envelope")
	}

	if p95Jitter >= e.cfg.JitterDegraded {
		addReason(ReasonHighJitter, DegradationDegraded, p95Jitter, e.cfg.JitterDegraded, true, 18, "jitter p95 is persistently high")
	} else if p95Jitter >= e.cfg.JitterSuspect {
		addReason(ReasonHighJitter, DegradationSuspect, p95Jitter, e.cfg.JitterSuspect, false, 8, "jitter spike detected")
	}

	if rttDrift >= e.cfg.RTTDriftCritical {
		addReason(ReasonPathInstability, DegradationCritical, rttDrift, e.cfg.RTTDriftCritical, true, 20, "RTT drift indicates path instability")
	} else if rttDrift >= e.cfg.RTTDriftSuspect {
		addReason(ReasonPathInstability, DegradationSuspect, rttDrift, e.cfg.RTTDriftSuspect, false, 8, "RTT drift is elevated")
	}

	if avgTimeout >= e.cfg.TimeoutDegraded {
		addReason(ReasonTimeoutPressure, DegradationDegraded, avgTimeout, e.cfg.TimeoutDegraded, true, 22, "timeouts are accumulating across the rolling window")
	} else if avgTimeout >= e.cfg.TimeoutSuspect {
		addReason(ReasonTimeoutPressure, DegradationSuspect, avgTimeout, e.cfg.TimeoutSuspect, false, 10, "timeouts are above baseline")
	}

	if resumeFail > 0 && resumeFail >= resumeOK {
		addReason(ReasonIdleResumeFailures, DegradationDegraded, float64(resumeFail), float64(resumeOK), resumeFail > 1, 14, "idle resume failures are outnumbering successful resumes")
	}

	if burstDrops > 0 {
		addReason(ReasonBurstSuppression, DegradationSuspect, float64(burstDrops), 1, burstDrops > 1, 8, "burst pattern losses detected")
	}

	if ackStarved > 0 {
		addReason(ReasonAckStarvation, DegradationDegraded, float64(ackStarved), 1, ackStarved > 1, 16, "ACK starvation observed")
	}

	if p95Ack >= e.cfg.AckDelayBudgetMs {
		addReason(ReasonAckDelayAnomaly, DegradationSuspect, p95Ack, e.cfg.AckDelayBudgetMs, len(ackDelays) >= e.cfg.MinSamples, 7, "ACK delay anomalies are visible")
	}

	if avgReorder >= e.cfg.ReorderSuspect {
		addReason(ReasonReorderRate, DegradationSuspect, avgReorder, e.cfg.ReorderSuspect, len(reorders) >= e.cfg.MinSamples, 6, "packet reorder rate is elevated")
	}

	if stalled > 0 {
		addReason(ReasonReceiveStall, DegradationDegraded, float64(stalled), 1, stalled > 1, 14, "receive window stalled during the rolling window")
	}

	if pathFlaps > 0 {
		addReason(ReasonPathInstability, DegradationDegraded, float64(pathFlaps), 1, pathFlaps > 1, 15, "path flapping detected")
	}

	if recovery > 0 {
		addReason(ReasonRecoveryEvents, DegradationSuspect, float64(recovery), 1, recovery > 1, 6, "recovery events are recurring")
	}

	if deliveryRatio < 0.85 || ackRatioSum < 0.85 {
		addReason(ReasonDeliveryPressure, DegradationDegraded, math.Min(deliveryRatio, ackRatioSum), 0.85, true, 14, "delivered/acked ratio is collapsing")
	}

	if e.emaThroughput > 0 && throughputRecent > 0 && throughputRecent < e.emaThroughput*e.cfg.ThroughputCollapseRatio {
		addReason(ReasonThroughputCollapse, DegradationDegraded, throughputRecent, e.emaThroughput*e.cfg.ThroughputCollapseRatio, len(samples) >= e.cfg.MinSamples, 16, "throughput collapsed relative to the rolling baseline")
	}

	if len(samples) < e.cfg.MinSamples {
		addReason(ReasonInsufficientConfidence, DegradationSuspect, float64(len(samples)), float64(e.cfg.MinSamples), false, 6, "sample count is too low for a confident decision")
	}

	sort.SliceStable(reasons, func(i, j int) bool {
		if reasons[i].Penalty == reasons[j].Penalty {
			return reasons[i].Flag < reasons[j].Flag
		}
		return reasons[i].Penalty > reasons[j].Penalty
	})

	score := 100
	flags := make([]ReasonFlag, 0, len(reasons))
	level := DegradationHealthy
	for _, reason := range reasons {
		score -= reason.Penalty
		flags = append(flags, reason.Flag)
		if severityRank(reason.Severity) > severityRank(level) {
			level = reason.Severity
		}
	}
	if score < 0 {
		score = 0
	}
	if score >= 85 && level == DegradationHealthy {
		level = DegradationHealthy
	} else if score >= 65 && severityRank(level) < severityRank(DegradationSuspect) {
		level = DegradationSuspect
	} else if score >= 40 && severityRank(level) < severityRank(DegradationDegraded) {
		level = DegradationDegraded
	} else if score < 40 {
		level = DegradationCritical
	}

	snap.Score = score
	snap.Level = level
	snap.Flags = flags
	snap.Reasons = reasons
	return snap
}

func (e *Engine) trimLocked(now time.Time) {
	if len(e.samples) == 0 {
		return
	}
	cutoff := now.Add(-e.cfg.Window)
	keep := e.samples[:0]
	for _, sample := range e.samples {
		if sample.At.After(cutoff) || sample.At.Equal(cutoff) {
			keep = append(keep, sample)
		}
	}
	e.samples = keep
}

func ema(prev, next, alpha float64) float64 {
	if next <= 0 {
		return prev
	}
	if prev <= 0 {
		return next
	}
	return (alpha * next) + ((1 - alpha) * prev)
}

func percentile(values []float64, q float64) float64 {
	if len(values) == 0 {
		return 0
	}
	cp := append([]float64(nil), values...)
	sort.Float64s(cp)
	if q <= 0 {
		return cp[0]
	}
	if q >= 1 {
		return cp[len(cp)-1]
	}
	idx := int(math.Ceil(float64(len(cp))*q)) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(cp) {
		idx = len(cp) - 1
	}
	return cp[idx]
}

func recentAverage(samples []Sample) float64 {
	if len(samples) == 0 {
		return 0
	}
	var total float64
	var count int
	start := len(samples) - 5
	if start < 0 {
		start = 0
	}
	for _, sample := range samples[start:] {
		if sample.ThroughputBps <= 0 {
			continue
		}
		total += sample.ThroughputBps
		count++
	}
	if count == 0 {
		return 0
	}
	return total / float64(count)
}

func severityRank(level DegradationLevel) int {
	switch level {
	case DegradationCritical:
		return 4
	case DegradationDegraded:
		return 3
	case DegradationSuspect:
		return 2
	default:
		return 1
	}
}
