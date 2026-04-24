package profile

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type Family string

const (
	FamilyQUICLike      Family = "quic_like"
	FamilyUDPBurst      Family = "udp_burst"
	FamilySteadyLowRate Family = "steady_lowrate"
	FamilySurvival      Family = "survival"
)

const (
	ProfileBalanced      = "balanced"
	ProfileLowObservable = "low_observable"
	ProfileSurvival      = "survival"
)

type PacketSizeStrategy struct {
	MaxDatagramPayload int
	PaddingTargetBytes int
	SizeJitterBytes    int
}

type InterPacketTimingStrategy struct {
	BaseGap       time.Duration
	GapJitter     time.Duration
	BurstCooldown time.Duration
}

type KeepAliveStrategy struct {
	Interval time.Duration
	IdleOnly bool
}

type IdleResumeStrategy struct {
	ProbeAfterIdle           time.Duration
	ProactiveRenewBefore     time.Duration
	ResumeCooldown           time.Duration
	SuppressAggressiveResume bool
}

type BurstStrategy struct {
	MaxPacketsPerBurst int
	MaxBytesPerBurst   int
}

type PaddingPolicy struct {
	Enabled         bool
	MaxPaddingBytes int
}

type CoalescingPolicy struct {
	Enabled       bool
	MaxFrames     int
	FlushInterval time.Duration
}

type AckHintPolicy struct {
	Enabled        bool
	ExpectedAckGap time.Duration
	AckDelayBudget time.Duration
}

type RetryPolicy struct {
	OpenBackoff          time.Duration
	ProbeBackoff         time.Duration
	MaxSequentialFailure int
}

type PathConstraints struct {
	PreferUDP         bool
	AllowDegradedPath bool
	AllowTCPSession   bool
	AllowRelay        bool
}

type TransportProfile struct {
	ID                        string
	Family                    Family
	Priority                  int
	PacketSizeStrategy        PacketSizeStrategy
	InterPacketTimingStrategy InterPacketTimingStrategy
	KeepAliveStrategy         KeepAliveStrategy
	IdleResumeStrategy        IdleResumeStrategy
	BurstStrategy             BurstStrategy
	PaddingPolicy             PaddingPolicy
	CoalescingPolicy          CoalescingPolicy
	AckHintPolicy             AckHintPolicy
	RetryPolicy               RetryPolicy
	PathConstraints           PathConstraints
}

func DefaultProfiles() []TransportProfile {
	return []TransportProfile{
		{
			ID:                        ProfileBalanced,
			Family:                    FamilyQUICLike,
			Priority:                  100,
			PacketSizeStrategy:        PacketSizeStrategy{MaxDatagramPayload: 1180, PaddingTargetBytes: 0, SizeJitterBytes: 32},
			InterPacketTimingStrategy: InterPacketTimingStrategy{BaseGap: 0, GapJitter: 0, BurstCooldown: 250 * time.Microsecond},
			KeepAliveStrategy:         KeepAliveStrategy{Interval: 12 * time.Second},
			IdleResumeStrategy:        IdleResumeStrategy{ProbeAfterIdle: 12 * time.Second, ProactiveRenewBefore: 5 * time.Second, ResumeCooldown: 2 * time.Second},
			BurstStrategy:             BurstStrategy{MaxPacketsPerBurst: 4, MaxBytesPerBurst: 4 * 1180},
			PaddingPolicy:             PaddingPolicy{Enabled: false, MaxPaddingBytes: 0},
			CoalescingPolicy:          CoalescingPolicy{Enabled: true, MaxFrames: 4, FlushInterval: 2 * time.Millisecond},
			AckHintPolicy:             AckHintPolicy{Enabled: true, ExpectedAckGap: 250 * time.Millisecond, AckDelayBudget: 25 * time.Millisecond},
			RetryPolicy:               RetryPolicy{OpenBackoff: 800 * time.Millisecond, ProbeBackoff: 1500 * time.Millisecond, MaxSequentialFailure: 3},
			PathConstraints:           PathConstraints{PreferUDP: true, AllowDegradedPath: true, AllowTCPSession: true, AllowRelay: true},
		},
		{
			ID:                        ProfileLowObservable,
			Family:                    FamilySteadyLowRate,
			Priority:                  80,
			PacketSizeStrategy:        PacketSizeStrategy{MaxDatagramPayload: 960, PaddingTargetBytes: 0, SizeJitterBytes: 16},
			InterPacketTimingStrategy: InterPacketTimingStrategy{BaseGap: 1500 * time.Microsecond, GapJitter: 800 * time.Microsecond, BurstCooldown: 2 * time.Millisecond},
			KeepAliveStrategy:         KeepAliveStrategy{Interval: 20 * time.Second, IdleOnly: true},
			IdleResumeStrategy:        IdleResumeStrategy{ProbeAfterIdle: 20 * time.Second, ProactiveRenewBefore: 8 * time.Second, ResumeCooldown: 4 * time.Second, SuppressAggressiveResume: true},
			BurstStrategy:             BurstStrategy{MaxPacketsPerBurst: 2, MaxBytesPerBurst: 2 * 960},
			PaddingPolicy:             PaddingPolicy{Enabled: true, MaxPaddingBytes: 24},
			CoalescingPolicy:          CoalescingPolicy{Enabled: true, MaxFrames: 2, FlushInterval: 4 * time.Millisecond},
			AckHintPolicy:             AckHintPolicy{Enabled: true, ExpectedAckGap: 350 * time.Millisecond, AckDelayBudget: 35 * time.Millisecond},
			RetryPolicy:               RetryPolicy{OpenBackoff: 1200 * time.Millisecond, ProbeBackoff: 2 * time.Second, MaxSequentialFailure: 2},
			PathConstraints:           PathConstraints{PreferUDP: true, AllowDegradedPath: true, AllowTCPSession: true, AllowRelay: true},
		},
		{
			ID:                        ProfileSurvival,
			Family:                    FamilySurvival,
			Priority:                  60,
			PacketSizeStrategy:        PacketSizeStrategy{MaxDatagramPayload: 820, PaddingTargetBytes: 0, SizeJitterBytes: 8},
			InterPacketTimingStrategy: InterPacketTimingStrategy{BaseGap: 3 * time.Millisecond, GapJitter: 2 * time.Millisecond, BurstCooldown: 5 * time.Millisecond},
			KeepAliveStrategy:         KeepAliveStrategy{Interval: 8 * time.Second, IdleOnly: false},
			IdleResumeStrategy:        IdleResumeStrategy{ProbeAfterIdle: 8 * time.Second, ProactiveRenewBefore: 12 * time.Second, ResumeCooldown: 6 * time.Second, SuppressAggressiveResume: true},
			BurstStrategy:             BurstStrategy{MaxPacketsPerBurst: 1, MaxBytesPerBurst: 820},
			PaddingPolicy:             PaddingPolicy{Enabled: false, MaxPaddingBytes: 0},
			CoalescingPolicy:          CoalescingPolicy{Enabled: false, MaxFrames: 1, FlushInterval: time.Millisecond},
			AckHintPolicy:             AckHintPolicy{Enabled: true, ExpectedAckGap: 500 * time.Millisecond, AckDelayBudget: 45 * time.Millisecond},
			RetryPolicy:               RetryPolicy{OpenBackoff: 1500 * time.Millisecond, ProbeBackoff: 2500 * time.Millisecond, MaxSequentialFailure: 1},
			PathConstraints:           PathConstraints{PreferUDP: true, AllowDegradedPath: true, AllowTCPSession: true, AllowRelay: true},
		},
	}
}

type Registry struct {
	profiles map[string]TransportProfile
	ordered  []TransportProfile
}

func NewRegistry(extra []TransportProfile) *Registry {
	items := append([]TransportProfile(nil), DefaultProfiles()...)
	items = append(items, extra...)

	profiles := make(map[string]TransportProfile, len(items))
	for _, item := range items {
		normalized := item.normalize()
		profiles[normalized.ID] = normalized
	}

	ordered := make([]TransportProfile, 0, len(profiles))
	for _, item := range profiles {
		ordered = append(ordered, item)
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Priority == ordered[j].Priority {
			return ordered[i].ID < ordered[j].ID
		}
		return ordered[i].Priority > ordered[j].Priority
	})

	return &Registry{profiles: profiles, ordered: ordered}
}

func DefaultRegistry() *Registry {
	return NewRegistry(nil)
}

func (r *Registry) List() []TransportProfile {
	if r == nil {
		return nil
	}
	out := make([]TransportProfile, len(r.ordered))
	copy(out, r.ordered)
	return out
}

func (r *Registry) Get(id string) (TransportProfile, bool) {
	if r == nil {
		return TransportProfile{}, false
	}
	profile, ok := r.profiles[strings.TrimSpace(strings.ToLower(id))]
	return profile, ok
}

func (r *Registry) MustGetOrDefault(id string) TransportProfile {
	if r == nil {
		return DefaultRegistry().MustGetOrDefault(id)
	}
	if profile, ok := r.Get(id); ok {
		return profile
	}
	profile, _ := r.Get(ProfileBalanced)
	return profile
}

func (r *Registry) NextCandidates(current string) []TransportProfile {
	current = strings.TrimSpace(strings.ToLower(current))
	out := make([]TransportProfile, 0, len(r.ordered))
	for _, item := range r.ordered {
		if item.ID == current {
			continue
		}
		out = append(out, item)
	}
	return out
}

func (p TransportProfile) normalize() TransportProfile {
	if p.ID == "" {
		p.ID = ProfileBalanced
	}
	p.ID = strings.TrimSpace(strings.ToLower(p.ID))
	if p.Family == "" {
		p.Family = FamilyQUICLike
	}
	if p.PacketSizeStrategy.MaxDatagramPayload <= 0 {
		p.PacketSizeStrategy.MaxDatagramPayload = 1180
	}
	if p.BurstStrategy.MaxPacketsPerBurst <= 0 {
		p.BurstStrategy.MaxPacketsPerBurst = 1
	}
	if p.BurstStrategy.MaxBytesPerBurst <= 0 {
		p.BurstStrategy.MaxBytesPerBurst = p.BurstStrategy.MaxPacketsPerBurst * p.PacketSizeStrategy.MaxDatagramPayload
	}
	if p.KeepAliveStrategy.Interval <= 0 {
		p.KeepAliveStrategy.Interval = 12 * time.Second
	}
	if p.IdleResumeStrategy.ProbeAfterIdle <= 0 {
		p.IdleResumeStrategy.ProbeAfterIdle = 12 * time.Second
	}
	if p.IdleResumeStrategy.ProactiveRenewBefore <= 0 {
		p.IdleResumeStrategy.ProactiveRenewBefore = 5 * time.Second
	}
	if p.IdleResumeStrategy.ResumeCooldown <= 0 {
		p.IdleResumeStrategy.ResumeCooldown = 2 * time.Second
	}
	if p.CoalescingPolicy.MaxFrames <= 0 {
		p.CoalescingPolicy.MaxFrames = 1
	}
	if p.RetryPolicy.OpenBackoff <= 0 {
		p.RetryPolicy.OpenBackoff = 800 * time.Millisecond
	}
	if p.RetryPolicy.ProbeBackoff <= 0 {
		p.RetryPolicy.ProbeBackoff = 1500 * time.Millisecond
	}
	if p.RetryPolicy.MaxSequentialFailure <= 0 {
		p.RetryPolicy.MaxSequentialFailure = 1
	}
	return p
}

func (p TransportProfile) EffectiveDatagramPayload(configuredMax int) int {
	maxPayload := p.PacketSizeStrategy.MaxDatagramPayload
	if configuredMax > 0 && (maxPayload <= 0 || configuredMax < maxPayload) {
		maxPayload = configuredMax
	}
	if maxPayload <= 0 {
		return 1180
	}
	return maxPayload
}

func (p TransportProfile) Validate() error {
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("transport profile id is required")
	}
	if p.PacketSizeStrategy.MaxDatagramPayload < 256 {
		return fmt.Errorf("transport profile %s max_datagram_payload must be >= 256", p.ID)
	}
	if p.KeepAliveStrategy.Interval <= 0 {
		return fmt.Errorf("transport profile %s keepalive interval must be > 0", p.ID)
	}
	return nil
}
