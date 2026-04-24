package migration

import (
	"context"
	"fmt"
	"sync"
	"time"

	"vlf-runtime/internal/transport/health"
	"vlf-runtime/internal/transport/profile"
)

type PathInfo struct {
	Family           string
	PreferLowObserve bool
	LatencySensitive bool
	BulkLike         bool
	DegradedPathOK   bool
}

type Decision struct {
	CurrentProfile string
	NextProfile    string
	Action         string
	Reason         string
	Cooldown       bool
}

type MigrationResult struct {
	FromProfile string
	ToProfile   string
	AppliedAt   time.Time
	Reverted    bool
	Err         error
}

type ProfileMigrator interface {
	ApplyTransportProfile(context.Context, string) error
}

type Config struct {
	Cooldown            time.Duration
	MaxSwitchesPerHour  int
	FailureMemoryWindow time.Duration
	Now                 func() time.Time
}

type Scheduler struct {
	cfg      Config
	registry *profile.Registry

	mu            sync.Mutex
	lastSwitchAt  time.Time
	lastSwitchKey string
	switchHistory []time.Time
	failures      map[string]time.Time
}

type Snapshot struct {
	LastSwitchAt      time.Time
	LastSwitchKey     string
	CooldownRemaining time.Duration
}

func DefaultConfig() Config {
	return Config{
		Cooldown:            45 * time.Second,
		MaxSwitchesPerHour:  6,
		FailureMemoryWindow: 20 * time.Minute,
		Now:                 time.Now,
	}
}

func NewScheduler(cfg Config, registry *profile.Registry) *Scheduler {
	def := DefaultConfig()
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = def.Cooldown
	}
	if cfg.MaxSwitchesPerHour <= 0 {
		cfg.MaxSwitchesPerHour = def.MaxSwitchesPerHour
	}
	if cfg.FailureMemoryWindow <= 0 {
		cfg.FailureMemoryWindow = def.FailureMemoryWindow
	}
	if cfg.Now == nil {
		cfg.Now = def.Now
	}
	if registry == nil {
		registry = profile.DefaultRegistry()
	}
	return &Scheduler{
		cfg:      cfg,
		registry: registry,
		failures: make(map[string]time.Time),
	}
}

func (s *Scheduler) EvaluateProfileHealth(snapshot health.Snapshot) Decision {
	switch snapshot.Level {
	case health.DegradationCritical:
		return Decision{Action: "degraded", Reason: "critical_profile_health"}
	case health.DegradationDegraded:
		return Decision{Action: "degraded", Reason: "degraded_profile_health"}
	case health.DegradationSuspect:
		return Decision{Action: "observe", Reason: "suspect_profile_health"}
	default:
		return Decision{Action: "keep", Reason: "profile_healthy"}
	}
}

func (s *Scheduler) ChooseNextProfile(current string, snapshot health.Snapshot, path PathInfo, now time.Time) Decision {
	if s == nil {
		return Decision{CurrentProfile: current, NextProfile: current, Action: "keep", Reason: "scheduler_nil"}
	}
	if now.IsZero() {
		now = s.cfg.Now()
	}
	if current == "" {
		current = profile.ProfileBalanced
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.trimLocked(now)
	if !s.lastSwitchAt.IsZero() && now.Sub(s.lastSwitchAt) < s.cfg.Cooldown {
		return Decision{
			CurrentProfile: current,
			NextProfile:    current,
			Action:         "keep",
			Reason:         "switch_cooldown_active",
			Cooldown:       true,
		}
	}
	if len(s.switchHistory) >= s.cfg.MaxSwitchesPerHour {
		return Decision{
			CurrentProfile: current,
			NextProfile:    current,
			Action:         "keep",
			Reason:         "switch_rate_limited",
		}
	}

	candidates := s.registry.NextCandidates(current)
	bestScore := -1 << 30
	bestProfile := current
	bestReason := "current_profile_preferred"
	for _, candidate := range candidates {
		score, reason := s.scoreCandidate(current, candidate, snapshot, path, now)
		if score > bestScore {
			bestScore = score
			bestProfile = candidate.ID
			bestReason = reason
		}
	}

	if bestProfile == "" || bestProfile == current || bestScore <= 0 {
		return Decision{
			CurrentProfile: current,
			NextProfile:    current,
			Action:         "keep",
			Reason:         "no_better_profile_candidate",
		}
	}

	return Decision{
		CurrentProfile: current,
		NextProfile:    bestProfile,
		Action:         "switch",
		Reason:         bestReason,
	}
}

func (s *Scheduler) RecordSwitchResult(from, to string, ok bool, reverted bool, now time.Time) {
	if s == nil {
		return
	}
	if now.IsZero() {
		now = s.cfg.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSwitchAt = now
	s.lastSwitchKey = from + "->" + to
	s.switchHistory = append(s.switchHistory, now)
	if !ok || reverted {
		s.failures[s.historyKey(to, "")] = now
	}
	s.trimLocked(now)
}

func (s *Scheduler) Snapshot(now time.Time) Snapshot {
	if s == nil {
		return Snapshot{}
	}
	if now.IsZero() {
		now = s.cfg.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	remaining := time.Duration(0)
	if !s.lastSwitchAt.IsZero() {
		if delta := s.cfg.Cooldown - now.Sub(s.lastSwitchAt); delta > 0 {
			remaining = delta
		}
	}
	return Snapshot{
		LastSwitchAt:      s.lastSwitchAt,
		LastSwitchKey:     s.lastSwitchKey,
		CooldownRemaining: remaining,
	}
}

func (s *Scheduler) AttemptProfileMigration(ctx context.Context, migrator ProfileMigrator, current, next string) MigrationResult {
	result := MigrationResult{
		FromProfile: current,
		ToProfile:   next,
		AppliedAt:   s.cfg.Now(),
	}
	if migrator == nil {
		result.Err = fmt.Errorf("profile migrator is nil")
		return result
	}
	if next == "" || next == current {
		return result
	}
	if err := migrator.ApplyTransportProfile(ctx, next); err != nil {
		result.Err = err
		return result
	}
	return result
}

func (s *Scheduler) scoreCandidate(current string, candidate profile.TransportProfile, snapshot health.Snapshot, path PathInfo, now time.Time) (int, string) {
	score := candidate.Priority
	reason := "priority"

	if ts, ok := s.failures[s.historyKey(candidate.ID, path.Family)]; ok && now.Sub(ts) < s.cfg.FailureMemoryWindow {
		score -= 60
		reason = "profile_recent_failure_memory"
	}

	switch snapshot.Level {
	case health.DegradationCritical:
		if candidate.ID == profile.ProfileSurvival {
			score += 300
			reason = "critical_health_prefers_survival"
		}
	case health.DegradationDegraded:
		if hasFlag(snapshot, health.ReasonHighJitter) || hasFlag(snapshot, health.ReasonBurstSuppression) || hasFlag(snapshot, health.ReasonAckStarvation) {
			if candidate.ID == profile.ProfileLowObservable {
				score += 180
				reason = "jitter_or_burst_prefers_low_observable"
			}
		}
		if hasFlag(snapshot, health.ReasonHighLoss) || hasFlag(snapshot, health.ReasonTimeoutPressure) {
			if candidate.ID == profile.ProfileSurvival {
				score += 220
				reason = "loss_or_timeout_prefers_survival"
			}
		}
	default:
		if current == profile.ProfileSurvival && candidate.ID == profile.ProfileBalanced && snapshot.Level == health.DegradationHealthy {
			score += 140
			reason = "healthy_recovery_prefers_balanced"
		}
	}

	if path.PreferLowObserve && candidate.ID == profile.ProfileLowObservable {
		score += 75
		reason = "path_prefers_low_observable"
	}
	if path.LatencySensitive && candidate.ID == profile.ProfileBalanced {
		score += 40
		reason = "latency_sensitive_prefers_balanced"
	}
	if path.BulkLike && candidate.ID == profile.ProfileBalanced {
		score += 25
		reason = "bulk_prefers_balanced"
	}
	if !path.DegradedPathOK && candidate.ID == profile.ProfileSurvival {
		score -= 20
	}

	return score, reason
}

func (s *Scheduler) historyKey(profileID, pathFamily string) string {
	return profileID + "|" + pathFamily
}

func (s *Scheduler) trimLocked(now time.Time) {
	cutoff := now.Add(-time.Hour)
	kept := s.switchHistory[:0]
	for _, ts := range s.switchHistory {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	s.switchHistory = kept

	for key, ts := range s.failures {
		if now.Sub(ts) >= s.cfg.FailureMemoryWindow {
			delete(s.failures, key)
		}
	}
}

func hasFlag(snapshot health.Snapshot, flag health.ReasonFlag) bool {
	for _, item := range snapshot.Flags {
		if item == flag {
			return true
		}
	}
	return false
}
