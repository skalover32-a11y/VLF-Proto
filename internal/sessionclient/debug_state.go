package sessionclient

import (
	"encoding/json"
	"sync"
	"time"

	"vlf-runtime/internal/transport/health"
)

type ResumePath string

const (
	ResumePathUnknown        ResumePath = "unknown"
	ResumePathFullAuth       ResumePath = "full_auth"
	ResumePathResumeFastPath ResumePath = "resume_fast_path"
	ResumePathLegacyFallback ResumePath = "legacy_fallback"
)

type DebugSnapshot struct {
	Transport                      Transport                `json:"transport"`
	ActiveProfile                  string                   `json:"active_profile"`
	HealthScore                    int                      `json:"health_score"`
	DegradationLevel               health.DegradationLevel  `json:"degradation_level"`
	DegradationReasonFlags         []health.ReasonFlag      `json:"degradation_reason_flags,omitempty"`
	MigrationAttempts              uint64                   `json:"migration_attempts"`
	MigrationSuccesses             uint64                   `json:"migration_successes"`
	MigrationReverts               uint64                   `json:"migration_reverts"`
	LastMigrationReason            string                   `json:"last_migration_reason,omitempty"`
	LastMigrationAttemptAt         time.Time                `json:"last_migration_attempt_at,omitempty"`
	LastMigrationSuccessAt         time.Time                `json:"last_migration_success_at,omitempty"`
	MigrationCooldownRemaining     time.Duration            `json:"migration_cooldown_remaining"`
	MigrationCooldownActive        bool                     `json:"migration_cooldown_active"`
	ResumePath                     ResumePath               `json:"resume_path"`
	LegacyPeerFallback             bool                     `json:"legacy_peer_fallback"`
	ProfileSwitchUnsupported       bool                     `json:"profile_switch_unsupported"`
	ProfileSwitchUnsupportedReason string                   `json:"profile_switch_unsupported_reason,omitempty"`
	TimeSpentPerProfile            map[string]time.Duration `json:"time_spent_per_profile,omitempty"`
	SessionLease                   SessionLease             `json:"session_lease,omitempty"`
	HasSessionLease                bool                     `json:"has_session_lease"`
	SessionUnusable                SessionUnusableState     `json:"session_unusable,omitempty"`
	HasSessionUnusable             bool                     `json:"has_session_unusable"`
}

type clientDebugState struct {
	mu                             sync.Mutex
	currentProfile                 string
	currentProfileSince            time.Time
	timeSpentPerProfile            map[string]time.Duration
	migrationAttempts              uint64
	migrationSuccesses             uint64
	migrationReverts               uint64
	lastMigrationReason            string
	lastMigrationAttemptAt         time.Time
	lastMigrationSuccessAt         time.Time
	resumePath                     ResumePath
	legacyPeerFallback             bool
	profileSwitchUnsupported       bool
	profileSwitchUnsupportedReason string
}

func (s *clientDebugState) init(profileID string, now time.Time) {
	if now.IsZero() {
		now = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timeSpentPerProfile == nil {
		s.timeSpentPerProfile = make(map[string]time.Duration)
	}
	if s.currentProfile == "" {
		s.currentProfile = profileID
		s.currentProfileSince = now
	}
	if s.resumePath == "" {
		s.resumePath = ResumePathFullAuth
	}
}

func (s *clientDebugState) noteProfile(profileID string, now time.Time) {
	if profileID == "" {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timeSpentPerProfile == nil {
		s.timeSpentPerProfile = make(map[string]time.Duration)
	}
	if s.currentProfile == "" {
		s.currentProfile = profileID
		s.currentProfileSince = now
		return
	}
	if s.currentProfile == profileID {
		return
	}
	if !s.currentProfileSince.IsZero() {
		s.timeSpentPerProfile[s.currentProfile] += now.Sub(s.currentProfileSince)
	}
	s.currentProfile = profileID
	s.currentProfileSince = now
}

func (s *clientDebugState) setResumePath(path ResumePath) {
	if path == "" {
		return
	}
	s.mu.Lock()
	s.resumePath = path
	s.mu.Unlock()
}

func (s *clientDebugState) markLegacyFallback(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.legacyPeerFallback = true
	s.resumePath = ResumePathLegacyFallback
	if s.profileSwitchUnsupportedReason == "" {
		s.profileSwitchUnsupportedReason = normalizeUnsupportedProfileReason(reason)
	}
	s.profileSwitchUnsupported = true
}

func (s *clientDebugState) markProfileSwitchUnsupported(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.profileSwitchUnsupported = true
	s.profileSwitchUnsupportedReason = normalizeUnsupportedProfileReason(reason)
}

func (s *clientDebugState) profileSwitchUnsupportedState() (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.profileSwitchUnsupported, s.profileSwitchUnsupportedReason
}

func (s *clientDebugState) noteMigrationAttempt(reason string, now time.Time) {
	if now.IsZero() {
		now = time.Now()
	}
	s.mu.Lock()
	s.migrationAttempts++
	s.lastMigrationReason = reason
	s.lastMigrationAttemptAt = now
	s.mu.Unlock()
}

func (s *clientDebugState) noteMigrationSuccess(now time.Time) {
	if now.IsZero() {
		now = time.Now()
	}
	s.mu.Lock()
	s.migrationSuccesses++
	s.lastMigrationSuccessAt = now
	s.mu.Unlock()
}

func (s *clientDebugState) noteMigrationRevert(now time.Time) {
	if now.IsZero() {
		now = time.Now()
	}
	s.mu.Lock()
	s.migrationReverts++
	s.mu.Unlock()
}

func (s *clientDebugState) snapshot(now time.Time) DebugSnapshot {
	if now.IsZero() {
		now = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	timeSpent := make(map[string]time.Duration, len(s.timeSpentPerProfile)+1)
	for key, value := range s.timeSpentPerProfile {
		timeSpent[key] = value
	}
	if s.currentProfile != "" && !s.currentProfileSince.IsZero() {
		timeSpent[s.currentProfile] += now.Sub(s.currentProfileSince)
	}
	return DebugSnapshot{
		ActiveProfile:                  s.currentProfile,
		MigrationAttempts:              s.migrationAttempts,
		MigrationSuccesses:             s.migrationSuccesses,
		MigrationReverts:               s.migrationReverts,
		LastMigrationReason:            s.lastMigrationReason,
		LastMigrationAttemptAt:         s.lastMigrationAttemptAt,
		LastMigrationSuccessAt:         s.lastMigrationSuccessAt,
		ResumePath:                     s.resumePath,
		LegacyPeerFallback:             s.legacyPeerFallback,
		ProfileSwitchUnsupported:       s.profileSwitchUnsupported,
		ProfileSwitchUnsupportedReason: s.profileSwitchUnsupportedReason,
		TimeSpentPerProfile:            timeSpent,
	}
}

func MarshalDebugSnapshot(snapshot DebugSnapshot) ([]byte, error) {
	return json.MarshalIndent(snapshot, "", "  ")
}
