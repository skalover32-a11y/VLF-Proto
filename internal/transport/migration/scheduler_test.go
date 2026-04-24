package migration

import (
	"context"
	"testing"
	"time"

	"vlf-runtime/internal/transport/health"
	"vlf-runtime/internal/transport/profile"
)

type stubMigrator struct {
	applied string
	err     error
}

func (s *stubMigrator) ApplyTransportProfile(_ context.Context, id string) error {
	s.applied = id
	return s.err
}

func TestChooseNextProfilePrefersLowObservableOnJitter(t *testing.T) {
	scheduler := NewScheduler(Config{Now: func() time.Time { return time.Unix(1700000000, 0) }}, profile.DefaultRegistry())
	decision := scheduler.ChooseNextProfile(profile.ProfileBalanced, health.Snapshot{
		Level: health.DegradationDegraded,
		Flags: []health.ReasonFlag{health.ReasonHighJitter},
	}, PathInfo{}, time.Unix(1700000000, 0))
	if decision.NextProfile != profile.ProfileLowObservable {
		t.Fatalf("next_profile=%s, want %s", decision.NextProfile, profile.ProfileLowObservable)
	}
}

func TestChooseNextProfilePrefersSurvivalOnCriticalLoss(t *testing.T) {
	scheduler := NewScheduler(Config{Now: func() time.Time { return time.Unix(1700000000, 0) }}, profile.DefaultRegistry())
	decision := scheduler.ChooseNextProfile(profile.ProfileBalanced, health.Snapshot{
		Level: health.DegradationCritical,
		Flags: []health.ReasonFlag{health.ReasonHighLoss},
	}, PathInfo{}, time.Unix(1700000000, 0))
	if decision.NextProfile != profile.ProfileSurvival {
		t.Fatalf("next_profile=%s, want %s", decision.NextProfile, profile.ProfileSurvival)
	}
}

func TestSwitchCooldownSuppressesSpam(t *testing.T) {
	now := time.Unix(1700000000, 0)
	scheduler := NewScheduler(Config{Cooldown: time.Minute, Now: func() time.Time { return now }}, profile.DefaultRegistry())
	scheduler.RecordSwitchResult(profile.ProfileBalanced, profile.ProfileLowObservable, true, false, now)
	decision := scheduler.ChooseNextProfile(profile.ProfileLowObservable, health.Snapshot{
		Level: health.DegradationCritical,
		Flags: []health.ReasonFlag{health.ReasonHighLoss},
	}, PathInfo{}, now.Add(10*time.Second))
	if !decision.Cooldown {
		t.Fatalf("cooldown=false, want true")
	}
}

func TestAttemptProfileMigrationReturnsResult(t *testing.T) {
	scheduler := NewScheduler(Config{}, profile.DefaultRegistry())
	migrator := &stubMigrator{}
	result := scheduler.AttemptProfileMigration(context.Background(), migrator, profile.ProfileBalanced, profile.ProfileLowObservable)
	if result.Err != nil {
		t.Fatalf("err=%v", result.Err)
	}
	if migrator.applied != profile.ProfileLowObservable {
		t.Fatalf("applied=%s, want %s", migrator.applied, profile.ProfileLowObservable)
	}
}
