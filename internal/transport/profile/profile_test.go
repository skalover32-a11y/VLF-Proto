package profile

import "testing"

func TestDefaultRegistryContainsRequiredProfiles(t *testing.T) {
	reg := DefaultRegistry()
	for _, id := range []string{ProfileBalanced, ProfileLowObservable, ProfileSurvival} {
		if _, ok := reg.Get(id); !ok {
			t.Fatalf("missing profile %q", id)
		}
	}
}

func TestEffectiveDatagramPayloadHonorsConfiguredCap(t *testing.T) {
	profile, ok := DefaultRegistry().Get(ProfileBalanced)
	if !ok {
		t.Fatal("balanced profile missing")
	}
	if got := profile.EffectiveDatagramPayload(900); got != 900 {
		t.Fatalf("payload=%d, want 900", got)
	}
	if got := profile.EffectiveDatagramPayload(0); got != profile.PacketSizeStrategy.MaxDatagramPayload {
		t.Fatalf("payload=%d, want %d", got, profile.PacketSizeStrategy.MaxDatagramPayload)
	}
}
