//go:build windows

package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"vlf-runtime/internal/sessionclient"
)

func TestParseResolver(t *testing.T) {
	tests := []struct {
		in        string
		host      string
		port      int
		shouldErr bool
	}{
		{in: "1.1.1.1:53", host: "1.1.1.1", port: 53},
		{in: "8.8.8.8", host: "8.8.8.8", port: 53},
		{in: "dns.google:5353", host: "dns.google", port: 5353},
		{in: "", shouldErr: true},
	}

	for _, tc := range tests {
		host, port, err := parseResolver(tc.in)
		if tc.shouldErr {
			if err == nil {
				t.Fatalf("parseResolver(%q) expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseResolver(%q) unexpected error: %v", tc.in, err)
		}
		if host != tc.host || port != tc.port {
			t.Fatalf("parseResolver(%q) got %s:%d want %s:%d", tc.in, host, port, tc.host, tc.port)
		}
	}
}

func TestDialConfigUDPForcesQUIC(t *testing.T) {
	c := newPolicyController(sessionclient.Config{
		PreferQUIC:        false,
		DisableQUIC:       true,
		DisableTCPSession: false,
		AllowRelay:        true,
	}, modeNormal, statsFormatText)
	defer c.Close()

	cfg, _ := c.dialConfigUDP()
	if !cfg.PreferQUIC {
		t.Fatal("dialConfigUDP must prefer QUIC")
	}
	if cfg.DisableQUIC {
		t.Fatal("dialConfigUDP must enable QUIC")
	}
	if !cfg.DisableTCPSession {
		t.Fatal("dialConfigUDP must disable TCP session")
	}
	if cfg.AllowRelay {
		t.Fatal("dialConfigUDP must disable relay")
	}
}

func TestUDPManagerDefaultIdleTimeout(t *testing.T) {
	c := newPolicyController(sessionclient.Config{}, modeAuto, statsFormatText)
	defer c.Close()

	m := newUDPManager(c, 2*time.Second, udpOptions{})
	defer m.Close()
	if m.opts.IdleTimeout <= 0 {
		t.Fatal("idle timeout must be defaulted")
	}
}

func TestElevationTypeName(t *testing.T) {
	if got := elevationTypeName(tokenElevationTypeFull); got != "full" {
		t.Fatalf("unexpected type name for full: %s", got)
	}
	if got := elevationTypeName(tokenElevationTypeLimited); got != "limited" {
		t.Fatalf("unexpected type name for limited: %s", got)
	}
	if got := elevationTypeName(999); got != "unknown" {
		t.Fatalf("unexpected type name for unknown: %s", got)
	}
}

func TestShouldProbeManagedClient(t *testing.T) {
	now := time.Now()

	if shouldProbeManagedClient(now, now.Add(-managedClientProbeAge), 1) {
		t.Fatal("active managed client must not be probed")
	}
	if shouldProbeManagedClient(now, now.Add(-(managedClientProbeAge - time.Second)), 0) {
		t.Fatal("fresh idle client must not be probed")
	}
	if !shouldProbeManagedClient(now, now.Add(-managedClientProbeAge), 0) {
		t.Fatal("stale idle client must be probed")
	}
	if !shouldProbeManagedClient(now, time.Time{}, 0) {
		t.Fatal("client with zero lastUsed must be probed")
	}
}

func TestShouldReapManagedClient(t *testing.T) {
	now := time.Now()

	if shouldReapManagedClient(now, &managedClient{refCount: 1, lastUsed: now.Add(-time.Hour)}) {
		t.Fatal("active managed client must not be reaped")
	}
	if !shouldReapManagedClient(now, &managedClient{broken: true, lastUsed: now}) {
		t.Fatal("broken idle client must be reaped")
	}
	if !shouldReapManagedClient(now, &managedClient{lastUsed: now.Add(-managedClientMaxIdle)}) {
		t.Fatal("stale idle client must be reaped")
	}
	if shouldReapManagedClient(now, &managedClient{lastUsed: now.Add(-time.Second)}) {
		t.Fatal("fresh idle client must not be reaped")
	}
}

func TestClassifyManagedClientLease(t *testing.T) {
	now := time.Now()

	if got := classifyManagedClientLease(now, sessionclient.SessionLease{}); got != managedClientLeaseReuse {
		t.Fatalf("zero lease decision = %v, want reuse", got)
	}

	expired := sessionclient.SessionLease{ExpiresAt: now.Add(-time.Second)}
	if got := classifyManagedClientLease(now, expired); got != managedClientLeaseExpired {
		t.Fatalf("expired lease decision = %v, want expired", got)
	}

	expiring := sessionclient.SessionLease{ExpiresAt: now.Add(managedClientLeaseSkew)}
	if got := classifyManagedClientLease(now, expiring); got != managedClientLeaseExpiring {
		t.Fatalf("expiring lease decision = %v, want expiring", got)
	}

	healthy := sessionclient.SessionLease{ExpiresAt: now.Add(managedClientLeaseSkew + time.Second)}
	if got := classifyManagedClientLease(now, healthy); got != managedClientLeaseReuse {
		t.Fatalf("healthy lease decision = %v, want reuse", got)
	}
}

func TestIsExpectedPipeErrTreatsCommonRemoteCloseAsExpected(t *testing.T) {
	cases := []error{
		errors.New("An existing connection was forcibly closed by the remote host."),
		errors.New("connection reset by peer"),
		errors.New("broken pipe"),
	}
	for _, err := range cases {
		if !isExpectedPipeErr(err) {
			t.Fatalf("isExpectedPipeErr(%q) = false, want true", err)
		}
	}
}

func TestIsSessionClientFatalErrDoesNotPromoteGenericDeadline(t *testing.T) {
	if isSessionClientFatalErr(context.DeadlineExceeded) {
		t.Fatal("generic context deadline exceeded must not mark cached client fatal")
	}
	if !isSessionClientFatalErr(errors.New("quic: no recent network activity")) {
		t.Fatal("transport idle death must remain fatal")
	}
}

func TestCurrentManagedClientUnusableReasonLockedClearsExpiredTransient(t *testing.T) {
	c := newPolicyController(sessionclient.Config{}, modeAuto, statsFormatText)
	defer c.Close()

	now := time.Now()
	mc := &managedClient{
		key:            "probe-client",
		transport:      sessionclient.TransportQUIC,
		unusableReason: "probe_failed",
		unusableSince:  now.Add(-2 * time.Second),
		unusableUntil:  now.Add(-time.Second),
	}

	c.mu.Lock()
	reason := c.currentManagedClientUnusableReasonLocked(mc, now)
	c.mu.Unlock()

	if reason != "" {
		t.Fatalf("reason = %q, want cleared", reason)
	}
	if mc.unusableReason != "" || !mc.unusableSince.IsZero() || !mc.unusableUntil.IsZero() {
		t.Fatal("expired transient unusable reason must be cleared")
	}
}

func TestPickProbeClientSkipsTransientUnusableAndPrefersHealthyCandidate(t *testing.T) {
	c := newPolicyController(sessionclient.Config{}, modeAuto, statsFormatText)
	defer c.Close()

	now := time.Now()
	badClient := &sessionclient.Client{}
	goodClient := &sessionclient.Client{}

	c.lastTransport = sessionclient.TransportQUIC
	c.clients["bad"] = &managedClient{
		key:            "bad",
		client:         badClient,
		transport:      sessionclient.TransportQUIC,
		unusableReason: "probe_failed",
		unusableSince:  now.Add(-time.Second),
		unusableUntil:  now.Add(time.Second),
	}
	c.clients["good"] = &managedClient{
		key:       "good",
		client:    goodClient,
		transport: sessionclient.TransportTCPSession,
	}
	c.flows[1] = &flowState{
		id:        1,
		startedAt: now,
		transport: sessionclient.TransportQUIC,
		client:    badClient,
		clientKey: "bad",
	}
	c.flows[2] = &flowState{
		id:        2,
		startedAt: now,
		transport: sessionclient.TransportTCPSession,
		client:    goodClient,
		clientKey: "good",
	}

	client, transport, key, ok := c.pickProbeClient(now)
	if !ok {
		t.Fatal("pickProbeClient returned no candidate")
	}
	if client != goodClient {
		t.Fatal("pickProbeClient selected suppressed client")
	}
	if transport != sessionclient.TransportTCPSession {
		t.Fatalf("transport = %s, want tcp-session", transport)
	}
	if key != "good" {
		t.Fatalf("key = %q, want good", key)
	}
}

func TestClassifyPolicyCandidateReasonRejectsLeaseExpiring(t *testing.T) {
	now := time.Now()
	reason := classifyPolicyCandidateReason(
		now,
		now,
		true,
		managedClientLeaseExpiring,
		"",
	)
	if reason != policyCandidateLeaseExpiring {
		t.Fatalf("reason = %s, want %s", reason, policyCandidateLeaseExpiring)
	}
}

func TestClassifyPolicyCandidateReasonRejectsNoRecentActivity(t *testing.T) {
	now := time.Now()
	reason := classifyPolicyCandidateReason(
		now,
		now.Add(-policyRecentActivityWindow-time.Second),
		true,
		managedClientLeaseReuse,
		"",
	)
	if reason != policyCandidateNoRecentActivity {
		t.Fatalf("reason = %s, want %s", reason, policyCandidateNoRecentActivity)
	}
}

func TestCollectRTTWindowLockedFiltersByReason(t *testing.T) {
	c := newPolicyController(sessionclient.Config{}, modeAuto, statsFormatText)
	defer c.Close()

	now := time.Now()
	c.mu.Lock()
	c.appendRTTSampleLocked(now.Add(-time.Second), 50, sessionclient.TransportQUIC, "healthy", policyCandidateHealthy)
	c.appendRTTSampleLocked(now.Add(-time.Second), 80, sessionclient.TransportQUIC, "low", policyCandidateLowConfidence)
	c.appendRTTSampleLocked(now.Add(-time.Second), 120, sessionclient.TransportQUIC, "bad", policyCandidateLeaseExpired)
	healthy, lowConfidence := c.collectRTTWindowLocked(now.Add(-2*time.Second), now)
	c.mu.Unlock()

	if len(healthy) != 1 || healthy[0] != 50 {
		t.Fatalf("healthy samples = %v, want [50]", healthy)
	}
	if len(lowConfidence) != 1 || lowConfidence[0] != 80 {
		t.Fatalf("low-confidence samples = %v, want [80]", lowConfidence)
	}
}

func TestClassifyFailureClass(t *testing.T) {
	if got := classifyFailureClass("proxy_copy_up", policyCandidateHealthy); got != failureClassHardFailure {
		t.Fatalf("healthy proxy_copy_up class = %s, want %s", got, failureClassHardFailure)
	}
	if got := classifyFailureClass("rtt_probe_timeout_quic", policyCandidateHealthy); got != failureClassMeaningfulDegradation {
		t.Fatalf("healthy rtt probe class = %s, want %s", got, failureClassMeaningfulDegradation)
	}
	if got := classifyFailureClass("udp_pump_error", policyCandidateLeaseExpiring); got != failureClassLowConfidence {
		t.Fatalf("lease-expiring class = %s, want %s", got, failureClassLowConfidence)
	}
	if got := classifyFailureClass("udp_pump_error", policyCandidateProbeSuppressed); got != failureClassIgnored {
		t.Fatalf("probe-suppressed class = %s, want %s", got, failureClassIgnored)
	}
}

func TestRecordTransportErrorLowConfidenceUsesSeparateCounter(t *testing.T) {
	c := newPolicyController(sessionclient.Config{}, modeAuto, statsFormatText)
	defer c.Close()

	c.recordTransportError("udp_pump_error", failureClassLowConfidence, policyCandidateLeaseExpiring)

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.errorSpikeTime) != 0 {
		t.Fatalf("full error counter = %d, want 0", len(c.errorSpikeTime))
	}
	if len(c.errorLowConfidenceTimes) != 1 {
		t.Fatalf("low-confidence error counter = %d, want 1", len(c.errorLowConfidenceTimes))
	}
	if c.currentMode != modeNormal {
		t.Fatalf("mode = %s, want normal", c.currentMode)
	}
}

func TestRecordTransportErrorIgnoredDoesNotTouchCounters(t *testing.T) {
	c := newPolicyController(sessionclient.Config{}, modeAuto, statsFormatText)
	defer c.Close()

	c.recordTransportError("udp_pump_error", failureClassIgnored, policyCandidateProbeSuppressed)

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.errorSpikeTime) != 0 {
		t.Fatalf("full error counter = %d, want 0", len(c.errorSpikeTime))
	}
	if len(c.errorLowConfidenceTimes) != 0 {
		t.Fatalf("low-confidence error counter = %d, want 0", len(c.errorLowConfidenceTimes))
	}
}

func TestEvaluateAutoPolicyIgnoresLowConfidenceFastTrigger(t *testing.T) {
	c := newPolicyController(sessionclient.Config{}, modeAuto, statsFormatText)
	defer c.Close()

	now := time.Now()
	lowConfidenceClient := &sessionclient.Client{}
	lowConfidenceFlow := &flowState{
		id:        21,
		startedAt: now.Add(-fastFlowDurationThreshold - time.Second),
		transport: sessionclient.TransportQUIC,
		client:    lowConfidenceClient,
		clientKey: "low-confidence",
	}
	lowConfidenceFlow.lastActivity.Store(now.UnixNano())

	c.mu.Lock()
	c.currentMode = modeNormal
	c.flows[lowConfidenceFlow.id] = lowConfidenceFlow
	c.mu.Unlock()

	c.evaluateAutoPolicy(now)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.currentMode != modeNormal {
		t.Fatalf("mode = %s, want normal", c.currentMode)
	}
}

func TestEvaluateAutoPolicySurvivalDoesNotEnterOnSingleWeakSpike(t *testing.T) {
	c := newPolicyController(sessionclient.Config{}, modeAuto, statsFormatText)
	defer c.Close()

	now := time.Now()
	c.mu.Lock()
	c.quicFailTimes = []time.Time{now}
	c.mu.Unlock()

	c.evaluateAutoPolicy(now)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.currentMode != modeNormal {
		t.Fatalf("mode = %s, want normal", c.currentMode)
	}
	if c.degradedTicks != 0 {
		t.Fatalf("degradedTicks = %d, want 0", c.degradedTicks)
	}
}

func TestEvaluateAutoPolicySurvivalEnterNeedsConfirmation(t *testing.T) {
	c := newPolicyController(sessionclient.Config{}, modeAuto, statsFormatText)
	defer c.Close()

	now := time.Now()
	c.mu.Lock()
	c.quicFailTimes = []time.Time{
		now.Add(-2 * time.Second),
		now.Add(-time.Second),
		now,
	}
	c.mu.Unlock()

	c.evaluateAutoPolicy(now)
	c.mu.Lock()
	if c.currentMode != modeNormal {
		c.mu.Unlock()
		t.Fatalf("mode after first degraded tick = %s, want normal", c.currentMode)
	}
	if c.degradedTicks != 1 {
		c.mu.Unlock()
		t.Fatalf("degradedTicks after first degraded tick = %d, want 1", c.degradedTicks)
	}
	c.mu.Unlock()

	c.evaluateAutoPolicy(now.Add(time.Second))

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.currentMode != modeSurvival {
		t.Fatalf("mode after second degraded tick = %s, want survival", c.currentMode)
	}
	if c.degradedTicks != 0 {
		t.Fatalf("degradedTicks after switch = %d, want 0", c.degradedTicks)
	}
}

func TestEvaluateAutoPolicySurvivalExitNeedsStabilityWindow(t *testing.T) {
	c := newPolicyController(sessionclient.Config{}, modeAuto, statsFormatText)
	defer c.Close()

	now := time.Now()
	c.mu.Lock()
	c.currentMode = modeSurvival
	c.survivalUntil = now.Add(-time.Second)
	c.lastModeSwitchAt = time.Time{}
	c.mu.Unlock()

	for i := 0; i < survivalExitStableTicks-1; i++ {
		c.evaluateAutoPolicy(now.Add(time.Duration(i) * time.Second))
		c.mu.Lock()
		if c.currentMode != modeSurvival {
			c.mu.Unlock()
			t.Fatalf("mode at stable tick %d = %s, want survival", i+1, c.currentMode)
		}
		c.mu.Unlock()
	}

	c.evaluateAutoPolicy(now.Add(time.Duration(survivalExitStableTicks-1) * time.Second))

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.currentMode != modeNormal {
		t.Fatalf("mode after full stability window = %s, want normal", c.currentMode)
	}
}

func TestSwitchModeCooldownSuppressesImmediateFlip(t *testing.T) {
	c := newPolicyController(sessionclient.Config{}, modeAuto, statsFormatText)
	defer c.Close()

	now := time.Now()
	if !c.switchModeAt(now, modeSurvival, "first_switch") {
		t.Fatal("first switch must succeed")
	}
	if c.switchModeAt(now.Add(time.Second), modeNormal, "quick_reverse") {
		t.Fatal("cooldown must suppress immediate reverse switch")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.currentMode != modeSurvival {
		t.Fatalf("mode = %s, want survival", c.currentMode)
	}
}

func TestApplyFastModeHysteresisEnterNeedsConfirmation(t *testing.T) {
	c := newPolicyController(sessionclient.Config{}, modeAuto, statsFormatText)
	defer c.Close()

	now := time.Now()
	flow := &flowState{id: 77, startedAt: now.Add(-fastFlowDurationThreshold - time.Second)}
	candidate := &policyCandidate{flowID: flow.id, transport: sessionclient.TransportQUIC, reason: policyCandidateHealthy}
	reason := "flow_77_duration_11s"

	c.applyFastModeHysteresis(now, modeNormal, candidate, reason)
	c.mu.Lock()
	if c.currentMode != modeNormal {
		c.mu.Unlock()
		t.Fatalf("mode after first fast tick = %s, want normal", c.currentMode)
	}
	if c.fastSignalTicks != 1 {
		c.mu.Unlock()
		t.Fatalf("fastSignalTicks after first fast tick = %d, want 1", c.fastSignalTicks)
	}
	c.mu.Unlock()

	c.applyFastModeHysteresis(now.Add(time.Second), modeNormal, candidate, reason)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.currentMode != modeFast {
		t.Fatalf("mode after second fast tick = %s, want fast", c.currentMode)
	}
}

func TestApplyFastModeHysteresisExitNeedsQuietWindow(t *testing.T) {
	c := newPolicyController(sessionclient.Config{}, modeAuto, statsFormatText)
	defer c.Close()

	now := time.Now()
	c.mu.Lock()
	c.currentMode = modeFast
	c.lastModeSwitchAt = time.Time{}
	c.mu.Unlock()

	for i := 0; i < fastExitStableTicks-1; i++ {
		c.applyFastModeHysteresis(now.Add(time.Duration(i)*time.Second), modeFast, nil, "")
		c.mu.Lock()
		if c.currentMode != modeFast {
			c.mu.Unlock()
			t.Fatalf("mode at quiet tick %d = %s, want fast", i+1, c.currentMode)
		}
		c.mu.Unlock()
	}

	c.applyFastModeHysteresis(now.Add(time.Duration(fastExitStableTicks-1)*time.Second), modeFast, nil, "")
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.currentMode != modeNormal {
		t.Fatalf("mode after quiet window = %s, want normal", c.currentMode)
	}
}

func TestFastModeHysteresisSuppressesNearThresholdOscillation(t *testing.T) {
	c := newPolicyController(sessionclient.Config{}, modeAuto, statsFormatText)
	defer c.Close()

	now := time.Now()
	candidate := &policyCandidate{flowID: 5, transport: sessionclient.TransportQUIC, reason: policyCandidateHealthy}
	reason := "flow_5_duration_11s"

	c.applyFastModeHysteresis(now, modeNormal, candidate, reason)
	c.applyFastModeHysteresis(now.Add(time.Second), modeNormal, nil, "")
	c.applyFastModeHysteresis(now.Add(2*time.Second), modeNormal, candidate, reason)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.currentMode != modeNormal {
		t.Fatalf("mode = %s, want normal under oscillating signal", c.currentMode)
	}
	if c.fastSignalTicks != 1 {
		t.Fatalf("fastSignalTicks = %d, want 1 after signal reset and re-arm", c.fastSignalTicks)
	}
}
