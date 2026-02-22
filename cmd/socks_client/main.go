package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"vlf-runtime/internal/auth"
	"vlf-runtime/internal/sessionclient"
)

const (
	socksVer5 = 0x05

	socksMethodNoAuth       = 0x00
	socksMethodNoAcceptable = 0xff

	socksCmdConnect = 0x01

	socksAtypIPv4   = 0x01
	socksAtypDomain = 0x03
	socksAtypIPv6   = 0x04

	socksReplySuccess            = 0x00
	socksReplyGeneralFailure     = 0x01
	socksReplyHostUnreachable    = 0x04
	socksReplyCommandUnsupported = 0x07
	socksReplyAddrUnsupported    = 0x08

	fastFlowDurationThreshold = 10 * time.Second
	fastDownloadThreshold     = int64(64 * 1024 * 1024)
	fastDownrateThresholdMbps = 20.0
	fastDownrateWindow        = 5 * time.Second

	failureWindowDuration    = 30 * time.Second
	quicFailureThreshold     = 3
	transportErrorThreshold  = 8
	survivalRecoveryMinDelay = 60 * time.Second

	statsPrintInterval = 10 * time.Second
	policyTickInterval = time.Second

	rttProbeTimeout         = 1500 * time.Millisecond
	capRTTHighMs            = 250.0
	capRTTLowMs             = 150.0
	capEnableConsecutive    = 2
	capDisableConsecutive   = 3
	capMaxNewFlowsPerSecond = 2
	capActiveFlowsMargin    = 4
)

type socksTarget struct {
	Host string
	Port int
}

type clientMode string

const (
	modeAuto     clientMode = "auto"
	modeNormal   clientMode = "normal"
	modeFast     clientMode = "fast"
	modeSurvival clientMode = "survival"
)

type statsFormat string

const (
	statsFormatText statsFormat = "text"
	statsFormatJSON statsFormat = "json"
)

type flowState struct {
	id        uint64
	startedAt time.Time
	transport sessionclient.Transport
	client    *sessionclient.Client

	upBytes   atomic.Int64
	downBytes atomic.Int64

	mu          sync.Mutex
	downSamples []downSample
}

type downSample struct {
	at    time.Time
	total int64
}

type rttSample struct {
	at time.Time
	ms float64
}

type capState struct {
	Enabled           bool `json:"enabled"`
	MaxNewFlowsPerSec int  `json:"max_new_flows_per_sec"`
	MaxActiveFlows    int  `json:"max_active_flows"`
}

type statsPayload struct {
	Mode        string    `json:"mode"`
	Transport   string    `json:"transport"`
	ActiveFlows int       `json:"active_flows"`
	MbpsUp      float64   `json:"mbps_up"`
	MbpsDown    float64   `json:"mbps_down"`
	MbpsTotal   float64   `json:"mbps_total"`
	BytesUp     int64     `json:"bytes_up"`
	BytesDown   int64     `json:"bytes_down"`
	RTTP50      *float64  `json:"rtt_p50"`
	RTTP95      *float64  `json:"rtt_p95"`
	Switches    uint64    `json:"switches"`
	Caps        *capState `json:"caps,omitempty"`
}

type flowWriter struct {
	dst       io.Writer
	flowBytes *atomic.Int64
	total     *atomic.Int64
}

func (w *flowWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	if n > 0 {
		w.flowBytes.Add(int64(n))
		w.total.Add(int64(n))
	}
	return n, err
}

type policyController struct {
	baseCfg     sessionclient.Config
	configured  clientMode
	currentMode clientMode
	statsFormat statsFormat

	mu            sync.Mutex
	nextFlowID    uint64
	flows         map[uint64]*flowState
	lastTransport sessionclient.Transport
	switches      uint64

	quicFailTimes  []time.Time
	errorSpikeTime []time.Time
	survivalSince  time.Time
	survivalUntil  time.Time

	rttSamples []rttSample

	lastStatsAt   time.Time
	lastStatsUp   int64
	lastStatsDown int64

	capEnabled        bool
	capMaxNewPerSec   int
	capMaxActiveFlows int
	capOpenedThisSec  int
	capWindowSec      int64
	pendingPermits    int
	highRTTTicks      int
	lowRTTTicks       int

	totalUpBytes   atomic.Int64
	totalDownBytes atomic.Int64

	stopCh chan struct{}
	doneCh chan struct{}
}

func main() {
	baseCfg, err := sessionclient.LoadConfigFromEnv()
	if err != nil {
		log.Fatalf("load session config: %v", err)
	}

	listenAddr := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	serverHost := flag.String("server", baseCfg.GatewayHost, "gateway host")
	serverPort := flag.Int("port", baseCfg.GatewayUDP, "gateway port for QUIC and TCP session lanes")
	relayBase := flag.String("relay-base", baseCfg.RelayBase, "relay base URL (fallback)")
	connectTimeout := flag.Duration("connect-timeout", 10*time.Second, "dial/open timeout per CONNECT")
	modeRaw := flag.String("mode", "auto", "client mode: auto|normal|fast|survival")
	preferQUIC := flag.Bool("prefer-quic", baseCfg.PreferQUIC, "base prefer QUIC transport first")
	disableQUIC := flag.Bool("disable-quic", baseCfg.DisableQUIC, "disable QUIC transport")
	disableTCP := flag.Bool("disable-tcp-session", baseCfg.DisableTCPSession, "disable TCP session transport")
	allowRelay := flag.Bool("allow-relay-fallback", baseCfg.AllowRelay, "allow HTTP relay fallback")
	statsFormatRaw := flag.String("stats-format", "text", "stats output format: text|json")
	clientID := flag.String("client-id", "", "override client id")
	secret := flag.String("secret", "", "override secret (plain or b64:...)")
	debug := flag.Bool("debug", baseCfg.Debug, "enable sessionclient debug logs")
	flag.Parse()

	mode, err := parseMode(*modeRaw)
	if err != nil {
		log.Fatalf("invalid --mode: %v", err)
	}
	if *serverPort <= 0 || *serverPort > 65535 {
		log.Fatalf("invalid --port=%d", *serverPort)
	}
	if *connectTimeout <= 0 {
		*connectTimeout = 10 * time.Second
	}
	parsedStatsFormat, err := parseStatsFormat(*statsFormatRaw)
	if err != nil {
		log.Fatalf("invalid --stats-format: %v", err)
	}

	cfg := baseCfg
	cfg.GatewayHost = *serverHost
	cfg.GatewayUDP = *serverPort
	cfg.GatewayTCP = *serverPort
	cfg.RelayBase = *relayBase
	cfg.PreferQUIC = *preferQUIC
	cfg.DisableQUIC = *disableQUIC
	cfg.DisableTCPSession = *disableTCP
	cfg.AllowRelay = *allowRelay
	cfg.Debug = *debug

	if *clientID != "" {
		cfg.ClientID = *clientID
	}
	if *secret != "" {
		parsedSecret, parseErr := auth.ParseSecretString(*secret)
		if parseErr != nil {
			log.Fatalf("parse --secret: %v", parseErr)
		}
		cfg.Secret = parsedSecret
	}

	controller := newPolicyController(cfg, mode, parsedStatsFormat)
	defer controller.Close()

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", *listenAddr, err)
	}
	defer ln.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	log.Printf("SOCKS5 listening on %s", *listenAddr)
	log.Printf("Gateway=%s:%d mode=%s base_prefer_quic=%t base_disable_quic=%t disable_tcp=%t allow_relay=%t",
		cfg.GatewayHost, *serverPort, mode, cfg.PreferQUIC, cfg.DisableQUIC, cfg.DisableTCPSession, cfg.AllowRelay)

	var wg sync.WaitGroup
	for {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil || errors.Is(acceptErr, net.ErrClosed) {
				break
			}
			var ne net.Error
			if errors.As(acceptErr, &ne) && ne.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			log.Printf("accept failed: %v", acceptErr)
			continue
		}

		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			handleConn(c, controller, *connectTimeout)
		}(conn)
	}

	wg.Wait()
	log.Printf("SOCKS5 stopped")
}

func parseMode(raw string) (clientMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(modeAuto):
		return modeAuto, nil
	case string(modeNormal):
		return modeNormal, nil
	case string(modeFast):
		return modeFast, nil
	case string(modeSurvival):
		return modeSurvival, nil
	default:
		return "", fmt.Errorf("%q (allowed: auto|normal|fast|survival)", raw)
	}
}

func parseStatsFormat(raw string) (statsFormat, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(statsFormatText):
		return statsFormatText, nil
	case string(statsFormatJSON):
		return statsFormatJSON, nil
	default:
		return "", fmt.Errorf("%q (allowed: text|json)", raw)
	}
}

func newPolicyController(baseCfg sessionclient.Config, configured clientMode, sf statsFormat) *policyController {
	initial := configured
	if configured == modeAuto {
		initial = modeNormal
	}

	c := &policyController{
		baseCfg:       baseCfg,
		configured:    configured,
		currentMode:   initial,
		statsFormat:   sf,
		flows:         make(map[uint64]*flowState),
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
		lastStatsAt:   time.Now(),
		survivalSince: time.Time{},
		survivalUntil: time.Time{},
	}
	go c.loop()
	return c
}

func (c *policyController) Close() {
	close(c.stopCh)
	<-c.doneCh
}

func (c *policyController) loop() {
	defer close(c.doneCh)
	ticker := time.NewTicker(policyTickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case now := <-ticker.C:
			c.probeRTT(now)
			c.evaluateAutoPolicy(now)
			c.printStats(now)
		}
	}
}

func (c *policyController) dialConfig() (sessionclient.Config, clientMode) {
	c.mu.Lock()
	mode := c.currentMode
	c.mu.Unlock()
	return c.configForMode(mode), mode
}

func (c *policyController) configForMode(mode clientMode) sessionclient.Config {
	cfg := c.baseCfg
	switch mode {
	case modeNormal:
		cfg.PreferQUIC = true
	case modeFast:
		cfg.PreferQUIC = true
		// In FAST we still keep fallbacks enabled, but prefer QUIC aggressively.
		cfg.QUICTimeout = maxDuration(cfg.QUICTimeout, 2200*time.Millisecond)
	case modeSurvival:
		cfg.PreferQUIC = false
		if !cfg.DisableTCPSession || cfg.AllowRelay {
			cfg.DisableQUIC = true
		}
	}
	return cfg
}

func (c *policyController) onDialSuccess(mode clientMode, cfg sessionclient.Config, transport sessionclient.Transport) {
	if mode == modeSurvival {
		return
	}
	if !cfg.DisableQUIC && cfg.PreferQUIC && transport != sessionclient.TransportQUIC {
		c.recordQUICFailure("dial_fallback_transport_" + string(transport))
	}
}

func (c *policyController) onDialError(cfg sessionclient.Config, err error) {
	var de *sessionclient.DialError
	if errors.As(err, &de) && de.QUICErr != nil && !cfg.DisableQUIC {
		c.recordQUICFailure("dial_error")
	}
	c.recordTransportError("dial_error")
}

func (c *policyController) onTransportError(reason string) {
	c.recordTransportError(reason)
}

func (c *policyController) registerFlow(client *sessionclient.Client, transport sessionclient.Transport, setupDuration time.Duration) *flowState {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.pendingPermits > 0 {
		c.pendingPermits--
	}

	c.nextFlowID++
	fs := &flowState{
		id:        c.nextFlowID,
		startedAt: now,
		transport: transport,
		client:    client,
	}
	c.flows[fs.id] = fs

	if c.lastTransport == "" {
		c.lastTransport = transport
		log.Printf("policy transport init: transport=%s", transport)
	} else if c.lastTransport != transport {
		prev := c.lastTransport
		c.lastTransport = transport
		c.switches++
		log.Printf("policy transport switch: from=%s to=%s reason=new_flow_dial", prev, transport)
	}

	return fs
}

func (c *policyController) unregisterFlow(id uint64) {
	c.mu.Lock()
	delete(c.flows, id)
	c.mu.Unlock()
}

func (c *policyController) acquireFlowPermit(ctx context.Context) error {
	for {
		now := time.Now()

		c.mu.Lock()
		if c.configured != modeAuto || !c.capEnabled {
			c.pendingPermits++
			c.mu.Unlock()
			return nil
		}

		if now.Unix() != c.capWindowSec {
			c.capWindowSec = now.Unix()
			c.capOpenedThisSec = 0
		}

		activeNow := len(c.flows) + c.pendingPermits
		canOpen := activeNow < c.capMaxActiveFlows && c.capOpenedThisSec < c.capMaxNewPerSec
		if canOpen {
			c.pendingPermits++
			c.capOpenedThisSec++
			c.mu.Unlock()
			return nil
		}
		c.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (c *policyController) releaseFlowPermit() {
	c.mu.Lock()
	if c.pendingPermits > 0 {
		c.pendingPermits--
	}
	c.mu.Unlock()
}

func (c *policyController) recordQUICFailure(reason string) {
	now := time.Now()
	c.mu.Lock()
	c.quicFailTimes = append(c.quicFailTimes, now)
	c.quicFailTimes = pruneTimes(c.quicFailTimes, now.Add(-failureWindowDuration))
	count := len(c.quicFailTimes)
	configured := c.configured
	current := c.currentMode
	c.mu.Unlock()

	log.Printf("policy quic failure: reason=%s count_30s=%d", reason, count)
	if configured == modeAuto && current != modeSurvival && count >= quicFailureThreshold {
		c.switchMode(modeSurvival, fmt.Sprintf("quic_failures_%d_in_%s", count, failureWindowDuration))
	}
}

func (c *policyController) recordTransportError(reason string) {
	now := time.Now()
	c.mu.Lock()
	c.errorSpikeTime = append(c.errorSpikeTime, now)
	c.errorSpikeTime = pruneTimes(c.errorSpikeTime, now.Add(-failureWindowDuration))
	count := len(c.errorSpikeTime)
	configured := c.configured
	current := c.currentMode
	c.mu.Unlock()

	log.Printf("policy transport error: reason=%s count_30s=%d", reason, count)
	if configured == modeAuto && current != modeSurvival && count >= transportErrorThreshold {
		c.switchMode(modeSurvival, fmt.Sprintf("transport_errors_%d_in_%s", count, failureWindowDuration))
	}
}

func (c *policyController) probeRTT(now time.Time) {
	client, transport, ok := c.pickProbeClient()
	if !ok {
		return
	}

	probeCtx, cancel := context.WithTimeout(context.Background(), rttProbeTimeout)
	defer cancel()

	rtt, err := client.ProbeRTT(probeCtx)
	if err != nil {
		if errors.Is(err, sessionclient.ErrRTTProbeUnsupported) || isExpectedProbeErr(err) {
			return
		}
		if errors.Is(err, context.DeadlineExceeded) {
			c.recordTransportError("rtt_probe_timeout_" + string(transport))
			return
		}
		c.recordTransportError("rtt_probe_error_" + string(transport))
		return
	}

	c.mu.Lock()
	c.appendRTTSampleLocked(now, float64(rtt.Microseconds())/1000.0)
	c.mu.Unlock()
}

func (c *policyController) pickProbeClient() (*sessionclient.Client, sessionclient.Transport, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.flows) == 0 {
		return nil, "", false
	}

	var fallback *flowState
	for _, flow := range c.flows {
		if flow.client == nil {
			continue
		}
		if fallback == nil {
			fallback = flow
		}
		if c.lastTransport != "" && flow.transport == c.lastTransport {
			return flow.client, flow.transport, true
		}
	}
	if fallback == nil {
		return nil, "", false
	}
	return fallback.client, fallback.transport, true
}

func (c *policyController) switchMode(next clientMode, reason string) {
	now := time.Now()
	c.mu.Lock()
	prev := c.currentMode
	if prev == next {
		c.mu.Unlock()
		return
	}
	c.currentMode = next
	c.switches++
	if next == modeSurvival {
		c.survivalSince = now
		c.survivalUntil = now.Add(survivalRecoveryMinDelay)
	}
	switches := c.switches
	c.mu.Unlock()

	log.Printf("policy mode switch: from=%s to=%s reason=%s switches=%d", prev, next, reason, switches)
}

func (c *policyController) evaluateAutoPolicy(now time.Time) {
	c.mu.Lock()
	if c.configured != modeAuto {
		c.mu.Unlock()
		return
	}

	c.quicFailTimes = pruneTimes(c.quicFailTimes, now.Add(-failureWindowDuration))
	c.errorSpikeTime = pruneTimes(c.errorSpikeTime, now.Add(-failureWindowDuration))

	mode := c.currentMode
	quicFails := len(c.quicFailTimes)
	transportErrs := len(c.errorSpikeTime)
	survivalUntil := c.survivalUntil
	flows := make([]*flowState, 0, len(c.flows))
	for _, f := range c.flows {
		flows = append(flows, f)
	}
	c.mu.Unlock()

	if mode != modeSurvival && quicFails >= quicFailureThreshold {
		c.switchMode(modeSurvival, fmt.Sprintf("quic_failures_%d_in_%s", quicFails, failureWindowDuration))
		return
	}
	if mode != modeSurvival && transportErrs >= transportErrorThreshold {
		c.switchMode(modeSurvival, fmt.Sprintf("transport_errors_%d_in_%s", transportErrs, failureWindowDuration))
		return
	}

	if mode == modeSurvival {
		if now.After(survivalUntil) && quicFails == 0 && transportErrs == 0 {
			c.switchMode(modeNormal, "survival_recovery_no_recent_errors")
		}
		return
	}

	if mode != modeNormal {
		return
	}

	for _, f := range flows {
		duration := now.Sub(f.startedAt)
		if duration >= fastFlowDurationThreshold {
			c.switchMode(modeFast, fmt.Sprintf("flow_%d_duration_%s", f.id, duration.Round(time.Second)))
			return
		}

		downBytes := f.downBytes.Load()
		if downBytes >= fastDownloadThreshold {
			c.switchMode(modeFast, fmt.Sprintf("flow_%d_download_%dmb", f.id, downBytes/(1024*1024)))
			return
		}

		if avgDownrateMbps(f, now) >= fastDownrateThresholdMbps {
			c.switchMode(modeFast, fmt.Sprintf("flow_%d_downrate_gt_%.0fmbps_for_%s", f.id, fastDownrateThresholdMbps, fastDownrateWindow))
			return
		}
	}
}

func (c *policyController) printStats(now time.Time) {
	upTotal := c.totalUpBytes.Load()
	downTotal := c.totalDownBytes.Load()

	c.mu.Lock()
	if now.Sub(c.lastStatsAt) < statsPrintInterval {
		c.mu.Unlock()
		return
	}

	prevAt := c.lastStatsAt
	prevUp := c.lastStatsUp
	prevDown := c.lastStatsDown

	mode := c.currentMode
	configured := c.configured
	lastTransport := c.lastTransport
	activeFlows := len(c.flows)
	switches := c.switches
	sf := c.statsFormat

	rttWindow := c.collectRTTWindowLocked(prevAt, now)
	var rttP50Ptr *float64
	var rttP95Ptr *float64
	if len(rttWindow) > 0 {
		p50 := percentile(rttWindow, 50)
		p95 := percentile(rttWindow, 95)
		rttP50Ptr = &p50
		rttP95Ptr = &p95
	}

	c.updateAdaptiveCapLocked(now, activeFlows, rttP95Ptr)
	capSnapshot := c.capSnapshotLocked()

	c.lastStatsAt = now
	c.lastStatsUp = upTotal
	c.lastStatsDown = downTotal
	c.mu.Unlock()

	windowSec := now.Sub(prevAt).Seconds()
	if windowSec <= 0 {
		windowSec = statsPrintInterval.Seconds()
	}
	deltaUp := upTotal - prevUp
	deltaDown := downTotal - prevDown
	upMbps := bytesToMbps(deltaUp, windowSec)
	downMbps := bytesToMbps(deltaDown, windowSec)
	totalMbps := upMbps + downMbps

	modeLabel := string(mode)
	if configured == modeAuto {
		modeLabel = fmt.Sprintf("auto(%s)", mode)
	}
	transportLabel := "n/a"
	if lastTransport != "" {
		transportLabel = string(lastTransport)
	}

	if sf == statsFormatJSON {
		payload := statsPayload{
			Mode:        modeLabel,
			Transport:   transportLabel,
			ActiveFlows: activeFlows,
			MbpsUp:      upMbps,
			MbpsDown:    downMbps,
			MbpsTotal:   totalMbps,
			BytesUp:     upTotal,
			BytesDown:   downTotal,
			RTTP50:      rttP50Ptr,
			RTTP95:      rttP95Ptr,
			Switches:    switches,
			Caps:        capSnapshot,
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			log.Printf("stats marshal failed: %v", err)
		} else {
			fmt.Println(string(raw))
		}
		return
	}

	rttP50Label := "n/a"
	rttP95Label := "n/a"
	if rttP50Ptr != nil {
		rttP50Label = fmt.Sprintf("%.1f", *rttP50Ptr)
	}
	if rttP95Ptr != nil {
		rttP95Label = fmt.Sprintf("%.1f", *rttP95Ptr)
	}

	capLabel := "off"
	if capSnapshot != nil && capSnapshot.Enabled {
		capLabel = fmt.Sprintf("on(new/s=%d,active<=%d)", capSnapshot.MaxNewFlowsPerSec, capSnapshot.MaxActiveFlows)
	}

	log.Printf("stats mode=%s transport=%s active_flows=%d bytes_up=%d bytes_down=%d mbps_up=%.2f mbps_down=%.2f mbps_total=%.2f rtt_p50_ms=%s rtt_p95_ms=%s switches=%d caps=%s",
		modeLabel, transportLabel, activeFlows, upTotal, downTotal, upMbps, downMbps, totalMbps, rttP50Label, rttP95Label, switches, capLabel)
}

func (c *policyController) appendRTTSampleLocked(at time.Time, ms float64) {
	if ms <= 0 {
		return
	}
	c.rttSamples = append(c.rttSamples, rttSample{at: at, ms: ms})
	c.pruneRTTSamplesLocked(at.Add(-2 * time.Minute))
}

func (c *policyController) pruneRTTSamplesLocked(cutoff time.Time) {
	if len(c.rttSamples) == 0 {
		return
	}
	idx := 0
	for idx < len(c.rttSamples) && c.rttSamples[idx].at.Before(cutoff) {
		idx++
	}
	if idx == 0 {
		return
	}
	copy(c.rttSamples, c.rttSamples[idx:])
	c.rttSamples = c.rttSamples[:len(c.rttSamples)-idx]
}

func (c *policyController) collectRTTWindowLocked(from, now time.Time) []float64 {
	c.pruneRTTSamplesLocked(now.Add(-2 * time.Minute))
	out := make([]float64, 0, len(c.rttSamples))
	for _, sample := range c.rttSamples {
		if sample.at.Before(from) {
			continue
		}
		out = append(out, sample.ms)
	}
	return out
}

func (c *policyController) updateAdaptiveCapLocked(now time.Time, activeFlows int, rttP95 *float64) {
	if c.configured != modeAuto {
		c.capEnabled = false
		c.capMaxNewPerSec = 0
		c.capMaxActiveFlows = 0
		c.highRTTTicks = 0
		c.lowRTTTicks = 0
		c.capOpenedThisSec = 0
		return
	}

	if rttP95 == nil {
		c.highRTTTicks = 0
		c.lowRTTTicks = 0
		return
	}

	value := *rttP95
	switch {
	case value > capRTTHighMs:
		c.highRTTTicks++
		c.lowRTTTicks = 0
		if !c.capEnabled && c.highRTTTicks >= capEnableConsecutive {
			current := activeFlows + c.pendingPermits
			c.capEnabled = true
			c.capMaxNewPerSec = capMaxNewFlowsPerSecond
			c.capMaxActiveFlows = current + capActiveFlowsMargin
			c.capWindowSec = now.Unix()
			c.capOpenedThisSec = 0
			log.Printf("policy cap enabled: reason=rtt_p95_high rtt_p95_ms=%.1f max_new_flows_per_sec=%d max_active_flows=%d",
				value, c.capMaxNewPerSec, c.capMaxActiveFlows)
		}
	case value < capRTTLowMs:
		c.lowRTTTicks++
		c.highRTTTicks = 0
		if c.capEnabled && c.lowRTTTicks >= capDisableConsecutive {
			c.capEnabled = false
			c.capMaxNewPerSec = 0
			c.capMaxActiveFlows = 0
			c.capOpenedThisSec = 0
			log.Printf("policy cap disabled: reason=rtt_p95_recovered rtt_p95_ms=%.1f", value)
		}
	default:
		c.highRTTTicks = 0
		c.lowRTTTicks = 0
	}
}

func (c *policyController) capSnapshotLocked() *capState {
	if !c.capEnabled || c.capMaxNewPerSec <= 0 || c.capMaxActiveFlows <= 0 {
		return nil
	}
	return &capState{
		Enabled:           true,
		MaxNewFlowsPerSec: c.capMaxNewPerSec,
		MaxActiveFlows:    c.capMaxActiveFlows,
	}
}

func pruneTimes(items []time.Time, cutoff time.Time) []time.Time {
	if len(items) == 0 {
		return items
	}
	idx := 0
	for idx < len(items) && items[idx].Before(cutoff) {
		idx++
	}
	if idx == 0 {
		return items
	}
	copy(items, items[idx:])
	return items[:len(items)-idx]
}

func avgDownrateMbps(flow *flowState, now time.Time) float64 {
	total := flow.downBytes.Load()

	flow.mu.Lock()
	flow.downSamples = append(flow.downSamples, downSample{at: now, total: total})
	cutoff := now.Add(-fastDownrateWindow)
	idx := 0
	for idx < len(flow.downSamples)-1 && flow.downSamples[idx].at.Before(cutoff) {
		idx++
	}
	if idx > 0 {
		copy(flow.downSamples, flow.downSamples[idx:])
		flow.downSamples = flow.downSamples[:len(flow.downSamples)-idx]
	}

	if len(flow.downSamples) < 2 {
		flow.mu.Unlock()
		return 0
	}

	first := flow.downSamples[0]
	last := flow.downSamples[len(flow.downSamples)-1]
	flow.mu.Unlock()

	dt := last.at.Sub(first.at).Seconds()
	if dt <= 0 {
		return 0
	}
	delta := last.total - first.total
	if delta <= 0 {
		return 0
	}
	return bytesToMbps(delta, dt)
}

func percentile(samples []float64, p float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	cp := append([]float64(nil), samples...)
	sort.Float64s(cp)
	if p <= 0 {
		return cp[0]
	}
	if p >= 100 {
		return cp[len(cp)-1]
	}
	pos := (p / 100.0) * float64(len(cp)-1)
	lo := int(pos)
	hi := lo + 1
	if hi >= len(cp) {
		return cp[lo]
	}
	frac := pos - float64(lo)
	return cp[lo]*(1-frac) + cp[hi]*frac
}

func bytesToMbps(deltaBytes int64, secs float64) float64 {
	if deltaBytes <= 0 || secs <= 0 {
		return 0
	}
	return (float64(deltaBytes) * 8.0) / secs / 1e6
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func handleConn(conn net.Conn, controller *policyController, connectTimeout time.Duration) {
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	target, err := negotiateSOCKS5(conn)
	if err != nil {
		log.Printf("SOCKS handshake failed from %s: %v", conn.RemoteAddr(), err)
		return
	}
	_ = conn.SetDeadline(time.Time{})

	admissionCtx, cancelAdmission := context.WithTimeout(context.Background(), connectTimeout)
	if err := controller.acquireFlowPermit(admissionCtx); err != nil {
		cancelAdmission()
		_ = writeSocksReply(conn, socksReplyGeneralFailure)
		log.Printf("flow admission denied for %s -> %s:%d: %v", conn.RemoteAddr(), target.Host, target.Port, err)
		return
	}
	cancelAdmission()
	permitHeld := true

	cfg, mode := controller.dialConfig()
	setupStart := time.Now()

	dialCtx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	client, err := sessionclient.Dial(dialCtx, cfg)
	cancel()
	if err != nil {
		if permitHeld {
			controller.releaseFlowPermit()
			permitHeld = false
		}
		controller.onDialError(cfg, err)
		_ = writeSocksReply(conn, socksReplyGeneralFailure)
		log.Printf("session dial failed mode=%s for %s -> %s:%d: %v", mode, conn.RemoteAddr(), target.Host, target.Port, err)
		return
	}
	controller.onDialSuccess(mode, cfg, client.Transport())

	openCtx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	flow, err := client.OpenTCPFlow(openCtx, target.Host, target.Port)
	cancel()
	if err != nil {
		if permitHeld {
			controller.releaseFlowPermit()
			permitHeld = false
		}
		controller.onTransportError("open_tcp_flow_failed")
		_ = writeSocksReply(conn, socksReplyHostUnreachable)
		_ = client.Close()
		log.Printf("open tcp flow failed mode=%s for %s -> %s:%d: %v", mode, conn.RemoteAddr(), target.Host, target.Port, err)
		return
	}

	if err := writeSocksReply(conn, socksReplySuccess); err != nil {
		if permitHeld {
			controller.releaseFlowPermit()
			permitHeld = false
		}
		controller.onTransportError("write_socks_reply_failed")
		_ = flow.Close()
		_ = client.Close()
		log.Printf("failed to send SOCKS success reply to %s: %v", conn.RemoteAddr(), err)
		return
	}

	fs := controller.registerFlow(client, client.Transport(), time.Since(setupStart))
	permitHeld = false
	log.Printf("proxy CONNECT %s -> %s:%d via %s mode=%s flow_id=%d", conn.RemoteAddr(), target.Host, target.Port, client.Transport(), mode, fs.id)
	proxyBidirectional(conn, flow, client, controller, fs)
}

func negotiateSOCKS5(conn net.Conn) (socksTarget, error) {
	var greetHdr [2]byte
	if _, err := io.ReadFull(conn, greetHdr[:]); err != nil {
		return socksTarget{}, fmt.Errorf("read greeting header: %w", err)
	}
	if greetHdr[0] != socksVer5 {
		return socksTarget{}, fmt.Errorf("unsupported SOCKS version: %d", greetHdr[0])
	}

	nMethods := int(greetHdr[1])
	if nMethods <= 0 {
		return socksTarget{}, errors.New("no auth methods provided")
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return socksTarget{}, fmt.Errorf("read methods: %w", err)
	}

	acceptNoAuth := false
	for _, m := range methods {
		if m == socksMethodNoAuth {
			acceptNoAuth = true
			break
		}
	}
	if !acceptNoAuth {
		_ = writeMethodSelection(conn, socksMethodNoAcceptable)
		return socksTarget{}, errors.New("client does not support no-auth")
	}
	if err := writeMethodSelection(conn, socksMethodNoAuth); err != nil {
		return socksTarget{}, fmt.Errorf("write method selection: %w", err)
	}

	var reqHdr [4]byte
	if _, err := io.ReadFull(conn, reqHdr[:]); err != nil {
		return socksTarget{}, fmt.Errorf("read request header: %w", err)
	}
	if reqHdr[0] != socksVer5 {
		return socksTarget{}, fmt.Errorf("invalid request version: %d", reqHdr[0])
	}
	if reqHdr[1] != socksCmdConnect {
		_ = writeSocksReply(conn, socksReplyCommandUnsupported)
		return socksTarget{}, fmt.Errorf("unsupported cmd: %d", reqHdr[1])
	}

	host, err := readTargetHost(conn, reqHdr[3])
	if err != nil {
		_ = writeSocksReply(conn, socksReplyAddrUnsupported)
		return socksTarget{}, err
	}

	var portRaw [2]byte
	if _, err := io.ReadFull(conn, portRaw[:]); err != nil {
		return socksTarget{}, fmt.Errorf("read target port: %w", err)
	}
	port := int(binary.BigEndian.Uint16(portRaw[:]))
	if port <= 0 {
		_ = writeSocksReply(conn, socksReplyGeneralFailure)
		return socksTarget{}, errors.New("invalid target port")
	}

	return socksTarget{Host: host, Port: port}, nil
}

func readTargetHost(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case socksAtypIPv4:
		var ipRaw [4]byte
		if _, err := io.ReadFull(conn, ipRaw[:]); err != nil {
			return "", fmt.Errorf("read ipv4: %w", err)
		}
		return net.IP(ipRaw[:]).String(), nil
	case socksAtypIPv6:
		var ipRaw [16]byte
		if _, err := io.ReadFull(conn, ipRaw[:]); err != nil {
			return "", fmt.Errorf("read ipv6: %w", err)
		}
		return net.IP(ipRaw[:]).String(), nil
	case socksAtypDomain:
		var lnRaw [1]byte
		if _, err := io.ReadFull(conn, lnRaw[:]); err != nil {
			return "", fmt.Errorf("read domain length: %w", err)
		}
		ln := int(lnRaw[0])
		if ln <= 0 {
			return "", errors.New("empty domain")
		}
		hostRaw := make([]byte, ln)
		if _, err := io.ReadFull(conn, hostRaw); err != nil {
			return "", fmt.Errorf("read domain: %w", err)
		}
		return string(hostRaw), nil
	default:
		return "", fmt.Errorf("unsupported atyp: %d", atyp)
	}
}

func writeMethodSelection(conn net.Conn, method byte) error {
	_, err := conn.Write([]byte{socksVer5, method})
	return err
}

func writeSocksReply(conn net.Conn, reply byte) error {
	// BND.ADDR/BND.PORT are not used by CONNECT client in this MVP.
	out := []byte{
		socksVer5,
		reply,
		0x00,
		socksAtypIPv4,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
	_, err := conn.Write(out)
	return err
}

func proxyBidirectional(local net.Conn, remote sessionclient.TCPFlow, client *sessionclient.Client, controller *policyController, fs *flowState) {
	defer controller.unregisterFlow(fs.id)

	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			_ = local.Close()
			_ = remote.Close()
			_ = client.Close()
		})
	}

	upWriter := &flowWriter{
		dst:       remote,
		flowBytes: &fs.upBytes,
		total:     &controller.totalUpBytes,
	}
	downWriter := &flowWriter{
		dst:       local,
		flowBytes: &fs.downBytes,
		total:     &controller.totalDownBytes,
	}

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(upWriter, local)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(downWriter, remote)
		errCh <- err
	}()

	first := <-errCh
	closeAll()
	second := <-errCh

	if !isExpectedPipeErr(first) {
		controller.onTransportError("proxy_copy_up")
		log.Printf("proxy copy ended with error flow_id=%d dir=up: %v", fs.id, first)
	}
	if !isExpectedPipeErr(second) {
		controller.onTransportError("proxy_copy_down")
		log.Printf("proxy copy ended with error flow_id=%d dir=down: %v", fs.id, second)
	}
}

func isExpectedPipeErr(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return true
	}
	msg := err.Error()
	return msg == "use of closed network connection" || msg == "EOF"
}

func isExpectedProbeErr(err error) bool {
	if isExpectedPipeErr(err) {
		return true
	}
	if errors.Is(err, context.Canceled) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "application error 0x0") || strings.Contains(msg, "stream reset")
}
