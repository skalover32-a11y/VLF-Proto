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
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
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
	socksMethodUserPass     = 0x02
	socksMethodNoAcceptable = 0xff

	socksCmdConnect = 0x01
	socksCmdBind    = 0x02
	socksCmdUDP     = 0x03

	socksAtypIPv4   = 0x01
	socksAtypDomain = 0x03
	socksAtypIPv6   = 0x04

	socksUserAuthVer = 0x01

	socksReplySuccess            = 0x00
	socksReplyGeneralFailure     = 0x01
	socksReplyConnectionNotAllow = 0x02
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
	Atyp byte
	Host string
	Port int
}

type socksRequest struct {
	Cmd    byte
	Target socksTarget
}

type authMode string

const (
	authModeNone     authMode = "none"
	authModeUserPass authMode = "userpass"
)

type authConfig struct {
	mode     authMode
	username string
	password string
}

type clientMetrics struct {
	authFailures      atomic.Uint64
	connectTotal      atomic.Uint64
	bindTotal         atomic.Uint64
	udpAssociateTotal atomic.Uint64

	udpPacketsIn      atomic.Uint64
	udpPacketsOut     atomic.Uint64
	udpDropsFrag      atomic.Uint64
	udpDropsParse     atomic.Uint64
	udpDropsAssocFull atomic.Uint64
	udpDropsNATFull   atomic.Uint64
	udpDropsNotClient atomic.Uint64

	activeAssociations atomic.Int64
	activeNATEntries   atomic.Int64
}

type udpAssociationManager struct {
	controller     *policyController
	metrics        *clientMetrics
	connectTimeout time.Duration
	idleTimeout    time.Duration
	maxAssoc       int
	maxNAT         int

	mu     sync.Mutex
	nextID uint64
	items  map[uint64]*udpAssociation
}

type udpAssociation struct {
	id uint64

	controller     *policyController
	metrics        *clientMetrics
	connectTimeout time.Duration
	idleTimeout    time.Duration
	maxNAT         int

	tcpConn net.Conn
	udpConn *net.UDPConn

	clientIP net.IP

	clientMu  sync.RWMutex
	clientUDP *net.UDPAddr

	mu      sync.Mutex
	nat     map[string]*udpNATEntry
	closing chan struct{}
	wg      sync.WaitGroup

	closeOnce sync.Once
	onClose   func(id uint64)
}

type udpNATEntry struct {
	key    string
	target socksTarget

	client *sessionclient.Client
	flow   sessionclient.UDPFlow
	state  *flowState

	lastActive atomic.Int64
	closeOnce  sync.Once
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
	serverPortLegacy := flag.Int("port", 0, "deprecated: gateway port for both QUIC and TCP session lanes")
	serverPortUDP := flag.Int("port-udp", baseCfg.GatewayUDP, "gateway QUIC/UDP port")
	serverPortTCP := flag.Int("port-tcp", baseCfg.GatewayTCP, "gateway TCP session port")
	relayBase := flag.String("relay-base", baseCfg.RelayBase, "relay base URL (fallback)")
	connectTimeout := flag.Duration("connect-timeout", 10*time.Second, "dial/open timeout per CONNECT")
	udpIdleTimeout := flag.Duration("udp-idle-timeout", 60*time.Second, "UDP NAT idle timeout for SOCKS UDP ASSOCIATE")
	udpMaxAssociations := flag.Int("udp-max-associations", 128, "max concurrent UDP associations")
	udpMaxNAT := flag.Int("udp-max-nat", 4096, "max UDP NAT entries per association")
	modeRaw := flag.String("mode", "auto", "client mode: auto|normal|fast|survival")
	preferQUIC := flag.Bool("prefer-quic", baseCfg.PreferQUIC, "base prefer QUIC transport first")
	disableQUIC := flag.Bool("disable-quic", baseCfg.DisableQUIC, "disable QUIC transport")
	disableTCP := flag.Bool("disable-tcp-session", baseCfg.DisableTCPSession, "disable TCP session transport")
	allowRelay := flag.Bool("allow-relay-fallback", baseCfg.AllowRelay, "allow HTTP relay fallback")
	statsFormatRaw := flag.String("stats-format", "text", "stats output format: text|json")
	authModeRaw := flag.String("auth", string(authModeNone), "SOCKS auth mode: none|userpass")
	username := flag.String("username", "", "SOCKS username for --auth userpass")
	password := flag.String("password", "", "SOCKS password for --auth userpass")
	metricsListen := flag.String("metrics-listen", "127.0.0.1:2113", "metrics listen address (empty disables)")
	clientID := flag.String("client-id", "", "override client id")
	secret := flag.String("secret", "", "override secret (plain or b64:...)")
	debug := flag.Bool("debug", baseCfg.Debug, "enable sessionclient debug logs")
	flag.Parse()

	mode, err := parseMode(*modeRaw)
	if err != nil {
		log.Fatalf("invalid --mode: %v", err)
	}
	if *serverPortLegacy < 0 || *serverPortLegacy > 65535 {
		log.Fatalf("invalid --port=%d", *serverPortLegacy)
	}
	if *serverPortUDP <= 0 || *serverPortUDP > 65535 {
		log.Fatalf("invalid --port-udp=%d", *serverPortUDP)
	}
	if *serverPortTCP <= 0 || *serverPortTCP > 65535 {
		log.Fatalf("invalid --port-tcp=%d", *serverPortTCP)
	}
	if *connectTimeout <= 0 {
		*connectTimeout = 10 * time.Second
	}
	if *udpIdleTimeout <= 0 {
		*udpIdleTimeout = 60 * time.Second
	}
	if *udpMaxAssociations <= 0 {
		*udpMaxAssociations = 128
	}
	if *udpMaxNAT <= 0 {
		*udpMaxNAT = 4096
	}
	parsedStatsFormat, err := parseStatsFormat(*statsFormatRaw)
	if err != nil {
		log.Fatalf("invalid --stats-format: %v", err)
	}
	authCfg, err := parseAuthConfig(*authModeRaw, *username, *password)
	if err != nil {
		log.Fatalf("invalid --auth config: %v", err)
	}

	cfg := baseCfg
	cfg.GatewayHost = *serverHost
	cfg.GatewayUDP = *serverPortUDP
	cfg.GatewayTCP = *serverPortTCP
	if *serverPortLegacy > 0 {
		cfg.GatewayUDP = *serverPortLegacy
		cfg.GatewayTCP = *serverPortLegacy
		log.Printf("warning: --port is deprecated; use --port-udp/--port-tcp for split transport ports")
	}
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
	metrics := &clientMetrics{}
	udpAssocMgr := newUDPAssociationManager(controller, metrics, *connectTimeout, *udpIdleTimeout, *udpMaxAssociations, *udpMaxNAT)
	defer udpAssocMgr.CloseAll("shutdown")

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
	if err := startMetricsServer(ctx, *metricsListen, metrics); err != nil {
		log.Fatalf("start metrics server: %v", err)
	}

	log.Printf("SOCKS5 listening on %s", *listenAddr)
	log.Printf("SOCKS auth mode=%s udp_idle_timeout=%s udp_max_associations=%d udp_max_nat=%d",
		authCfg.mode, *udpIdleTimeout, *udpMaxAssociations, *udpMaxNAT)
	log.Printf("Gateway host=%s quic_udp=%d tcp_session=%d mode=%s base_prefer_quic=%t base_disable_quic=%t disable_tcp=%t allow_relay=%t",
		cfg.GatewayHost, cfg.GatewayUDP, cfg.GatewayTCP, mode, cfg.PreferQUIC, cfg.DisableQUIC, cfg.DisableTCPSession, cfg.AllowRelay)

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
			handleConn(c, controller, udpAssocMgr, metrics, authCfg, *connectTimeout)
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

func (c *policyController) dialConfigUDP() (sessionclient.Config, clientMode) {
	cfg, mode := c.dialConfig()
	cfg.PreferQUIC = true
	cfg.DisableQUIC = false
	cfg.DisableTCPSession = true
	cfg.AllowRelay = false
	return cfg, mode
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

func handleConn(
	conn net.Conn,
	controller *policyController,
	udpMgr *udpAssociationManager,
	metrics *clientMetrics,
	authCfg authConfig,
	connectTimeout time.Duration,
) {
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	req, err := negotiateSOCKS5(conn, authCfg, metrics)
	if err != nil {
		log.Printf("SOCKS handshake failed from %s: %v", conn.RemoteAddr(), err)
		return
	}
	_ = conn.SetDeadline(time.Time{})

	switch req.Cmd {
	case socksCmdConnect:
		metrics.connectTotal.Add(1)
		handleConnect(conn, req.Target, controller, connectTimeout)
	case socksCmdBind:
		metrics.bindTotal.Add(1)
		handleBind(conn, req.Target, controller, connectTimeout)
	case socksCmdUDP:
		metrics.udpAssociateTotal.Add(1)
		if err := handleUDPAssociate(conn, req.Target, udpMgr); err != nil {
			log.Printf("UDP ASSOCIATE failed from %s: %v", conn.RemoteAddr(), err)
		}
	default:
		_ = writeSocksReply(conn, socksReplyCommandUnsupported)
		log.Printf("unsupported command %d from %s", req.Cmd, conn.RemoteAddr())
	}
}

func handleConnect(conn net.Conn, target socksTarget, controller *policyController, connectTimeout time.Duration) {
	admissionCtx, cancelAdmission := context.WithTimeout(context.Background(), connectTimeout)
	if err := controller.acquireFlowPermit(admissionCtx); err != nil {
		cancelAdmission()
		_ = writeSocksReply(conn, socksReplyGeneralFailure)
		log.Printf("flow admission denied for CONNECT %s -> %s:%d: %v", conn.RemoteAddr(), target.Host, target.Port, err)
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
		log.Printf("open tcp flow failed mode=%s for CONNECT %s -> %s:%d: %v", mode, conn.RemoteAddr(), target.Host, target.Port, err)
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

func handleBind(conn net.Conn, target socksTarget, controller *policyController, connectTimeout time.Duration) {
	// Practical BIND implementation over VLF TCP flow: send two success replies and proxy bytes.
	// This supports clients that require CMD=BIND semantics while keeping transport path unified.
	admissionCtx, cancelAdmission := context.WithTimeout(context.Background(), connectTimeout)
	if err := controller.acquireFlowPermit(admissionCtx); err != nil {
		cancelAdmission()
		_ = writeSocksReply(conn, socksReplyGeneralFailure)
		log.Printf("flow admission denied for BIND %s -> %s:%d: %v", conn.RemoteAddr(), target.Host, target.Port, err)
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
		log.Printf("session dial failed mode=%s for BIND %s -> %s:%d: %v", mode, conn.RemoteAddr(), target.Host, target.Port, err)
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
		log.Printf("open tcp flow failed mode=%s for BIND %s -> %s:%d: %v", mode, conn.RemoteAddr(), target.Host, target.Port, err)
		return
	}

	if err := writeSocksReply(conn, socksReplySuccess); err != nil {
		if permitHeld {
			controller.releaseFlowPermit()
			permitHeld = false
		}
		controller.onTransportError("write_bind_reply1_failed")
		_ = flow.Close()
		_ = client.Close()
		log.Printf("failed to send BIND first reply to %s: %v", conn.RemoteAddr(), err)
		return
	}
	if err := writeSocksReply(conn, socksReplySuccess); err != nil {
		if permitHeld {
			controller.releaseFlowPermit()
			permitHeld = false
		}
		controller.onTransportError("write_bind_reply2_failed")
		_ = flow.Close()
		_ = client.Close()
		log.Printf("failed to send BIND second reply to %s: %v", conn.RemoteAddr(), err)
		return
	}

	fs := controller.registerFlow(client, client.Transport(), time.Since(setupStart))
	permitHeld = false
	log.Printf("proxy BIND %s -> %s:%d via %s mode=%s flow_id=%d", conn.RemoteAddr(), target.Host, target.Port, client.Transport(), mode, fs.id)
	proxyBidirectional(conn, flow, client, controller, fs)
}

func handleUDPAssociate(conn net.Conn, target socksTarget, mgr *udpAssociationManager) error {
	assoc, bindAddr, err := mgr.Create(conn, target)
	if err != nil {
		_ = writeSocksReply(conn, socksReplyGeneralFailure)
		return err
	}
	if err := writeSocksReplyAddr(conn, socksReplySuccess, udpAddrToSocksTarget(bindAddr)); err != nil {
		assoc.Close("write_udp_associate_reply_failed")
		return err
	}
	log.Printf("UDP ASSOCIATE created id=%d client=%s bind=%s", assoc.id, conn.RemoteAddr(), bindAddr.String())
	assoc.Serve()
	return nil
}

func negotiateSOCKS5(conn net.Conn, authCfg authConfig, metrics *clientMetrics) (socksRequest, error) {
	var greetHdr [2]byte
	if _, err := io.ReadFull(conn, greetHdr[:]); err != nil {
		return socksRequest{}, fmt.Errorf("read greeting header: %w", err)
	}
	if greetHdr[0] != socksVer5 {
		return socksRequest{}, fmt.Errorf("unsupported SOCKS version: %d", greetHdr[0])
	}

	nMethods := int(greetHdr[1])
	if nMethods <= 0 {
		return socksRequest{}, errors.New("no auth methods provided")
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return socksRequest{}, fmt.Errorf("read methods: %w", err)
	}

	selectedMethod := pickMethod(methods, authCfg.mode)
	if selectedMethod == socksMethodNoAcceptable {
		_ = writeMethodSelection(conn, socksMethodNoAcceptable)
		return socksRequest{}, errors.New("client does not support configured auth method")
	}
	if err := writeMethodSelection(conn, selectedMethod); err != nil {
		return socksRequest{}, fmt.Errorf("write method selection: %w", err)
	}
	if selectedMethod == socksMethodUserPass {
		if err := verifyUserPassAuth(conn, authCfg); err != nil {
			metrics.authFailures.Add(1)
			return socksRequest{}, err
		}
	}

	var reqHdr [4]byte
	if _, err := io.ReadFull(conn, reqHdr[:]); err != nil {
		return socksRequest{}, fmt.Errorf("read request header: %w", err)
	}
	if reqHdr[0] != socksVer5 {
		return socksRequest{}, fmt.Errorf("invalid request version: %d", reqHdr[0])
	}
	cmd := reqHdr[1]
	if cmd != socksCmdConnect && cmd != socksCmdBind && cmd != socksCmdUDP {
		_ = writeSocksReply(conn, socksReplyCommandUnsupported)
		return socksRequest{}, fmt.Errorf("unsupported cmd: %d", cmd)
	}

	target, err := readTarget(conn, reqHdr[3])
	if err != nil {
		_ = writeSocksReply(conn, socksReplyAddrUnsupported)
		return socksRequest{}, err
	}

	return socksRequest{Cmd: cmd, Target: target}, nil
}

func readTarget(conn net.Conn, atyp byte) (socksTarget, error) {
	target := socksTarget{Atyp: atyp}
	switch atyp {
	case socksAtypIPv4:
		var ipRaw [4]byte
		if _, err := io.ReadFull(conn, ipRaw[:]); err != nil {
			return target, fmt.Errorf("read ipv4: %w", err)
		}
		target.Host = net.IP(ipRaw[:]).String()
	case socksAtypIPv6:
		var ipRaw [16]byte
		if _, err := io.ReadFull(conn, ipRaw[:]); err != nil {
			return target, fmt.Errorf("read ipv6: %w", err)
		}
		target.Host = net.IP(ipRaw[:]).String()
	case socksAtypDomain:
		var lnRaw [1]byte
		if _, err := io.ReadFull(conn, lnRaw[:]); err != nil {
			return target, fmt.Errorf("read domain length: %w", err)
		}
		ln := int(lnRaw[0])
		if ln <= 0 {
			return target, errors.New("empty domain")
		}
		hostRaw := make([]byte, ln)
		if _, err := io.ReadFull(conn, hostRaw); err != nil {
			return target, fmt.Errorf("read domain: %w", err)
		}
		target.Host = string(hostRaw)
	default:
		return target, fmt.Errorf("unsupported atyp: %d", atyp)
	}

	var portRaw [2]byte
	if _, err := io.ReadFull(conn, portRaw[:]); err != nil {
		return target, fmt.Errorf("read target port: %w", err)
	}
	target.Port = int(binary.BigEndian.Uint16(portRaw[:]))
	if target.Port < 0 || target.Port > 65535 {
		return target, fmt.Errorf("invalid target port: %d", target.Port)
	}
	return target, nil
}

func writeMethodSelection(conn net.Conn, method byte) error {
	_, err := conn.Write([]byte{socksVer5, method})
	return err
}

func writeSocksReply(conn net.Conn, reply byte) error {
	return writeSocksReplyAddr(conn, reply, socksTarget{
		Atyp: socksAtypIPv4,
		Host: "0.0.0.0",
		Port: 0,
	})
}

func writeSocksReplyAddr(conn net.Conn, reply byte, bind socksTarget) error {
	out := make([]byte, 0, 4+32)
	out = append(out, socksVer5, reply, 0x00)
	addrRaw, err := encodeTargetAddr(bind)
	if err != nil {
		return err
	}
	out = append(out, addrRaw...)
	port := bind.Port
	if port < 0 || port > 65535 {
		port = 0
	}
	out = append(out, byte(port>>8), byte(port))
	_, err = conn.Write(out)
	return err
}

func parseAuthConfig(modeRaw, username, password string) (authConfig, error) {
	mode := authMode(strings.ToLower(strings.TrimSpace(modeRaw)))
	switch mode {
	case authModeNone:
		return authConfig{mode: authModeNone}, nil
	case authModeUserPass:
		if username == "" || password == "" {
			return authConfig{}, errors.New("username and password are required for --auth userpass")
		}
		return authConfig{
			mode:     authModeUserPass,
			username: username,
			password: password,
		}, nil
	default:
		return authConfig{}, fmt.Errorf("unsupported mode %q", modeRaw)
	}
}

func pickMethod(methods []byte, mode authMode) byte {
	has := func(want byte) bool {
		for _, m := range methods {
			if m == want {
				return true
			}
		}
		return false
	}

	switch mode {
	case authModeNone:
		if has(socksMethodNoAuth) {
			return socksMethodNoAuth
		}
	case authModeUserPass:
		if has(socksMethodUserPass) {
			return socksMethodUserPass
		}
	}
	return socksMethodNoAcceptable
}

func verifyUserPassAuth(conn net.Conn, cfg authConfig) error {
	var ver [1]byte
	if _, err := io.ReadFull(conn, ver[:]); err != nil {
		return fmt.Errorf("read user/pass version: %w", err)
	}
	if ver[0] != socksUserAuthVer {
		_, _ = conn.Write([]byte{socksUserAuthVer, 0x01})
		return fmt.Errorf("invalid user/pass version: %d", ver[0])
	}

	var ulnRaw [1]byte
	if _, err := io.ReadFull(conn, ulnRaw[:]); err != nil {
		return fmt.Errorf("read username length: %w", err)
	}
	uln := int(ulnRaw[0])
	if uln <= 0 {
		_, _ = conn.Write([]byte{socksUserAuthVer, 0x01})
		return errors.New("empty username")
	}

	userRaw := make([]byte, uln)
	if _, err := io.ReadFull(conn, userRaw); err != nil {
		return fmt.Errorf("read username: %w", err)
	}

	var plnRaw [1]byte
	if _, err := io.ReadFull(conn, plnRaw[:]); err != nil {
		return fmt.Errorf("read password length: %w", err)
	}
	pln := int(plnRaw[0])
	if pln <= 0 {
		_, _ = conn.Write([]byte{socksUserAuthVer, 0x01})
		return errors.New("empty password")
	}

	passRaw := make([]byte, pln)
	if _, err := io.ReadFull(conn, passRaw); err != nil {
		return fmt.Errorf("read password: %w", err)
	}

	if string(userRaw) != cfg.username || string(passRaw) != cfg.password {
		_, _ = conn.Write([]byte{socksUserAuthVer, 0x01})
		return errors.New("invalid username/password")
	}
	_, err := conn.Write([]byte{socksUserAuthVer, 0x00})
	return err
}

func encodeTargetAddr(target socksTarget) ([]byte, error) {
	switch target.Atyp {
	case socksAtypIPv4:
		ip := net.ParseIP(target.Host).To4()
		if ip == nil {
			return nil, fmt.Errorf("invalid ipv4 addr: %q", target.Host)
		}
		out := make([]byte, 0, 5)
		out = append(out, socksAtypIPv4)
		out = append(out, ip...)
		return out, nil
	case socksAtypIPv6:
		ip := net.ParseIP(target.Host)
		if ip == nil || ip.To16() == nil {
			return nil, fmt.Errorf("invalid ipv6 addr: %q", target.Host)
		}
		out := make([]byte, 0, 17)
		out = append(out, socksAtypIPv6)
		out = append(out, ip.To16()...)
		return out, nil
	case socksAtypDomain:
		host := strings.TrimSpace(target.Host)
		if host == "" || len(host) > 255 {
			return nil, fmt.Errorf("invalid domain addr: %q", target.Host)
		}
		out := make([]byte, 0, 2+len(host))
		out = append(out, socksAtypDomain, byte(len(host)))
		out = append(out, host...)
		return out, nil
	default:
		// Fallback: infer from host.
		if ip := net.ParseIP(target.Host); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				return encodeTargetAddr(socksTarget{Atyp: socksAtypIPv4, Host: ip4.String(), Port: target.Port})
			}
			return encodeTargetAddr(socksTarget{Atyp: socksAtypIPv6, Host: ip.String(), Port: target.Port})
		}
		return encodeTargetAddr(socksTarget{Atyp: socksAtypDomain, Host: target.Host, Port: target.Port})
	}
}

func udpAddrToSocksTarget(addr *net.UDPAddr) socksTarget {
	if addr == nil {
		return socksTarget{Atyp: socksAtypIPv4, Host: "0.0.0.0", Port: 0}
	}
	if ip4 := addr.IP.To4(); ip4 != nil {
		return socksTarget{Atyp: socksAtypIPv4, Host: ip4.String(), Port: addr.Port}
	}
	if ip16 := addr.IP.To16(); ip16 != nil {
		return socksTarget{Atyp: socksAtypIPv6, Host: ip16.String(), Port: addr.Port}
	}
	return socksTarget{Atyp: socksAtypIPv4, Host: "0.0.0.0", Port: addr.Port}
}

func parseSocksUDPDatagram(raw []byte) (frag byte, target socksTarget, payload []byte, err error) {
	if len(raw) < 4 {
		return 0, target, nil, errors.New("udp datagram too short")
	}
	if raw[0] != 0x00 || raw[1] != 0x00 {
		return 0, target, nil, errors.New("invalid udp rsv")
	}

	frag = raw[2]
	atyp := raw[3]
	target.Atyp = atyp
	offset := 4

	switch atyp {
	case socksAtypIPv4:
		if len(raw) < offset+4+2 {
			return frag, target, nil, errors.New("short udp ipv4 header")
		}
		target.Host = net.IP(raw[offset : offset+4]).String()
		offset += 4
	case socksAtypIPv6:
		if len(raw) < offset+16+2 {
			return frag, target, nil, errors.New("short udp ipv6 header")
		}
		target.Host = net.IP(raw[offset : offset+16]).String()
		offset += 16
	case socksAtypDomain:
		if len(raw) < offset+1 {
			return frag, target, nil, errors.New("short udp domain length")
		}
		ln := int(raw[offset])
		offset++
		if ln <= 0 || len(raw) < offset+ln+2 {
			return frag, target, nil, errors.New("invalid udp domain length")
		}
		target.Host = string(raw[offset : offset+ln])
		offset += ln
	default:
		return frag, target, nil, fmt.Errorf("unsupported udp atyp: %d", atyp)
	}

	target.Port = int(binary.BigEndian.Uint16(raw[offset : offset+2]))
	offset += 2
	if target.Port < 0 || target.Port > 65535 {
		return frag, target, nil, fmt.Errorf("invalid udp target port: %d", target.Port)
	}
	payload = raw[offset:]
	return frag, target, payload, nil
}

func buildSocksUDPDatagram(target socksTarget, payload []byte) ([]byte, error) {
	addrRaw, err := encodeTargetAddr(target)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 3+len(addrRaw)+2+len(payload))
	out = append(out, 0x00, 0x00, 0x00) // RSV + FRAG=0
	out = append(out, addrRaw...)
	port := target.Port
	if port < 0 || port > 65535 {
		port = 0
	}
	out = append(out, byte(port>>8), byte(port))
	out = append(out, payload...)
	return out, nil
}

func targetKey(target socksTarget) string {
	host := strings.ToLower(strings.TrimSpace(target.Host))
	return fmt.Sprintf("%d|%s|%d", target.Atyp, host, target.Port)
}

func startMetricsServer(ctx context.Context, addr string, m *clientMetrics) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = io.WriteString(w, m.prometheus())
	})
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shCtx)
	}()
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("metrics server stopped with error: %v", err)
		}
	}()

	log.Printf("metrics listening on %s/metrics", addr)
	return nil
}

func (m *clientMetrics) prometheus() string {
	var b strings.Builder
	writeCounter := func(name string, value uint64) {
		b.WriteString(name)
		b.WriteByte(' ')
		b.WriteString(strconv.FormatUint(value, 10))
		b.WriteByte('\n')
	}
	writeGauge := func(name string, value int64) {
		b.WriteString(name)
		b.WriteByte(' ')
		b.WriteString(strconv.FormatInt(value, 10))
		b.WriteByte('\n')
	}

	writeCounter("vlf_socks_auth_failures_total", m.authFailures.Load())
	writeCounter("vlf_socks_connect_total", m.connectTotal.Load())
	writeCounter("vlf_socks_bind_total", m.bindTotal.Load())
	writeCounter("vlf_socks_udp_associate_total", m.udpAssociateTotal.Load())
	writeCounter("vlf_socks_udp_packets_in_total", m.udpPacketsIn.Load())
	writeCounter("vlf_socks_udp_packets_out_total", m.udpPacketsOut.Load())
	writeCounter("vlf_socks_udp_drops_frag_total", m.udpDropsFrag.Load())
	writeCounter("vlf_socks_udp_drops_parse_total", m.udpDropsParse.Load())
	writeCounter("vlf_socks_udp_drops_assoc_limit_total", m.udpDropsAssocFull.Load())
	writeCounter("vlf_socks_udp_drops_nat_limit_total", m.udpDropsNATFull.Load())
	writeCounter("vlf_socks_udp_drops_not_client_total", m.udpDropsNotClient.Load())
	writeGauge("vlf_socks_udp_active_associations", m.activeAssociations.Load())
	writeGauge("vlf_socks_udp_active_nat_entries", m.activeNATEntries.Load())
	return b.String()
}

func newUDPAssociationManager(
	controller *policyController,
	metrics *clientMetrics,
	connectTimeout time.Duration,
	idleTimeout time.Duration,
	maxAssoc int,
	maxNAT int,
) *udpAssociationManager {
	if idleTimeout <= 0 {
		idleTimeout = 60 * time.Second
	}
	if maxAssoc <= 0 {
		maxAssoc = 128
	}
	if maxNAT <= 0 {
		maxNAT = 4096
	}
	return &udpAssociationManager{
		controller:     controller,
		metrics:        metrics,
		connectTimeout: connectTimeout,
		idleTimeout:    idleTimeout,
		maxAssoc:       maxAssoc,
		maxNAT:         maxNAT,
		items:          make(map[uint64]*udpAssociation),
	}
}

func (m *udpAssociationManager) Create(tcpConn net.Conn, reqTarget socksTarget) (*udpAssociation, *net.UDPAddr, error) {
	bindIP := net.IPv4(127, 0, 0, 1)
	if laddr, ok := tcpConn.LocalAddr().(*net.TCPAddr); ok && laddr.IP != nil && !laddr.IP.IsUnspecified() {
		if laddr.IP.To4() != nil {
			bindIP = laddr.IP.To4()
		} else if laddr.IP.To16() != nil {
			bindIP = laddr.IP
		}
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP, Port: 0})
	if err != nil {
		return nil, nil, err
	}

	m.mu.Lock()
	if len(m.items) >= m.maxAssoc {
		m.mu.Unlock()
		_ = udpConn.Close()
		m.metrics.udpDropsAssocFull.Add(1)
		return nil, nil, fmt.Errorf("max udp associations reached (%d)", m.maxAssoc)
	}

	m.nextID++
	id := m.nextID
	assoc := &udpAssociation{
		id:             id,
		controller:     m.controller,
		metrics:        m.metrics,
		connectTimeout: m.connectTimeout,
		idleTimeout:    m.idleTimeout,
		maxNAT:         m.maxNAT,
		tcpConn:        tcpConn,
		udpConn:        udpConn,
		nat:            make(map[string]*udpNATEntry),
		closing:        make(chan struct{}),
		onClose: func(closeID uint64) {
			m.mu.Lock()
			delete(m.items, closeID)
			m.mu.Unlock()
			m.metrics.activeAssociations.Add(-1)
		},
	}
	m.items[id] = assoc
	m.metrics.activeAssociations.Add(1)
	m.mu.Unlock()

	if raddr, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok && raddr.IP != nil {
		assoc.clientIP = append(net.IP(nil), raddr.IP...)
	}

	if reqTarget.Port > 0 && reqTarget.Host != "" {
		if ip := net.ParseIP(reqTarget.Host); ip != nil {
			assoc.clientUDP = &net.UDPAddr{IP: ip, Port: reqTarget.Port}
		}
	}

	addr, _ := udpConn.LocalAddr().(*net.UDPAddr)
	return assoc, addr, nil
}

func (m *udpAssociationManager) CloseAll(reason string) {
	m.mu.Lock()
	snapshot := make([]*udpAssociation, 0, len(m.items))
	for _, assoc := range m.items {
		snapshot = append(snapshot, assoc)
	}
	m.mu.Unlock()

	for _, assoc := range snapshot {
		assoc.Close(reason)
	}
}

func (a *udpAssociation) Serve() {
	a.wg.Add(3)
	go func() {
		defer a.wg.Done()
		a.readClientPackets()
	}()
	go func() {
		defer a.wg.Done()
		a.janitorLoop()
	}()
	go func() {
		defer a.wg.Done()
		_, _ = io.Copy(io.Discard, a.tcpConn)
		a.Close("tcp_control_closed")
	}()

	<-a.closing
	a.wg.Wait()
}

func (a *udpAssociation) Close(reason string) {
	a.closeOnce.Do(func() {
		log.Printf("closing UDP association id=%d reason=%s", a.id, reason)
		close(a.closing)
		_ = a.tcpConn.Close()
		_ = a.udpConn.Close()

		a.mu.Lock()
		entries := make([]*udpNATEntry, 0, len(a.nat))
		for _, entry := range a.nat {
			entries = append(entries, entry)
		}
		a.nat = make(map[string]*udpNATEntry)
		a.mu.Unlock()

		for _, entry := range entries {
			a.closeEntry(entry, "association_close")
		}
		if a.onClose != nil {
			a.onClose(a.id)
		}
	})
}

func (a *udpAssociation) readClientPackets() {
	buf := make([]byte, 64*1024)
	for {
		_ = a.udpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, srcAddr, err := a.udpConn.ReadFromUDP(buf)
		if err != nil {
			if isTimeoutErr(err) {
				select {
				case <-a.closing:
					return
				default:
					continue
				}
			}
			select {
			case <-a.closing:
				return
			default:
			}
			log.Printf("udp association id=%d read failed: %v", a.id, err)
			a.Close("udp_read_failed")
			return
		}
		if n == 0 {
			continue
		}

		a.metrics.udpPacketsIn.Add(1)
		if !a.acceptClientSource(srcAddr) {
			a.metrics.udpDropsNotClient.Add(1)
			continue
		}

		frag, target, payload, err := parseSocksUDPDatagram(buf[:n])
		if err != nil {
			a.metrics.udpDropsParse.Add(1)
			log.Printf("udp association id=%d parse failed: %v", a.id, err)
			continue
		}
		if frag != 0 {
			a.metrics.udpDropsFrag.Add(1)
			log.Printf("udp association id=%d unsupported FRAG=%d target=%s:%d", a.id, frag, target.Host, target.Port)
			continue
		}
		if len(payload) == 0 {
			continue
		}

		entry, getErr := a.getOrCreateEntry(target)
		if getErr != nil {
			log.Printf("udp association id=%d create entry failed target=%s:%d: %v", a.id, target.Host, target.Port, getErr)
			continue
		}

		sendCtx, cancel := context.WithTimeout(context.Background(), a.connectTimeout)
		sendErr := entry.flow.Send(sendCtx, payload)
		cancel()
		if sendErr != nil {
			a.controller.onTransportError("socks_udp_send_failed")
			a.closeEntry(entry, "udp_send_failed")
			continue
		}

		entry.lastActive.Store(time.Now().UnixNano())
		entry.state.upBytes.Add(int64(len(payload)))
		a.controller.totalUpBytes.Add(int64(len(payload)))
	}
}

func (a *udpAssociation) janitorLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.closing:
			return
		case now := <-ticker.C:
			cutoff := now.Add(-a.idleTimeout).UnixNano()
			var stale []*udpNATEntry
			a.mu.Lock()
			for _, entry := range a.nat {
				if entry.lastActive.Load() < cutoff {
					stale = append(stale, entry)
				}
			}
			a.mu.Unlock()

			for _, entry := range stale {
				a.closeEntry(entry, "udp_idle_timeout")
			}
		}
	}
}

func (a *udpAssociation) acceptClientSource(src *net.UDPAddr) bool {
	if src == nil || src.IP == nil {
		return false
	}
	if a.clientIP != nil && !src.IP.Equal(a.clientIP) {
		return false
	}

	a.clientMu.Lock()
	if a.clientUDP == nil {
		a.clientUDP = &net.UDPAddr{IP: append(net.IP(nil), src.IP...), Port: src.Port}
	} else if a.clientUDP.IP.Equal(src.IP) {
		a.clientUDP.Port = src.Port
	}
	a.clientMu.Unlock()
	return true
}

func (a *udpAssociation) clientEndpoint() *net.UDPAddr {
	a.clientMu.RLock()
	defer a.clientMu.RUnlock()
	if a.clientUDP == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), a.clientUDP.IP...), Port: a.clientUDP.Port}
}

func (a *udpAssociation) getOrCreateEntry(target socksTarget) (*udpNATEntry, error) {
	key := targetKey(target)

	a.mu.Lock()
	if entry := a.nat[key]; entry != nil {
		a.mu.Unlock()
		return entry, nil
	}
	if len(a.nat) >= a.maxNAT {
		a.mu.Unlock()
		a.metrics.udpDropsNATFull.Add(1)
		return nil, fmt.Errorf("max udp nat entries reached (%d)", a.maxNAT)
	}
	a.mu.Unlock()

	admissionCtx, cancelAdmission := context.WithTimeout(context.Background(), a.connectTimeout)
	if err := a.controller.acquireFlowPermit(admissionCtx); err != nil {
		cancelAdmission()
		return nil, err
	}
	cancelAdmission()
	permitHeld := true

	cfg, mode := a.controller.dialConfigUDP()
	setupStart := time.Now()

	dialCtx, cancel := context.WithTimeout(context.Background(), a.connectTimeout)
	client, err := sessionclient.Dial(dialCtx, cfg)
	cancel()
	if err != nil {
		if permitHeld {
			a.controller.releaseFlowPermit()
		}
		a.controller.onDialError(cfg, err)
		return nil, fmt.Errorf("dial udp session mode=%s: %w", mode, err)
	}
	a.controller.onDialSuccess(mode, cfg, client.Transport())

	openCtx, cancel := context.WithTimeout(context.Background(), a.connectTimeout)
	flow, err := client.OpenUDPFlow(openCtx, target.Host, target.Port)
	cancel()
	if err != nil {
		if permitHeld {
			a.controller.releaseFlowPermit()
		}
		a.controller.onTransportError("open_udp_flow_failed")
		_ = client.Close()
		return nil, err
	}

	fs := a.controller.registerFlow(client, client.Transport(), time.Since(setupStart))
	permitHeld = false

	entry := &udpNATEntry{
		key:    key,
		target: target,
		client: client,
		flow:   flow,
		state:  fs,
	}
	entry.lastActive.Store(time.Now().UnixNano())

	a.mu.Lock()
	// If another goroutine created same entry while we were dialing, use it and close ours.
	if existing := a.nat[key]; existing != nil {
		a.mu.Unlock()
		a.closeEntry(entry, "duplicate_entry_replace")
		return existing, nil
	}
	a.nat[key] = entry
	a.metrics.activeNATEntries.Add(1)
	a.mu.Unlock()

	log.Printf("udp association id=%d opened flow target=%s:%d via %s flow_id=%d",
		a.id, target.Host, target.Port, client.Transport(), fs.id)

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.reverseLoop(entry)
	}()

	return entry, nil
}

func (a *udpAssociation) reverseLoop(entry *udpNATEntry) {
	for {
		recvCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		payload, err := entry.flow.Recv(recvCtx)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				select {
				case <-a.closing:
					return
				default:
					continue
				}
			}
			if isExpectedUDPErr(err) {
				a.closeEntry(entry, "udp_recv_closed")
				return
			}
			a.controller.onTransportError("socks_udp_recv_failed")
			log.Printf("udp association id=%d reverse recv failed target=%s:%d: %v", a.id, entry.target.Host, entry.target.Port, err)
			a.closeEntry(entry, "udp_recv_failed")
			return
		}
		if len(payload) == 0 {
			continue
		}

		clientAddr := a.clientEndpoint()
		if clientAddr == nil {
			continue
		}

		raw, buildErr := buildSocksUDPDatagram(entry.target, payload)
		if buildErr != nil {
			a.metrics.udpDropsParse.Add(1)
			continue
		}
		_ = a.udpConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := a.udpConn.WriteToUDP(raw, clientAddr); err != nil {
			if isExpectedUDPErr(err) {
				a.closeEntry(entry, "udp_write_closed")
				return
			}
			a.controller.onTransportError("socks_udp_write_client_failed")
			log.Printf("udp association id=%d reverse write failed target=%s:%d: %v", a.id, entry.target.Host, entry.target.Port, err)
			continue
		}

		a.metrics.udpPacketsOut.Add(1)
		entry.lastActive.Store(time.Now().UnixNano())
		entry.state.downBytes.Add(int64(len(payload)))
		a.controller.totalDownBytes.Add(int64(len(payload)))
	}
}

func (a *udpAssociation) closeEntry(entry *udpNATEntry, reason string) {
	if entry == nil {
		return
	}
	entry.closeOnce.Do(func() {
		a.mu.Lock()
		if cur := a.nat[entry.key]; cur == entry {
			delete(a.nat, entry.key)
			a.metrics.activeNATEntries.Add(-1)
		}
		a.mu.Unlock()

		if entry.flow != nil {
			_ = entry.flow.Close()
		}
		if entry.client != nil {
			_ = entry.client.Close()
		}
		if entry.state != nil {
			a.controller.unregisterFlow(entry.state.id)
		}
		log.Printf("udp association id=%d closed nat target=%s:%d reason=%s", a.id, entry.target.Host, entry.target.Port, reason)
	})
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

func isExpectedUDPErr(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return true
	}
	if isTimeoutErr(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "closed pipe") ||
		strings.Contains(msg, "application error 0x0")
}

func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
