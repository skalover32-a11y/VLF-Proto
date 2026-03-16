//go:build windows

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
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	gudp "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"vlf-runtime/internal/auth"
	"vlf-runtime/internal/sessionclient"
	tunio "vlf-runtime/internal/tun/iobased"
)

const (
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

	udpQUICBackoff             = 30 * time.Second
	managedClientProbeAge      = 12 * time.Second
	managedClientMaxIdle       = 45 * time.Second
	managedClientLeaseSkew     = 5 * time.Second
	probeFailureSuppressWindow = 10 * time.Second
	policyRecentActivityWindow = 10 * time.Second
	modeSwitchCooldown         = 5 * time.Second
	survivalEnterConfirmTicks  = 2
	survivalExitStableTicks    = 5
	survivalExitWeightedMax    = 1.0
	fastEnterConfirmTicks      = 2
	fastExitStableTicks        = 4
)

const (
	tokenElevationTypeDefault = 1
	tokenElevationTypeFull    = 2
	tokenElevationTypeLimited = 3
)

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
	clientKey string

	upBytes      atomic.Int64
	downBytes    atomic.Int64
	lastActivity atomic.Int64

	mu          sync.Mutex
	downSamples []downSample
}

type downSample struct {
	at    time.Time
	total int64
}

type rttSample struct {
	at            time.Time
	ms            float64
	transport     sessionclient.Transport
	clientKey     string
	reason        policyCandidateReason
	lowConfidence bool
}

type policyCandidateReason string

const (
	policyCandidateHealthy            policyCandidateReason = "healthy"
	policyCandidateLeaseExpiring      policyCandidateReason = "lease_expiring"
	policyCandidateLeaseExpired       policyCandidateReason = "lease_expired"
	policyCandidateControlLoopDead    policyCandidateReason = "control_loop_dead"
	policyCandidateSessionClosed      policyCandidateReason = "session_closed"
	policyCandidateProbeSuppressed    policyCandidateReason = "probe_suppressed"
	policyCandidateClientMarkedBad    policyCandidateReason = "client_marked_bad"
	policyCandidateTransportUnhealthy policyCandidateReason = "transport_unhealthy"
	policyCandidateNoRecentActivity   policyCandidateReason = "no_recent_activity"
	policyCandidateLowConfidence      policyCandidateReason = "low_confidence_sample"
)

type policyCandidate struct {
	flowID         uint64
	client         *sessionclient.Client
	clientKey      string
	transport      sessionclient.Transport
	reason         policyCandidateReason
	lowConfidence  bool
	lastActivityAt time.Time
}

type failureClass string

const (
	failureClassHardFailure           failureClass = "hard_failure"
	failureClassMeaningfulDegradation failureClass = "meaningful_degradation"
	failureClassLowConfidence         failureClass = "low_confidence_failure"
	failureClassIgnored               failureClass = "ignored_failure"
)

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
	dst          io.Writer
	flowBytes    *atomic.Int64
	total        *atomic.Int64
	lastActivity *atomic.Int64
}

func (w *flowWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	if n > 0 {
		w.flowBytes.Add(int64(n))
		w.total.Add(int64(n))
		if w.lastActivity != nil {
			w.lastActivity.Store(time.Now().UnixNano())
		}
	}
	return n, err
}

type policyController struct {
	baseCfg     sessionclient.Config
	configured  clientMode
	currentMode clientMode
	statsFormat statsFormat
	closeOnce   sync.Once

	mu                   sync.Mutex
	nextFlowID           uint64
	flows                map[uint64]*flowState
	clients              map[string]*managedClient
	lastTransport        sessionclient.Transport
	switches             uint64
	lastModeSwitchAt     time.Time
	lastModeSwitchReason string
	degradedTicks        int
	stableTicks          int
	fastSignalTicks      int
	fastQuietTicks       int

	quicFailTimes              []time.Time
	quicLowConfidenceFailTimes []time.Time
	errorSpikeTime             []time.Time
	errorLowConfidenceTimes    []time.Time
	survivalSince              time.Time
	survivalUntil              time.Time

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

type managedClient struct {
	key       string
	client    *sessionclient.Client
	transport sessionclient.Transport
	refCount  int
	broken    bool
	lastUsed  time.Time

	unusableReason string
	unusableSince  time.Time
	unusableUntil  time.Time
}

type managedClientLeaseDecision uint8

const (
	managedClientLeaseReuse managedClientLeaseDecision = iota
	managedClientLeaseExpiring
	managedClientLeaseExpired
)

type tunReadWriter struct {
	dev    tun.Device
	rSizes []int
	rBuffs [][]byte
	wBuffs [][]byte
	rMu    sync.Mutex
	wMu    sync.Mutex
}

type routeInfo struct {
	InterfaceIndex int    `json:"InterfaceIndex"`
	NextHop        string `json:"NextHop"`
}

type elevationState struct {
	Elevated      bool
	TokenElevated uint32
	TokenType     uint32
}

type udpOptions struct {
	DNSResolverHost string
	DNSResolverPort int
	DNSOverride     bool
	IdleTimeout     time.Duration
}

type udpFlowState struct {
	key        string
	srcIP      string
	srcPort    int
	dstIP      string
	dstPort    int
	targetHost string
	targetPort int

	local net.Conn

	ctx    context.Context
	cancel context.CancelFunc

	client    *sessionclient.Client
	clientKey string
	udpFlow   sessionclient.UDPFlow
	flowRef   *flowState

	lastActive atomic.Int64
	closeOnce  sync.Once
}

type udpManager struct {
	controller     *policyController
	connectTimeout time.Duration
	opts           udpOptions

	mu    sync.Mutex
	flows map[string]*udpFlowState

	stopCh chan struct{}
	doneCh chan struct{}

	quicBlockedUntil atomic.Int64
	quicBlockedAt    atomic.Int64
}

type cleanupStack struct {
	mu  sync.Mutex
	fns []func()
}

func (c *cleanupStack) Add(fn func()) {
	c.mu.Lock()
	c.fns = append(c.fns, fn)
	c.mu.Unlock()
}

func (c *cleanupStack) Run() {
	c.mu.Lock()
	fns := make([]func(), len(c.fns))
	copy(fns, c.fns)
	c.mu.Unlock()

	for i := len(fns) - 1; i >= 0; i-- {
		safeCall(fns[i])
	}
}

func safeCall(fn func()) {
	defer func() {
		_ = recover()
	}()
	fn()
}

func main() {
	baseCfg, err := sessionclient.LoadConfigFromEnv()
	if err != nil {
		log.Fatalf("load session config: %v", err)
	}

	tunNameFlag := flag.String("tun-name", "VLF-TUN", "Wintun interface name")
	tunIP := flag.String("tun-ip", "198.18.0.2", "TUN IPv4 address")
	tunPrefix := flag.Int("tun-prefix", 15, "TUN IPv4 prefix length")
	tunGateway := flag.String("tun-gw", "198.18.0.1", "TUN gateway IPv4")
	mtu := flag.Int("mtu", 1350, "TUN MTU")

	serverHost := flag.String("server", baseCfg.GatewayHost, "gateway host")
	serverPortLegacy := flag.Int("port", 0, "deprecated: gateway port for both QUIC and TCP session lanes")
	serverPortUDP := flag.Int("port-udp", baseCfg.GatewayUDP, "gateway QUIC/UDP port")
	serverPortTCP := flag.Int("port-tcp", baseCfg.GatewayTCP, "gateway TCP session port")
	relayBase := flag.String("relay-base", "", "relay base URL (fallback); default http://<gateway-ip>:8080")
	connectTimeout := flag.Duration("connect-timeout", 10*time.Second, "dial/open timeout per TCP flow")
	udpIdleTimeout := flag.Duration("udp-idle-timeout", 60*time.Second, "UDP NAT idle timeout")
	dnsResolver := flag.String("dns-resolver", "1.1.1.1:53", "upstream DNS resolver for intercepted UDP/53")
	dnsOverride := flag.Bool("dns-override", true, "redirect all UDP/53 flows to dns-resolver")
	modeRaw := flag.String("mode", "auto", "client mode: auto|normal|fast|survival")
	statsFormatRaw := flag.String("stats-format", "text", "stats output format: text|json")
	preferQUIC := flag.Bool("prefer-quic", baseCfg.PreferQUIC, "base prefer QUIC transport first")
	disableQUIC := flag.Bool("disable-quic", baseCfg.DisableQUIC, "disable QUIC transport")
	disableTCP := flag.Bool("disable-tcp-session", baseCfg.DisableTCPSession, "disable TCP session transport")
	allowRelay := flag.Bool("allow-relay-fallback", baseCfg.AllowRelay, "allow HTTP relay fallback")
	forceIPv4 := flag.Bool("force-ipv4", true, "force IPv4 for gateway session dials (recommended for IPv4 TUN mode)")
	clientID := flag.String("client-id", "", "override client id")
	secret := flag.String("secret", "", "override secret (plain or b64:...)")
	debug := flag.Bool("debug", baseCfg.Debug, "enable sessionclient debug logs")
	flag.Parse()

	mode, err := parseMode(*modeRaw)
	if err != nil {
		log.Fatalf("invalid --mode: %v", err)
	}
	sf, err := parseStatsFormat(*statsFormatRaw)
	if err != nil {
		log.Fatalf("invalid --stats-format: %v", err)
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
	if net.ParseIP(*tunIP) == nil {
		log.Fatalf("invalid --tun-ip=%s", *tunIP)
	}
	if net.ParseIP(*tunGateway) == nil {
		log.Fatalf("invalid --tun-gw=%s", *tunGateway)
	}
	if *tunPrefix <= 0 || *tunPrefix > 32 {
		log.Fatalf("invalid --tun-prefix=%d", *tunPrefix)
	}
	if *mtu < 1200 || *mtu > 9000 {
		log.Fatalf("invalid --mtu=%d (expected 1200..9000)", *mtu)
	}
	dnsHost, dnsPort, err := parseResolver(*dnsResolver)
	if err != nil {
		log.Fatalf("invalid --dns-resolver: %v", err)
	}
	if err := ensureElevated(); err != nil {
		log.Fatalf("admin privileges required: %v", err)
	}

	cfg := baseCfg
	cfg.GatewayHost = *serverHost
	cfg.GatewayDialHost = cfg.GatewayHost
	cfg.TLSServerName = cfg.GatewayHost
	cfg.GatewayUDP = *serverPortUDP
	cfg.GatewayTCP = *serverPortTCP
	if *serverPortLegacy > 0 {
		cfg.GatewayUDP = *serverPortLegacy
		cfg.GatewayTCP = *serverPortLegacy
		log.Printf("warning: --port is deprecated; use --port-udp/--port-tcp for split transport ports")
	}
	cfg.PreferQUIC = *preferQUIC
	cfg.DisableQUIC = *disableQUIC
	cfg.DisableTCPSession = *disableTCP
	cfg.AllowRelay = *allowRelay
	cfg.ForceIPv4 = *forceIPv4
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
	if cfg.DisableTCPSession && !cfg.AllowRelay {
		log.Printf("warning: running in QUIC-only mode (tcp session and relay fallback are disabled)")
	}
	if cfg.DisableQUIC {
		log.Printf("warning: QUIC is disabled; UDP-heavy apps/calls (Discord/Telegram calls, games, voice/video) may fail or degrade")
	}

	gatewayIP, err := resolveGatewayIPv4(cfg.GatewayHost)
	if err != nil {
		log.Fatalf("resolve gateway host %q: %v", cfg.GatewayHost, err)
	}
	cfg.GatewayDialHost = gatewayIP
	if strings.TrimSpace(*relayBase) != "" {
		cfg.RelayBase = strings.TrimSpace(*relayBase)
	} else {
		cfg.RelayBase = defaultRelayBase(cfg.GatewayDialHost)
	}
	route, err := findBestRouteTo(gatewayIP)
	if err != nil {
		log.Fatalf("find route to gateway ip %s: %v", gatewayIP, err)
	}
	if route.NextHop == "" {
		route.NextHop = "0.0.0.0"
	}

	log.Printf("gateway resolved: host=%s ip=%s route_if=%d route_nexthop=%s", cfg.GatewayHost, gatewayIP, route.InterfaceIndex, route.NextHop)
	log.Printf("gateway transport ports: quic_udp=%d tcp_session=%d relay=%s tls_sni=%s", cfg.GatewayUDP, cfg.GatewayTCP, cfg.RelayBase, cfg.TLSServerName)

	controller := newPolicyController(cfg, mode, sf)
	defer controller.Close()

	var cleanup cleanupStack
	defer cleanup.Run()

	dev, err := tun.CreateTUN(*tunNameFlag, *mtu)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "wintun.dll") {
			log.Fatalf("create wintun %q: %v; hint: place wintun.dll next to tun_client.exe or into C:\\Windows\\System32 (download: https://www.wintun.net/builds/wintun-0.14.1.zip)", *tunNameFlag, err)
		}
		log.Fatalf("create wintun %q: %v", *tunNameFlag, err)
	}
	cleanup.Add(func() {
		_ = dev.Close()
	})

	tunName, err := dev.Name()
	if err != nil {
		log.Fatalf("read tun name: %v", err)
	}

	if err := configureTunInterface(tunName, *tunIP, *tunPrefix, *tunGateway, *mtu); err != nil {
		log.Fatalf("configure tun interface %s: %v", tunName, err)
	}
	cleanup.Add(func() {
		_ = cleanupTunInterface(tunName, *tunIP, *tunGateway)
	})

	if err := addBypassRoute(gatewayIP, route); err != nil {
		log.Fatalf("add gateway bypass route for %s: %v", gatewayIP, err)
	}
	cleanup.Add(func() {
		_ = removeBypassRoute(gatewayIP, route)
	})

	if err := addSplitRoutes(tunName, *tunGateway); err != nil {
		log.Fatalf("add split routes via tun %s: %v", tunName, err)
	}
	cleanup.Add(func() {
		_ = removeSplitRoutes(tunName, *tunGateway)
	})

	tunMTU, err := dev.MTU()
	if err != nil || tunMTU <= 0 {
		tunMTU = *mtu
	}
	rw := newTunReadWriter(dev)
	ep, err := tunio.New(rw, uint32(tunMTU), 0)
	if err != nil {
		log.Fatalf("create tun netstack endpoint: %v", err)
	}
	cleanup.Add(func() {
		ep.Close()
		ep.Wait()
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	udpMgr := newUDPManager(controller, *connectTimeout, udpOptions{
		DNSResolverHost: dnsHost,
		DNSResolverPort: dnsPort,
		DNSOverride:     *dnsOverride,
		IdleTimeout:     *udpIdleTimeout,
	})
	defer udpMgr.Close()

	if _, err := buildNetstack(ep, &wg, controller, *connectTimeout, udpMgr); err != nil {
		log.Fatalf("init netstack: %v", err)
	}

	log.Printf("TUN client started: if=%s ip=%s/%d gw=%s mtu=%d mode=%s stats=%s dns_override=%t dns_resolver=%s:%d udp_idle=%s",
		tunName, *tunIP, *tunPrefix, *tunGateway, tunMTU, mode, sf, *dnsOverride, dnsHost, dnsPort, udpMgr.opts.IdleTimeout)
	log.Printf("split routes active: 0.0.0.0/1 and 128.0.0.0/1 via %s; bypass for gateway %s via if=%d nh=%s",
		*tunGateway, gatewayIP, route.InterfaceIndex, route.NextHop)

	<-ctx.Done()
	log.Printf("shutdown signal received")

	_ = dev.Close()
	udpMgr.Close()
	controller.Close()
	ep.Close()
	ep.Wait()

	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		log.Printf("shutdown timeout waiting workers; active_flows=%d", controller.ActiveFlowCount())
	}
}

func ensureElevated() error {
	state, err := queryElevationState()
	if err != nil {
		return fmt.Errorf("query token elevation: %w", err)
	}

	log.Printf("elevation check: elevated=%t token_elevation=%d token_elevation_type=%s(%d)",
		state.Elevated, state.TokenElevated, elevationTypeName(state.TokenType), state.TokenType)

	if !state.Elevated {
		return errors.New("run process as Administrator (elevated PowerShell)")
	}
	return nil
}

func queryElevationState() (elevationState, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return elevationState{}, err
	}
	defer token.Close()

	var tokenElevated uint32
	var outLen uint32
	if err := windows.GetTokenInformation(
		token,
		windows.TokenElevation,
		(*byte)(unsafe.Pointer(&tokenElevated)),
		uint32(unsafe.Sizeof(tokenElevated)),
		&outLen,
	); err != nil {
		return elevationState{}, err
	}

	var tokenType uint32
	outLen = 0
	if err := windows.GetTokenInformation(
		token,
		windows.TokenElevationType,
		(*byte)(unsafe.Pointer(&tokenType)),
		uint32(unsafe.Sizeof(tokenType)),
		&outLen,
	); err != nil {
		tokenType = 0
	}

	elevated := tokenElevated != 0 || tokenType == tokenElevationTypeFull
	return elevationState{
		Elevated:      elevated,
		TokenElevated: tokenElevated,
		TokenType:     tokenType,
	}, nil
}

func elevationTypeName(v uint32) string {
	switch v {
	case tokenElevationTypeDefault:
		return "default"
	case tokenElevationTypeFull:
		return "full"
	case tokenElevationTypeLimited:
		return "limited"
	default:
		return "unknown"
	}
}

func resolveGatewayIPv4(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String(), nil
		}
		return "", fmt.Errorf("host %q is not an IPv4 address", host)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return "", err
	}
	for _, ip := range addrs {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address found for %q", host)
}

func findBestRouteTo(remoteIP string) (routeInfo, error) {
	findScript := fmt.Sprintf(`
$ErrorActionPreference='Stop'
$r = Find-NetRoute -RemoteIPAddress %s -AddressFamily IPv4 |
  Sort-Object -Property @{Expression={ $_.RouteMetric + $_.InterfaceMetric }} |
  Select-Object -First 1 -Property InterfaceIndex,NextHop
if ($null -eq $r) { throw "route_not_found" }
$r | ConvertTo-Json -Compress
`, psQuote(remoteIP))

	raw, err := runPowerShell(findScript)
	if err != nil {
		fallbackScript := `
$ErrorActionPreference='Stop'
$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
  Sort-Object -Property @{Expression={ $_.RouteMetric + $_.InterfaceMetric }} |
  Select-Object -First 1 -Property InterfaceIndex,NextHop
if ($null -eq $r) { throw "default_route_not_found" }
$r | ConvertTo-Json -Compress
`
		raw, err = runPowerShell(fallbackScript)
		if err != nil {
			return routeInfo{}, err
		}
	}

	var out routeInfo
	if unmarshalErr := json.Unmarshal(raw, &out); unmarshalErr != nil {
		return routeInfo{}, fmt.Errorf("decode route json %q: %w", strings.TrimSpace(string(raw)), unmarshalErr)
	}
	if out.InterfaceIndex <= 0 {
		return routeInfo{}, fmt.Errorf("invalid route interface index: %d", out.InterfaceIndex)
	}
	return out, nil
}

func configureTunInterface(alias, ip string, prefix int, gw string, mtu int) error {
	script := fmt.Sprintf(`
$ErrorActionPreference='Stop'
$alias = %s
$ip = %s
$gw = %s
$prefix = %d
$mtu = %d

Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -NlMtuBytes $mtu -ErrorAction Stop | Out-Null
Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

New-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -IPAddress $ip -PrefixLength $prefix -DefaultGateway $gw -PolicyStore ActiveStore -ErrorAction Stop | Out-Null

Get-NetRoute -InterfaceAlias $alias -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
`, psQuote(alias), psQuote(ip), psQuote(gw), prefix, mtu)

	_, err := runPowerShell(script)
	return err
}

func cleanupTunInterface(alias, ip, gw string) error {
	script := fmt.Sprintf(`
$ErrorActionPreference='SilentlyContinue'
$alias = %s
$ip = %s
$gw = %s

Get-NetRoute -InterfaceAlias $alias -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -NextHop $gw | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -IPAddress $ip | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
`, psQuote(alias), psQuote(ip), psQuote(gw))

	_, err := runPowerShell(script)
	return err
}

func addSplitRoutes(alias, gw string) error {
	script := fmt.Sprintf(`
$ErrorActionPreference='Stop'
$alias = %s
$gw = %s
$prefixes = @('0.0.0.0/1','128.0.0.0/1')
foreach ($p in $prefixes) {
  Get-NetRoute -DestinationPrefix $p -InterfaceAlias $alias -NextHop $gw -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
  New-NetRoute -DestinationPrefix $p -InterfaceAlias $alias -NextHop $gw -RouteMetric 5 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
}
`, psQuote(alias), psQuote(gw))

	_, err := runPowerShell(script)
	return err
}

func removeSplitRoutes(alias, gw string) error {
	script := fmt.Sprintf(`
$ErrorActionPreference='SilentlyContinue'
$alias = %s
$gw = %s
Get-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias $alias -NextHop $gw | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
Get-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias $alias -NextHop $gw | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
`, psQuote(alias), psQuote(gw))

	_, err := runPowerShell(script)
	return err
}

func addBypassRoute(gatewayIP string, route routeInfo) error {
	nextHop := route.NextHop
	if nextHop == "" {
		nextHop = "0.0.0.0"
	}
	script := fmt.Sprintf(`
$ErrorActionPreference='Stop'
$prefix = %s
$idx = %d
$nh = %s
Get-NetRoute -DestinationPrefix $prefix -InterfaceIndex $idx -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $idx -NextHop $nh -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
`, psQuote(gatewayIP+"/32"), route.InterfaceIndex, psQuote(nextHop))

	_, err := runPowerShell(script)
	return err
}

func removeBypassRoute(gatewayIP string, route routeInfo) error {
	nextHop := route.NextHop
	if nextHop == "" {
		nextHop = "0.0.0.0"
	}
	script := fmt.Sprintf(`
$ErrorActionPreference='SilentlyContinue'
$prefix = %s
$idx = %d
$nh = %s
Get-NetRoute -DestinationPrefix $prefix -InterfaceIndex $idx -NextHop $nh -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
`, psQuote(gatewayIP+"/32"), route.InterfaceIndex, psQuote(nextHop))

	_, err := runPowerShell(script)
	return err
}

func runPowerShell(script string) ([]byte, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("powershell failed: %w output=%s", err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func newTunReadWriter(dev tun.Device) *tunReadWriter {
	return &tunReadWriter{
		dev:    dev,
		rSizes: make([]int, 1),
		rBuffs: make([][]byte, 1),
		wBuffs: make([][]byte, 1),
	}
}

func (t *tunReadWriter) Read(p []byte) (int, error) {
	t.rMu.Lock()
	defer t.rMu.Unlock()

	t.rBuffs[0] = p
	_, err := t.dev.Read(t.rBuffs, t.rSizes, 0)
	if err != nil {
		return 0, err
	}
	return t.rSizes[0], nil
}

func (t *tunReadWriter) Write(p []byte) (int, error) {
	t.wMu.Lock()
	defer t.wMu.Unlock()

	t.wBuffs[0] = p
	_, err := t.dev.Write(t.wBuffs, 0)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func buildNetstack(ep stack.LinkEndpoint, wg *sync.WaitGroup, controller *policyController, connectTimeout time.Duration, udpMgr *udpManager) (*stack.Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			gudp.NewProtocol,
		},
	})

	nicID := s.NextNICID()
	if err := s.CreateNICWithOptions(nicID, ep, stack.NICOptions{}); err != nil {
		return nil, fmt.Errorf("create netstack NIC: %s", err)
	}
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("set promiscuous mode: %s", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("set spoofing: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         nicID,
	}})

	forwarder := tcp.NewForwarder(s, 0, 2<<10, func(r *tcp.ForwarderRequest) {
		id := r.ID()

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		_ = setSocketOptions(s, ep)

		localConn := gonet.NewTCPConn(&wq, ep)
		dstIP := tcpipAddrToString(id.LocalAddress)
		srcIP := tcpipAddrToString(id.RemoteAddress)
		dstPort := int(id.LocalPort)
		srcPort := int(id.RemotePort)

		wg.Add(1)
		go func() {
			defer wg.Done()
			handleTCPFromTun(localConn, controller, connectTimeout, srcIP, srcPort, dstIP, dstPort)
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)

	udpForwarder := gudp.NewForwarder(s, func(r *gudp.ForwarderRequest) {
		id := r.ID()
		var wq waiter.Queue

		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return
		}
		localConn := gonet.NewUDPConn(&wq, ep)

		wg.Add(1)
		go func() {
			defer wg.Done()
			udpMgr.Handle(localConn, id)
		}()
	})
	s.SetTransportProtocolHandler(gudp.ProtocolNumber, udpForwarder.HandlePacket)
	return s, nil
}

func tcpipAddrToString(addr tcpip.Address) string {
	raw := addr.AsSlice()
	if len(raw) == 0 {
		return ""
	}
	return net.IP(raw).String()
}

func setSocketOptions(s *stack.Stack, ep tcpip.Endpoint) tcpip.Error {
	ep.SocketOptions().SetKeepAlive(true)
	if err := ep.SetSockOptInt(tcpip.KeepaliveCountOption, 9); err != nil {
		return err
	}
	idle := tcpip.KeepaliveIdleOption(60 * time.Second)
	if err := ep.SetSockOpt(&idle); err != nil {
		return err
	}
	interval := tcpip.KeepaliveIntervalOption(30 * time.Second)
	if err := ep.SetSockOpt(&interval); err != nil {
		return err
	}

	var sendRange tcpip.TCPSendBufferSizeRangeOption
	if err := s.TransportProtocolOption(header.TCPProtocolNumber, &sendRange); err == nil {
		ep.SocketOptions().SetSendBufferSize(int64(sendRange.Default), false)
	}
	var recvRange tcpip.TCPReceiveBufferSizeRangeOption
	if err := s.TransportProtocolOption(header.TCPProtocolNumber, &recvRange); err == nil {
		ep.SocketOptions().SetReceiveBufferSize(int64(recvRange.Default), false)
	}
	return nil
}

func handleTCPFromTun(local net.Conn, controller *policyController, connectTimeout time.Duration, srcIP string, srcPort int, dstIP string, dstPort int) {
	defer local.Close()

	if dstIP == "" || dstPort <= 0 {
		return
	}

	admissionCtx, cancelAdmission := context.WithTimeout(context.Background(), connectTimeout)
	if err := controller.acquireFlowPermit(admissionCtx); err != nil {
		cancelAdmission()
		log.Printf("flow admission denied src=%s:%d dst=%s:%d: %v", srcIP, srcPort, dstIP, dstPort, err)
		return
	}
	cancelAdmission()
	permitHeld := true

	cfg, mode := controller.dialConfig()
	setupStart := time.Now()

	dialCtx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	client, transport, clientKey, dialed, err := controller.acquireClient(dialCtx, cfg)
	cancel()
	if err != nil {
		if permitHeld {
			controller.releaseFlowPermit()
			permitHeld = false
		}
		controller.onDialError(cfg, err)
		log.Printf("session dial failed mode=%s for %s:%d -> %s:%d: %v", mode, srcIP, srcPort, dstIP, dstPort, err)
		return
	}
	if dialed {
		controller.onDialSuccess(mode, cfg, transport)
	}

	openCtx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	flow, err := client.OpenTCPFlow(openCtx, dstIP, dstPort)
	cancel()
	if err != nil {
		if permitHeld {
			controller.releaseFlowPermit()
			permitHeld = false
		}
		controller.onTransportError("open_tcp_flow_failed", client, clientKey, time.Now())
		controller.markClientBad(clientKey, err)
		controller.releaseClient(clientKey)
		log.Printf("open tcp flow failed mode=%s for %s:%d -> %s:%d: %v", mode, srcIP, srcPort, dstIP, dstPort, err)
		return
	}

	fs := controller.registerFlow(client, clientKey, transport, time.Since(setupStart))
	permitHeld = false

	log.Printf("tun tcp %s:%d -> %s:%d via %s mode=%s flow_id=%d", srcIP, srcPort, dstIP, dstPort, transport, mode, fs.id)
	proxyBidirectional(local, flow, controller, fs)
}

func parseResolver(raw string) (string, int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0, errors.New("empty resolver")
	}
	host, portRaw, err := net.SplitHostPort(raw)
	if err != nil {
		if !strings.Contains(raw, ":") {
			host = raw
			portRaw = "53"
		} else {
			return "", 0, err
		}
	}
	port, err := net.LookupPort("udp", portRaw)
	if err != nil {
		return "", 0, err
	}
	if host == "" {
		return "", 0, errors.New("resolver host is empty")
	}
	return host, port, nil
}

func defaultRelayBase(host string) string {
	h := strings.TrimSpace(host)
	if h == "" {
		h = "localhost"
	}
	return "http://" + net.JoinHostPort(h, "8080")
}

func newUDPManager(controller *policyController, connectTimeout time.Duration, opts udpOptions) *udpManager {
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 60 * time.Second
	}
	m := &udpManager{
		controller:     controller,
		connectTimeout: connectTimeout,
		opts:           opts,
		flows:          make(map[string]*udpFlowState),
		stopCh:         make(chan struct{}),
		doneCh:         make(chan struct{}),
	}
	go m.janitorLoop()
	return m
}

func (m *udpManager) Close() {
	select {
	case <-m.stopCh:
	default:
		close(m.stopCh)
	}
	<-m.doneCh

	m.mu.Lock()
	flows := make([]*udpFlowState, 0, len(m.flows))
	for _, st := range m.flows {
		flows = append(flows, st)
	}
	m.mu.Unlock()

	for _, st := range flows {
		m.closeState(st, "manager_close")
	}
}

func (m *udpManager) janitorLoop() {
	defer close(m.doneCh)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case now := <-ticker.C:
			m.expireIdle(now)
		}
	}
}

func (m *udpManager) expireIdle(now time.Time) {
	idleCutoff := now.Add(-m.opts.IdleTimeout).UnixNano()
	var stale []*udpFlowState

	m.mu.Lock()
	for _, st := range m.flows {
		if st.lastActive.Load() < idleCutoff {
			stale = append(stale, st)
		}
	}
	m.mu.Unlock()

	for _, st := range stale {
		m.closeState(st, "udp_idle_timeout")
	}
}

func (m *udpManager) Handle(local net.Conn, id stack.TransportEndpointID) {
	srcIP := tcpipAddrToString(id.RemoteAddress)
	dstIP := tcpipAddrToString(id.LocalAddress)
	srcPort := int(id.RemotePort)
	dstPort := int(id.LocalPort)
	if srcIP == "" || dstIP == "" || srcPort <= 0 || dstPort <= 0 {
		_ = local.Close()
		return
	}

	key := fmt.Sprintf("%s:%d>%s:%d", srcIP, srcPort, dstIP, dstPort)

	m.mu.Lock()
	if _, exists := m.flows[key]; exists {
		m.mu.Unlock()
		_ = local.Close()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	targetHost := dstIP
	targetPort := dstPort
	if m.opts.DNSOverride && dstPort == 53 {
		targetHost = m.opts.DNSResolverHost
		targetPort = m.opts.DNSResolverPort
	}

	st := &udpFlowState{
		key:        key,
		srcIP:      srcIP,
		srcPort:    srcPort,
		dstIP:      dstIP,
		dstPort:    dstPort,
		targetHost: targetHost,
		targetPort: targetPort,
		local:      local,
		ctx:        ctx,
		cancel:     cancel,
	}
	st.lastActive.Store(time.Now().UnixNano())
	m.flows[key] = st
	m.mu.Unlock()

	go m.runState(st)
}

func (m *udpManager) runState(st *udpFlowState) {
	if m.isQUICBlocked() {
		if st.dstPort == 53 {
			m.runDNSFallback(st)
			return
		}
		m.closeState(st, "udp_quic_temporarily_blocked")
		return
	}

	admissionCtx, cancelAdmission := context.WithTimeout(context.Background(), m.connectTimeout)
	if err := m.controller.acquireFlowPermit(admissionCtx); err != nil {
		cancelAdmission()
		m.closeState(st, "udp_admission_denied")
		return
	}
	cancelAdmission()
	permitHeld := true

	cfg, mode := m.controller.dialConfigUDP()
	setupStart := time.Now()

	dialCtx, cancel := context.WithTimeout(context.Background(), m.connectTimeout)
	client, transport, clientKey, dialed, err := m.controller.acquireClient(dialCtx, cfg)
	cancel()
	if err != nil {
		if permitHeld {
			m.controller.releaseFlowPermit()
			permitHeld = false
		}
		m.noteQUICDialError(err)
		m.controller.onDialError(cfg, err)
		log.Printf("udp session dial failed mode=%s for %s:%d -> %s:%d target=%s:%d: %v",
			mode, st.srcIP, st.srcPort, st.dstIP, st.dstPort, st.targetHost, st.targetPort, err)
		if st.dstPort == 53 {
			m.runDNSFallback(st)
			return
		}
		m.closeState(st, "udp_dial_failed")
		return
	}
	if dialed {
		m.controller.onDialSuccess(mode, cfg, transport)
	}
	st.client = client
	st.clientKey = clientKey

	openCtx, cancel := context.WithTimeout(context.Background(), m.connectTimeout)
	udpFlow, err := client.OpenUDPFlow(openCtx, st.targetHost, st.targetPort)
	cancel()
	if err != nil {
		if permitHeld {
			m.controller.releaseFlowPermit()
			permitHeld = false
		}
		m.controller.onTransportError("open_udp_flow_failed", client, clientKey, time.Now())
		m.noteQUICDialError(err)
		m.controller.markClientBad(clientKey, err)
		m.controller.releaseClient(clientKey)
		st.client = nil
		st.clientKey = ""
		log.Printf("open udp flow failed mode=%s for %s:%d -> %s:%d target=%s:%d: %v",
			mode, st.srcIP, st.srcPort, st.dstIP, st.dstPort, st.targetHost, st.targetPort, err)
		if st.dstPort == 53 {
			m.runDNSFallback(st)
			return
		}
		m.closeState(st, "udp_open_failed")
		return
	}
	st.udpFlow = udpFlow

	fs := m.controller.registerFlow(client, clientKey, transport, time.Since(setupStart))
	st.flowRef = fs
	permitHeld = false

	log.Printf("tun udp %s:%d -> %s:%d target=%s:%d via %s mode=%s flow_id=%d",
		st.srcIP, st.srcPort, st.dstIP, st.dstPort, st.targetHost, st.targetPort, transport, mode, fs.id)

	errCh := make(chan error, 2)
	go func() { errCh <- m.localToRemote(st) }()
	go func() { errCh <- m.remoteToLocal(st) }()

	err = <-errCh
	if !isExpectedUDPErr(err) {
		m.controller.onTransportError("udp_pump_error", st.client, st.clientKey, udpStateLastActivityAt(st, time.Now()))
		m.controller.markClientBad(st.clientKey, err)
		log.Printf("udp pump ended with error key=%s: %v", st.key, err)
	}
	m.closeState(st, "udp_pump_end")
}

func (m *udpManager) localToRemote(st *udpFlowState) error {
	buf := make([]byte, 64*1024)
	for {
		if err := st.local.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return err
		}
		n, err := st.local.Read(buf)
		if n > 0 {
			payload := make([]byte, n)
			copy(payload, buf[:n])

			sendCtx, cancel := context.WithTimeout(st.ctx, m.connectTimeout)
			sendErr := st.udpFlow.Send(sendCtx, payload)
			cancel()
			if sendErr != nil {
				return sendErr
			}

			if st.flowRef != nil {
				st.flowRef.upBytes.Add(int64(n))
				m.controller.totalUpBytes.Add(int64(n))
				st.flowRef.lastActivity.Store(time.Now().UnixNano())
			}
			st.lastActive.Store(time.Now().UnixNano())
		}
		if err != nil {
			if isTimeoutErr(err) {
				select {
				case <-st.ctx.Done():
					return nil
				default:
					continue
				}
			}
			if isExpectedUDPErr(err) {
				return nil
			}
			return err
		}
	}
}

func (m *udpManager) remoteToLocal(st *udpFlowState) error {
	for {
		recvCtx, cancel := context.WithTimeout(st.ctx, 2*time.Second)
		payload, err := st.udpFlow.Recv(recvCtx)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				select {
				case <-st.ctx.Done():
					return nil
				default:
					continue
				}
			}
			if isExpectedUDPErr(err) {
				return nil
			}
			return err
		}
		if len(payload) == 0 {
			continue
		}

		if err := st.local.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return err
		}
		if _, err := st.local.Write(payload); err != nil {
			if isExpectedUDPErr(err) {
				return nil
			}
			return err
		}

		if st.flowRef != nil {
			st.flowRef.downBytes.Add(int64(len(payload)))
			m.controller.totalDownBytes.Add(int64(len(payload)))
			st.flowRef.lastActivity.Store(time.Now().UnixNano())
		}
		st.lastActive.Store(time.Now().UnixNano())
	}
}

func (m *udpManager) closeState(st *udpFlowState, reason string) {
	st.closeOnce.Do(func() {
		st.cancel()
		if st.local != nil {
			_ = st.local.Close()
		}
		if st.udpFlow != nil {
			_ = st.udpFlow.Close()
		}
		if st.flowRef != nil {
			m.controller.unregisterFlow(st.flowRef.id)
		} else if st.clientKey != "" {
			m.controller.releaseClient(st.clientKey)
		}
		st.client = nil
		st.clientKey = ""

		m.mu.Lock()
		delete(m.flows, st.key)
		m.mu.Unlock()
		log.Printf("closed udp flow key=%s reason=%s", st.key, reason)
	})
}

func (m *udpManager) isQUICBlocked() bool {
	return time.Now().UnixNano() < m.quicBlockedUntil.Load()
}

func (m *udpManager) noteQUICDialError(err error) {
	if err == nil {
		return
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "no application protocol") &&
		!strings.Contains(msg, "crypto_error 0x178") &&
		!strings.Contains(msg, "no recent network activity") {
		return
	}

	until := time.Now().Add(udpQUICBackoff).UnixNano()
	m.quicBlockedUntil.Store(until)

	now := time.Now().UnixNano()
	last := m.quicBlockedAt.Load()
	if now-last > int64(5*time.Second) && m.quicBlockedAt.CompareAndSwap(last, now) {
		log.Printf("udp quic path temporarily disabled for %s due to dial error: %v", udpQUICBackoff, err)
	}
}

func (m *udpManager) runDNSFallback(st *udpFlowState) {
	log.Printf("dns fallback over tcp flow for key=%s resolver=%s:%d", st.key, m.opts.DNSResolverHost, m.opts.DNSResolverPort)

	buf := make([]byte, 64*1024)
	for {
		if err := st.local.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			m.closeState(st, "dns_fallback_set_deadline_failed")
			return
		}
		n, err := st.local.Read(buf)
		if n > 0 {
			query := make([]byte, n)
			copy(query, buf[:n])

			resp, qErr := m.dnsQueryOverTCP(st.ctx, query)
			if qErr != nil {
				log.Printf("dns fallback query failed key=%s: %v", st.key, qErr)
				m.closeState(st, "dns_fallback_query_failed")
				return
			}
			if len(resp) == 0 {
				continue
			}

			if err := st.local.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
				m.closeState(st, "dns_fallback_set_write_deadline_failed")
				return
			}
			if _, err := st.local.Write(resp); err != nil {
				if isExpectedUDPErr(err) {
					m.closeState(st, "dns_fallback_local_closed")
					return
				}
				m.closeState(st, "dns_fallback_write_failed")
				return
			}
			st.lastActive.Store(time.Now().UnixNano())
		}

		if err != nil {
			if isTimeoutErr(err) {
				select {
				case <-st.ctx.Done():
					m.closeState(st, "dns_fallback_ctx_done")
					return
				default:
					continue
				}
			}
			if isExpectedUDPErr(err) {
				m.closeState(st, "dns_fallback_local_closed")
				return
			}
			m.closeState(st, "dns_fallback_local_read_error")
			return
		}
	}
}

func (m *udpManager) dnsQueryOverTCP(ctx context.Context, query []byte) ([]byte, error) {
	if len(query) == 0 || len(query) > 65535 {
		return nil, fmt.Errorf("invalid dns query size=%d", len(query))
	}

	admissionCtx, cancelAdmission := context.WithTimeout(ctx, m.connectTimeout)
	if err := m.controller.acquireFlowPermit(admissionCtx); err != nil {
		cancelAdmission()
		return nil, err
	}
	cancelAdmission()
	permitHeld := true

	cfg, mode := m.controller.dialConfig()
	setupStart := time.Now()

	dialCtx, cancel := context.WithTimeout(ctx, m.connectTimeout)
	client, transport, clientKey, dialed, err := m.controller.acquireClient(dialCtx, cfg)
	cancel()
	if err != nil {
		if permitHeld {
			m.controller.releaseFlowPermit()
			permitHeld = false
		}
		m.controller.onDialError(cfg, err)
		return nil, fmt.Errorf("dns dial mode=%s: %w", mode, err)
	}
	if dialed {
		m.controller.onDialSuccess(mode, cfg, transport)
	}

	openCtx, cancel := context.WithTimeout(ctx, m.connectTimeout)
	flow, err := client.OpenTCPFlow(openCtx, m.opts.DNSResolverHost, m.opts.DNSResolverPort)
	cancel()
	if err != nil {
		if permitHeld {
			m.controller.releaseFlowPermit()
			permitHeld = false
		}
		m.controller.onTransportError("dns_open_tcp_failed", client, clientKey, time.Now())
		m.controller.markClientBad(clientKey, err)
		m.controller.releaseClient(clientKey)
		return nil, err
	}

	fs := m.controller.registerFlow(client, clientKey, transport, time.Since(setupStart))
	permitHeld = false
	defer m.controller.unregisterFlow(fs.id)
	defer flow.Close()

	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)

	if err := writeWithTimeout(ctx, flow, frame, m.connectTimeout); err != nil {
		m.controller.onTransportError("dns_tcp_write", client, clientKey, flowLastActivityAt(fs, time.Now()))
		m.controller.markClientBad(clientKey, err)
		return nil, err
	}
	fs.upBytes.Add(int64(len(query)))
	m.controller.totalUpBytes.Add(int64(len(query)))
	fs.lastActivity.Store(time.Now().UnixNano())

	headerRaw, err := readNWithTimeout(ctx, flow, 2, m.connectTimeout)
	if err != nil {
		m.controller.onTransportError("dns_tcp_read_len", client, clientKey, flowLastActivityAt(fs, time.Now()))
		m.controller.markClientBad(clientKey, err)
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(headerRaw))
	if respLen <= 0 || respLen > 65535 {
		return nil, fmt.Errorf("invalid dns response length=%d", respLen)
	}
	resp, err := readNWithTimeout(ctx, flow, respLen, m.connectTimeout)
	if err != nil {
		m.controller.onTransportError("dns_tcp_read_payload", client, clientKey, flowLastActivityAt(fs, time.Now()))
		m.controller.markClientBad(clientKey, err)
		return nil, err
	}
	fs.downBytes.Add(int64(len(resp)))
	m.controller.totalDownBytes.Add(int64(len(resp)))
	fs.lastActivity.Store(time.Now().UnixNano())
	return resp, nil
}

func writeWithTimeout(ctx context.Context, w io.Writer, data []byte, timeout time.Duration) error {
	ch := make(chan error, 1)
	go func() {
		_, err := w.Write(data)
		ch <- err
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return context.DeadlineExceeded
	}
}

func readNWithTimeout(ctx context.Context, r io.Reader, n int, timeout time.Duration) ([]byte, error) {
	ch := make(chan struct {
		data []byte
		err  error
	}, 1)
	go func() {
		buf := make([]byte, n)
		_, err := io.ReadFull(r, buf)
		ch <- struct {
			data []byte
			err  error
		}{data: buf, err: err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case out := <-ch:
		return out.data, out.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, context.DeadlineExceeded
	}
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
		baseCfg:     baseCfg,
		configured:  configured,
		currentMode: initial,
		statsFormat: sf,
		flows:       make(map[uint64]*flowState),
		clients:     make(map[string]*managedClient),
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
		lastStatsAt: time.Now(),
	}
	go c.loop()
	return c
}

func (c *policyController) Close() {
	c.closeOnce.Do(func() {
		close(c.stopCh)
	})
	<-c.doneCh

	c.mu.Lock()
	snapshot := make([]*sessionclient.Client, 0, len(c.clients))
	for key, mc := range c.clients {
		if mc == nil || mc.client == nil {
			continue
		}
		snapshot = append(snapshot, mc.client)
		delete(c.clients, key)
	}
	c.mu.Unlock()

	for _, client := range snapshot {
		_ = client.Close()
	}
}

func (c *policyController) ActiveFlowCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.flows)
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
			c.reapIdleClients(now)
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

func (c *policyController) acquireClient(ctx context.Context, cfg sessionclient.Config) (*sessionclient.Client, sessionclient.Transport, string, bool, error) {
	key := clientConfigKey(cfg)
	now := time.Now()

	c.mu.Lock()
	if mc := c.clients[key]; mc != nil && mc.client != nil && !mc.broken {
		if reason := c.currentManagedClientUnusableReasonLocked(mc, now); reason != "" && mc.refCount == 0 {
			delete(c.clients, key)
			client := mc.client
			c.mu.Unlock()
			_ = client.Close()
			goto dialNew
		}

		if mc.refCount == 0 {
			if lease, ok := mc.client.SessionLease(); ok {
				switch classifyManagedClientLease(now, lease) {
				case managedClientLeaseExpired:
					delete(c.clients, key)
					client := mc.client
					transport := mc.transport
					c.mu.Unlock()
					log.Printf("auth_lease_expired: key=%s transport=%s session_id=%d expired_for=%s", key, transport, lease.SessionID, now.Sub(lease.ExpiresAt).Round(time.Second))
					log.Printf("cached_client_rejected_due_to_lease: key=%s transport=%s session_id=%d", key, transport, lease.SessionID)
					_ = client.Close()
					goto dialNew
				case managedClientLeaseExpiring:
					delete(c.clients, key)
					client := mc.client
					transport := mc.transport
					c.mu.Unlock()
					log.Printf("auth_lease_expiring: key=%s transport=%s session_id=%d expires_in=%s", key, transport, lease.SessionID, lease.ExpiresAt.Sub(now).Round(time.Second))
					log.Printf("proactive_reconnect_due_to_lease: key=%s transport=%s session_id=%d", key, transport, lease.SessionID)
					_ = client.Close()
					goto dialNew
				}
			}
		}

		if !shouldProbeManagedClient(now, mc.lastUsed, mc.refCount) {
			mc.refCount++
			mc.lastUsed = now
			client := mc.client
			transport := mc.transport
			c.mu.Unlock()
			return client, transport, key, false, nil
		}

		client := mc.client
		transport := mc.transport
		idleFor := now.Sub(mc.lastUsed)
		c.mu.Unlock()

		probeCtx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
		_, err := client.ProbeRTT(probeCtx)
		cancel()
		if err == nil || errors.Is(err, sessionclient.ErrRTTProbeUnsupported) {
			c.mu.Lock()
			if current := c.clients[key]; current != nil && current.client == client && !current.broken {
				current.refCount++
				current.lastUsed = now
				c.mu.Unlock()
				return client, transport, key, false, nil
			}
			c.mu.Unlock()
		} else {
			log.Printf("policy cached client probe failed: key=%s transport=%s idle=%s err=%v", key, transport, idleFor.Round(time.Second), err)
			c.markClientBad(key, err)
		}
	}
	c.mu.Unlock()

dialNew:
	client, err := sessionclient.Dial(ctx, cfg)
	if err != nil {
		return nil, "", key, false, err
	}
	transport := client.Transport()

	c.mu.Lock()
	if mc := c.clients[key]; mc != nil && mc.client != nil && !mc.broken {
		mc.refCount++
		mc.lastUsed = now
		existing := mc.client
		existingTransport := mc.transport
		c.mu.Unlock()
		_ = client.Close()
		return existing, existingTransport, key, false, nil
	}

	c.clients[key] = &managedClient{
		key:       key,
		client:    client,
		transport: transport,
		refCount:  1,
		lastUsed:  now,
	}
	c.mu.Unlock()

	return client, transport, key, true, nil
}

func (c *policyController) reapIdleClients(now time.Time) {
	var toClose []*sessionclient.Client

	c.mu.Lock()
	for key, mc := range c.clients {
		leaseExpired := false
		if mc != nil && mc.client != nil {
			if lease, ok := mc.client.SessionLease(); ok && classifyManagedClientLease(now, lease) == managedClientLeaseExpired {
				leaseExpired = true
			}
		}
		if !leaseExpired && !shouldReapManagedClient(now, mc) {
			continue
		}
		reason := "idle"
		if mc.broken {
			reason = "broken"
		} else if leaseExpired {
			reason = "lease_expired"
		}
		idleFor := "n/a"
		if !mc.lastUsed.IsZero() {
			idleFor = now.Sub(mc.lastUsed).Round(time.Second).String()
		}
		log.Printf("policy cached client reaped: key=%s transport=%s reason=%s idle=%s refcount=%d",
			key, mc.transport, reason, idleFor, mc.refCount)
		if mc.client != nil {
			toClose = append(toClose, mc.client)
		}
		delete(c.clients, key)
	}
	c.mu.Unlock()

	for _, client := range toClose {
		_ = client.Close()
	}
}

func (c *policyController) releaseClient(key string) {
	if key == "" {
		return
	}

	var closeClient *sessionclient.Client
	c.mu.Lock()
	mc := c.clients[key]
	if mc == nil {
		c.mu.Unlock()
		return
	}
	if mc.refCount > 0 {
		mc.refCount--
	}
	if mc.refCount == 0 && mc.broken {
		closeClient = mc.client
		delete(c.clients, key)
	}
	c.mu.Unlock()

	if closeClient != nil {
		_ = closeClient.Close()
	}
}

func (c *policyController) markClientBad(key string, err error) {
	if key == "" || !isSessionClientFatalErr(err) {
		return
	}

	var closeClient *sessionclient.Client
	c.mu.Lock()
	mc := c.clients[key]
	if mc == nil {
		c.mu.Unlock()
		return
	}
	if mc.broken {
		c.mu.Unlock()
		return
	}

	mc.broken = true
	c.setManagedClientUnusableReasonLocked(mc, time.Now(), "client_marked_bad", 0)
	if mc.refCount == 0 {
		closeClient = mc.client
		delete(c.clients, key)
	}
	c.mu.Unlock()

	if closeClient != nil {
		_ = closeClient.Close()
	}
}

func (c *policyController) setManagedClientUnusableReasonLocked(mc *managedClient, now time.Time, reason string, ttl time.Duration) {
	if mc == nil || reason == "" {
		return
	}

	until := time.Time{}
	if ttl > 0 {
		until = now.Add(ttl)
	}
	if mc.unusableReason == reason && mc.unusableUntil.Equal(until) {
		return
	}

	mc.unusableReason = reason
	mc.unusableSince = now
	mc.unusableUntil = until

	ttlText := "persistent"
	if !until.IsZero() {
		ttlText = ttl.Round(time.Millisecond).String()
	}
	log.Printf("session_unusable_reason_set: key=%s transport=%s reason=%s ttl=%s refcount=%d", mc.key, mc.transport, reason, ttlText, mc.refCount)
}

func (c *policyController) clearManagedClientTransientReasonLocked(mc *managedClient, reason string) {
	if mc == nil || mc.unusableReason != reason || mc.unusableUntil.IsZero() {
		return
	}
	mc.unusableReason = ""
	mc.unusableSince = time.Time{}
	mc.unusableUntil = time.Time{}
}

func (c *policyController) currentManagedClientUnusableReasonLocked(mc *managedClient, now time.Time) string {
	if mc == nil {
		return ""
	}

	if mc.broken {
		if mc.unusableReason != "client_marked_bad" || !mc.unusableUntil.IsZero() {
			c.setManagedClientUnusableReasonLocked(mc, now, "client_marked_bad", 0)
		}
		return "client_marked_bad"
	}

	if mc.client != nil {
		if state, ok := mc.client.SessionUnusableReason(); ok && state.Reason != "" {
			if mc.unusableReason != state.Reason || !mc.unusableUntil.IsZero() || !mc.unusableSince.Equal(state.Since) {
				mc.unusableReason = state.Reason
				mc.unusableSince = state.Since
				mc.unusableUntil = time.Time{}
				log.Printf("session_unusable_reason_set: key=%s transport=%s reason=%s ttl=persistent refcount=%d", mc.key, mc.transport, state.Reason, mc.refCount)
			}
			return state.Reason
		}
	}

	if mc.unusableReason != "" && !mc.unusableUntil.IsZero() && !now.Before(mc.unusableUntil) {
		mc.unusableReason = ""
		mc.unusableSince = time.Time{}
		mc.unusableUntil = time.Time{}
	}

	return mc.unusableReason
}

func (c *policyController) configForMode(mode clientMode) sessionclient.Config {
	cfg := c.baseCfg
	switch mode {
	case modeNormal:
		cfg.PreferQUIC = true
	case modeFast:
		cfg.PreferQUIC = true
		cfg.QUICTimeout = maxDuration(cfg.QUICTimeout, 2200*time.Millisecond)
	case modeSurvival:
		cfg.PreferQUIC = false
		if !cfg.DisableTCPSession || cfg.AllowRelay {
			cfg.DisableQUIC = true
		}
	}
	return cfg
}

func flowLastActivityAt(flow *flowState, fallback time.Time) time.Time {
	if flow == nil {
		return fallback
	}
	if ts := flow.lastActivity.Load(); ts > 0 {
		return time.Unix(0, ts)
	}
	if !flow.startedAt.IsZero() {
		return flow.startedAt
	}
	return fallback
}

func udpStateLastActivityAt(st *udpFlowState, fallback time.Time) time.Time {
	if st == nil {
		return fallback
	}
	if st.flowRef != nil {
		return flowLastActivityAt(st.flowRef, fallback)
	}
	if ts := st.lastActive.Load(); ts > 0 {
		return time.Unix(0, ts)
	}
	return fallback
}

func (c *policyController) onDialSuccess(mode clientMode, cfg sessionclient.Config, transport sessionclient.Transport) {
	if mode == modeSurvival {
		return
	}
	if !cfg.DisableQUIC && cfg.PreferQUIC && transport != sessionclient.TransportQUIC {
		c.recordQUICFailure("dial_fallback_transport_"+string(transport), failureClassMeaningfulDegradation, policyCandidateHealthy)
	}
}

func (c *policyController) onDialError(cfg sessionclient.Config, err error) {
	var de *sessionclient.DialError
	if errors.As(err, &de) && de.QUICErr != nil && !cfg.DisableQUIC {
		c.recordQUICFailure("dial_error", failureClassMeaningfulDegradation, policyCandidateHealthy)
	}
	c.recordTransportError("dial_error", failureClassMeaningfulDegradation, policyCandidateHealthy)
}

func (c *policyController) onTransportError(reason string, client *sessionclient.Client, clientKey string, lastActivityAt time.Time) {
	now := time.Now()
	c.mu.Lock()
	candidateReason := c.classifyPolicySampleReasonLocked(now, client, clientKey, lastActivityAt)
	c.mu.Unlock()
	c.recordTransportError(reason, classifyFailureClass(reason, candidateReason), candidateReason)
}

func (c *policyController) registerFlow(client *sessionclient.Client, clientKey string, transport sessionclient.Transport, setupDuration time.Duration) *flowState {
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
		clientKey: clientKey,
	}
	fs.lastActivity.Store(now.UnixNano())
	c.flows[fs.id] = fs
	if mc := c.clients[clientKey]; mc != nil && mc.client == client {
		c.clearManagedClientTransientReasonLocked(mc, "probe_failed")
	}

	if c.lastTransport == "" {
		c.lastTransport = transport
		log.Printf("policy transport init: transport=%s", transport)
	} else if c.lastTransport != transport {
		prev := c.lastTransport
		c.lastTransport = transport
		c.switches++
		log.Printf("policy transport switch: from=%s to=%s reason=new_flow_dial", prev, transport)
	}

	if setupDuration > 0 {
		reason := c.classifyPolicySampleReasonLocked(now, client, clientKey, now)
		c.appendRTTSampleLocked(now, float64(setupDuration.Microseconds())/1000.0, transport, clientKey, reason)
	}

	return fs
}

func (c *policyController) unregisterFlow(id uint64) {
	c.mu.Lock()
	fs := c.flows[id]
	delete(c.flows, id)
	c.mu.Unlock()

	if fs != nil {
		c.releaseClient(fs.clientKey)
	}
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

func (c *policyController) recordQUICFailure(reason string, class failureClass, candidateReason policyCandidateReason) {
	now := time.Now()
	c.mu.Lock()
	c.quicFailTimes = pruneTimes(c.quicFailTimes, now.Add(-failureWindowDuration))
	c.quicLowConfidenceFailTimes = pruneTimes(c.quicLowConfidenceFailTimes, now.Add(-failureWindowDuration))
	switch class {
	case failureClassHardFailure, failureClassMeaningfulDegradation:
		c.quicFailTimes = append(c.quicFailTimes, now)
	case failureClassLowConfidence:
		c.quicLowConfidenceFailTimes = append(c.quicLowConfidenceFailTimes, now)
	}
	fullCount := len(c.quicFailTimes)
	lowCount := len(c.quicLowConfidenceFailTimes)
	weightedCount := weightedFailureCount(fullCount, lowCount)
	c.mu.Unlock()

	log.Printf("failure_classified: scope=quic reason=%s failure_class=%s policy_candidate_reason=%s full_count_30s=%d low_confidence_count_30s=%d weighted_count_30s=%.1f",
		reason, class, candidateReason, fullCount, lowCount, weightedCount)
	switch class {
	case failureClassIgnored:
		log.Printf("failure_ignored_due_to_reason: scope=quic reason=%s policy_candidate_reason=%s", reason, candidateReason)
		log.Printf("survival_input_ignored: scope=quic reason=%s policy_candidate_reason=%s", reason, candidateReason)
		return
	case failureClassLowConfidence:
		log.Printf("failure_weight_reduced: scope=quic reason=%s policy_candidate_reason=%s", reason, candidateReason)
		log.Printf("survival_input_reduced_confidence: scope=quic reason=%s policy_candidate_reason=%s weighted_count_30s=%.1f", reason, candidateReason, weightedCount)
	default:
		log.Printf("survival_input_accepted: scope=quic reason=%s policy_candidate_reason=%s weighted_count_30s=%.1f", reason, candidateReason, weightedCount)
	}

	log.Printf("policy quic failure: reason=%s full_count_30s=%d low_confidence_count_30s=%d weighted_count_30s=%.1f", reason, fullCount, lowCount, weightedCount)
}

func (c *policyController) recordTransportError(reason string, class failureClass, candidateReason policyCandidateReason) {
	now := time.Now()
	c.mu.Lock()
	c.errorSpikeTime = pruneTimes(c.errorSpikeTime, now.Add(-failureWindowDuration))
	c.errorLowConfidenceTimes = pruneTimes(c.errorLowConfidenceTimes, now.Add(-failureWindowDuration))
	switch class {
	case failureClassHardFailure, failureClassMeaningfulDegradation:
		c.errorSpikeTime = append(c.errorSpikeTime, now)
	case failureClassLowConfidence:
		c.errorLowConfidenceTimes = append(c.errorLowConfidenceTimes, now)
	}
	fullCount := len(c.errorSpikeTime)
	lowCount := len(c.errorLowConfidenceTimes)
	weightedCount := weightedFailureCount(fullCount, lowCount)
	c.mu.Unlock()

	log.Printf("failure_classified: scope=transport reason=%s failure_class=%s policy_candidate_reason=%s full_count_30s=%d low_confidence_count_30s=%d weighted_count_30s=%.1f",
		reason, class, candidateReason, fullCount, lowCount, weightedCount)
	switch class {
	case failureClassIgnored:
		log.Printf("failure_ignored_due_to_reason: scope=transport reason=%s policy_candidate_reason=%s", reason, candidateReason)
		log.Printf("survival_input_ignored: scope=transport reason=%s policy_candidate_reason=%s", reason, candidateReason)
		return
	case failureClassLowConfidence:
		log.Printf("failure_weight_reduced: scope=transport reason=%s policy_candidate_reason=%s", reason, candidateReason)
		log.Printf("survival_input_reduced_confidence: scope=transport reason=%s policy_candidate_reason=%s weighted_count_30s=%.1f", reason, candidateReason, weightedCount)
	default:
		log.Printf("survival_input_accepted: scope=transport reason=%s policy_candidate_reason=%s weighted_count_30s=%.1f", reason, candidateReason, weightedCount)
	}

	log.Printf("policy transport error: reason=%s full_count_30s=%d low_confidence_count_30s=%d weighted_count_30s=%.1f", reason, fullCount, lowCount, weightedCount)
}

func (c *policyController) probeRTT(now time.Time) {
	client, transport, clientKey, ok := c.pickProbeClient(now)
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
			c.onTransportError("rtt_probe_timeout_"+string(transport), client, clientKey, now)
		} else {
			c.onTransportError("rtt_probe_error_"+string(transport), client, clientKey, now)
		}
		c.mu.Lock()
		if mc := c.clients[clientKey]; mc != nil && mc.client == client {
			c.setManagedClientUnusableReasonLocked(mc, time.Now(), "probe_failed", probeFailureSuppressWindow)
		}
		c.mu.Unlock()
		return
	}

	c.mu.Lock()
	if mc := c.clients[clientKey]; mc != nil && mc.client == client {
		c.clearManagedClientTransientReasonLocked(mc, "probe_failed")
	}
	reason := c.classifyPolicySampleReasonLocked(now, client, clientKey, now)
	c.appendRTTSampleLocked(now, float64(rtt.Microseconds())/1000.0, transport, clientKey, reason)
	c.mu.Unlock()
}

func (c *policyController) pickProbeClient(now time.Time) (*sessionclient.Client, sessionclient.Transport, string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.flows) == 0 {
		return nil, "", "", false
	}

	type probeCandidate struct {
		client    *sessionclient.Client
		transport sessionclient.Transport
		key       string
	}

	seen := make(map[string]struct{}, len(c.flows))
	var fallback *probeCandidate
	for _, flow := range c.flows {
		if flow.client == nil {
			continue
		}

		key := flow.clientKey
		if key == "" {
			key = fmt.Sprintf("ptr:%p", flow.client)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		var leaseDecision managedClientLeaseDecision
		var lease sessionclient.SessionLease
		var hasLease bool
		var unusableReason string

		if mc := c.clients[flow.clientKey]; mc != nil && mc.client == flow.client {
			unusableReason = c.currentManagedClientUnusableReasonLocked(mc, now)
			lease, hasLease = mc.client.SessionLease()
		} else {
			if state, ok := flow.client.SessionUnusableReason(); ok {
				unusableReason = state.Reason
			}
			lease, hasLease = flow.client.SessionLease()
		}

		if hasLease {
			leaseDecision = classifyManagedClientLease(now, lease)
			if leaseDecision == managedClientLeaseExpired || leaseDecision == managedClientLeaseExpiring {
				reason := "lease_expired"
				expiresText := now.Sub(lease.ExpiresAt).Round(time.Second).String()
				if leaseDecision == managedClientLeaseExpiring {
					reason = "lease_expiring"
					expiresText = lease.ExpiresAt.Sub(now).Round(time.Second).String()
				}
				log.Printf("probe_skipped_due_to_lease: key=%s transport=%s reason=%s session_id=%d expires=%s", key, flow.transport, reason, lease.SessionID, expiresText)
				log.Printf("probe_client_rejected: key=%s transport=%s reason=%s", key, flow.transport, reason)
				continue
			}
		}

		if unusableReason != "" {
			log.Printf("probe_skipped_due_to_unusable_reason: key=%s transport=%s reason=%s", key, flow.transport, unusableReason)
			log.Printf("probe_client_rejected: key=%s transport=%s reason=%s", key, flow.transport, unusableReason)
			continue
		}

		candidate := &probeCandidate{
			client:    flow.client,
			transport: flow.transport,
			key:       key,
		}
		if fallback == nil {
			fallback = candidate
		}
		if c.lastTransport != "" && flow.transport == c.lastTransport {
			log.Printf("probe_client_selected: key=%s transport=%s preferred=true", key, flow.transport)
			return candidate.client, candidate.transport, candidate.key, true
		}
	}
	if fallback == nil {
		return nil, "", "", false
	}
	log.Printf("probe_client_selected: key=%s transport=%s preferred=false", fallback.key, fallback.transport)
	return fallback.client, fallback.transport, fallback.key, true
}

func normalizePolicyCandidateReason(reason string) policyCandidateReason {
	switch reason {
	case "":
		return policyCandidateHealthy
	case "lease_expiring":
		return policyCandidateLeaseExpiring
	case "lease_expired":
		return policyCandidateLeaseExpired
	case "control_loop_dead":
		return policyCandidateControlLoopDead
	case "session_closed":
		return policyCandidateSessionClosed
	case "probe_failed":
		return policyCandidateProbeSuppressed
	case "client_marked_bad":
		return policyCandidateClientMarkedBad
	case "transport_unhealthy":
		return policyCandidateTransportUnhealthy
	case "no_recent_activity":
		return policyCandidateNoRecentActivity
	case "low_confidence_sample":
		return policyCandidateLowConfidence
	default:
		return policyCandidateTransportUnhealthy
	}
}

func classifyFailureClass(reason string, candidateReason policyCandidateReason) failureClass {
	switch candidateReason {
	case policyCandidateLeaseExpired,
		policyCandidateControlLoopDead,
		policyCandidateSessionClosed,
		policyCandidateProbeSuppressed,
		policyCandidateClientMarkedBad,
		policyCandidateTransportUnhealthy:
		return failureClassIgnored
	case policyCandidateLeaseExpiring,
		policyCandidateNoRecentActivity,
		policyCandidateLowConfidence:
		return failureClassLowConfidence
	}

	if strings.HasPrefix(reason, "rtt_probe_") || strings.HasPrefix(reason, "dial_") {
		return failureClassMeaningfulDegradation
	}
	return failureClassHardFailure
}

func weightedFailureCount(fullCount, lowConfidenceCount int) float64 {
	return float64(fullCount) + (float64(lowConfidenceCount) * 0.5)
}

func classifyPolicyCandidateReason(
	now time.Time,
	lastActivityAt time.Time,
	hasLease bool,
	leaseDecision managedClientLeaseDecision,
	unusableReason string,
) policyCandidateReason {
	if unusableReason != "" {
		return normalizePolicyCandidateReason(unusableReason)
	}
	if hasLease {
		switch leaseDecision {
		case managedClientLeaseExpired:
			return policyCandidateLeaseExpired
		case managedClientLeaseExpiring:
			return policyCandidateLeaseExpiring
		}
	} else {
		return policyCandidateLowConfidence
	}
	if !lastActivityAt.IsZero() && now.Sub(lastActivityAt) > policyRecentActivityWindow {
		return policyCandidateNoRecentActivity
	}
	return policyCandidateHealthy
}

func (c *policyController) classifyPolicySampleReasonLocked(now time.Time, client *sessionclient.Client, clientKey string, lastActivityAt time.Time) policyCandidateReason {
	if client == nil {
		return policyCandidateLowConfidence
	}

	var leaseDecision managedClientLeaseDecision
	var unusableReason string
	var hasLease bool

	if clientKey != "" {
		if mc := c.clients[clientKey]; mc != nil && mc.client == client {
			unusableReason = c.currentManagedClientUnusableReasonLocked(mc, now)
			if lease, ok := mc.client.SessionLease(); ok {
				hasLease = true
				leaseDecision = classifyManagedClientLease(now, lease)
			}
			return classifyPolicyCandidateReason(now, lastActivityAt, hasLease, leaseDecision, unusableReason)
		}
	}

	if state, ok := client.SessionUnusableReason(); ok && state.Reason != "" {
		unusableReason = state.Reason
	}
	if lease, ok := client.SessionLease(); ok {
		hasLease = true
		leaseDecision = classifyManagedClientLease(now, lease)
	}
	return classifyPolicyCandidateReason(now, lastActivityAt, hasLease, leaseDecision, unusableReason)
}

func (c *policyController) evaluateFlowCandidateLocked(now time.Time, flow *flowState) policyCandidate {
	if flow == nil {
		return policyCandidate{reason: policyCandidateLowConfidence, lowConfidence: true}
	}

	lastActivityAt := flow.startedAt
	if ts := flow.lastActivity.Load(); ts > 0 {
		lastActivityAt = time.Unix(0, ts)
	}
	reason := c.classifyPolicySampleReasonLocked(now, flow.client, flow.clientKey, lastActivityAt)

	return policyCandidate{
		flowID:         flow.id,
		client:         flow.client,
		clientKey:      flow.clientKey,
		transport:      flow.transport,
		reason:         reason,
		lowConfidence:  reason == policyCandidateLowConfidence,
		lastActivityAt: lastActivityAt,
	}
}

func selectPreferredPolicyCandidate(candidates []policyCandidate, lastTransport sessionclient.Transport) *policyCandidate {
	if len(candidates) == 0 {
		return nil
	}

	best := &candidates[0]
	for i := 1; i < len(candidates); i++ {
		candidate := &candidates[i]
		bestPreferred := lastTransport != "" && best.transport == lastTransport
		candidatePreferred := lastTransport != "" && candidate.transport == lastTransport
		if candidatePreferred && !bestPreferred {
			best = candidate
			continue
		}
		if candidatePreferred == bestPreferred && candidate.lastActivityAt.After(best.lastActivityAt) {
			best = candidate
		}
	}
	return best
}

func (c *policyController) switchMode(next clientMode, reason string) {
	c.switchModeAt(time.Now(), next, reason)
}

func (c *policyController) switchModeAt(now time.Time, next clientMode, reason string) bool {
	c.mu.Lock()
	prev := c.currentMode
	if prev == next {
		c.mu.Unlock()
		return false
	}
	lastSwitchAt := c.lastModeSwitchAt
	lastReason := c.lastModeSwitchReason
	if !lastSwitchAt.IsZero() && now.Sub(lastSwitchAt) < modeSwitchCooldown {
		remaining := (modeSwitchCooldown - now.Sub(lastSwitchAt)).Round(time.Millisecond)
		c.mu.Unlock()
		if lastReason == reason {
			log.Printf("repeated_storm_suppressed: from=%s to=%s mode_switch_reason=%s cooldown_remaining=%s", prev, next, reason, remaining)
		}
		log.Printf("mode_switch_suppressed_by_cooldown: from=%s to=%s mode_switch_reason=%s cooldown_remaining=%s last_mode_switch_reason=%s", prev, next, reason, remaining, lastReason)
		return false
	}
	c.currentMode = next
	c.switches++
	c.lastModeSwitchAt = now
	c.lastModeSwitchReason = reason
	c.degradedTicks = 0
	c.stableTicks = 0
	c.fastSignalTicks = 0
	c.fastQuietTicks = 0
	if next == modeSurvival {
		c.survivalSince = now
		c.survivalUntil = now.Add(survivalRecoveryMinDelay)
	}
	switches := c.switches
	c.mu.Unlock()

	log.Printf("mode_switch_confirmed: from=%s to=%s mode_switch_reason=%s switches=%d", prev, next, reason, switches)
	log.Printf("policy mode switch: from=%s to=%s reason=%s switches=%d", prev, next, reason, switches)
	return true
}

func preferredSurvivalReason(weightedQuicFails, weightedTransportErrs float64) string {
	quicRatio := weightedQuicFails / float64(quicFailureThreshold)
	transportRatio := weightedTransportErrs / float64(transportErrorThreshold)
	if transportRatio > quicRatio {
		return fmt.Sprintf("transport_errors_weighted_%.1f_in_%s", weightedTransportErrs, failureWindowDuration)
	}
	return fmt.Sprintf("quic_failures_weighted_%.1f_in_%s", weightedQuicFails, failureWindowDuration)
}

func fastSignalReason(flow *flowState, now time.Time) (string, bool) {
	if flow == nil {
		return "", false
	}
	duration := now.Sub(flow.startedAt)
	if duration >= fastFlowDurationThreshold {
		return fmt.Sprintf("flow_%d_duration_%s", flow.id, duration.Round(time.Second)), true
	}
	downBytes := flow.downBytes.Load()
	if downBytes >= fastDownloadThreshold {
		return fmt.Sprintf("flow_%d_download_%dmb", flow.id, downBytes/(1024*1024)), true
	}
	if avgDownrateMbps(flow, now) >= fastDownrateThresholdMbps {
		return fmt.Sprintf("flow_%d_downrate_gt_%.0fmbps_for_%s", flow.id, fastDownrateThresholdMbps, fastDownrateWindow), true
	}
	return "", false
}

func selectFastSignal(now time.Time, flows []*flowState, healthyCandidates []policyCandidate, lastTransport sessionclient.Transport) (*policyCandidate, string) {
	fastEligible := make([]policyCandidate, 0, len(healthyCandidates))
	fastEligibleReasons := make(map[uint64]string, len(healthyCandidates))
	for _, candidate := range healthyCandidates {
		f := findFlowByID(flows, candidate.flowID)
		if f == nil {
			continue
		}
		if reason, ok := fastSignalReason(f, now); ok {
			fastEligible = append(fastEligible, candidate)
			fastEligibleReasons[candidate.flowID] = reason
		}
	}
	fastSelected := selectPreferredPolicyCandidate(fastEligible, lastTransport)
	if fastSelected == nil {
		return nil, ""
	}
	return fastSelected, fastEligibleReasons[fastSelected.flowID]
}

func (c *policyController) applyFastModeHysteresis(now time.Time, mode clientMode, fastSelected *policyCandidate, reason string) {
	if mode == modeNormal {
		if fastSelected == nil {
			c.mu.Lock()
			c.fastSignalTicks = 0
			c.mu.Unlock()
			return
		}
		c.mu.Lock()
		c.fastSignalTicks++
		c.fastQuietTicks = 0
		fastSignalTicks := c.fastSignalTicks
		c.mu.Unlock()
		log.Printf("mode_hysteresis_enter_check: from=%s to=%s signal=fast mode_switch_reason=%s fast_signal_ticks=%d required_confirm_ticks=%d",
			modeNormal, modeFast, reason, fastSignalTicks, fastEnterConfirmTicks)
		if fastSignalTicks < fastEnterConfirmTicks {
			log.Printf("mode_switch_suppressed_by_insufficient_signal: from=%s to=%s mode_switch_reason=%s fast_signal_ticks=%d required_confirm_ticks=%d",
				modeNormal, modeFast, reason, fastSignalTicks, fastEnterConfirmTicks)
			return
		}
		c.switchModeAt(now, modeFast, reason)
		return
	}

	if mode != modeFast {
		return
	}

	if fastSelected != nil {
		c.mu.Lock()
		c.fastQuietTicks = 0
		c.fastSignalTicks = 0
		c.mu.Unlock()
		return
	}

	c.mu.Lock()
	c.fastQuietTicks++
	fastQuietTicks := c.fastQuietTicks
	c.mu.Unlock()
	log.Printf("mode_hysteresis_exit_check: from=%s to=%s stable=%t stable_ticks=%d required_stable_ticks=%d mode_switch_reason=%s",
		modeFast, modeNormal, true, fastQuietTicks, fastExitStableTicks, "fast_recovery_quiet_window")
	if fastQuietTicks < fastExitStableTicks {
		log.Printf("mode_switch_suppressed_by_stability_window: from=%s to=%s mode_switch_reason=%s stable_ticks=%d required_stable_ticks=%d",
			modeFast, modeNormal, "fast_recovery_quiet_window", fastQuietTicks, fastExitStableTicks)
		return
	}
	c.switchModeAt(now, modeNormal, "fast_recovery_quiet_window")
}

func (c *policyController) evaluateAutoPolicy(now time.Time) {
	c.mu.Lock()
	if c.configured != modeAuto {
		c.mu.Unlock()
		return
	}

	c.quicFailTimes = pruneTimes(c.quicFailTimes, now.Add(-failureWindowDuration))
	c.quicLowConfidenceFailTimes = pruneTimes(c.quicLowConfidenceFailTimes, now.Add(-failureWindowDuration))
	c.errorSpikeTime = pruneTimes(c.errorSpikeTime, now.Add(-failureWindowDuration))
	c.errorLowConfidenceTimes = pruneTimes(c.errorLowConfidenceTimes, now.Add(-failureWindowDuration))

	mode := c.currentMode
	quicFails := len(c.quicFailTimes)
	quicLowConfidenceFails := len(c.quicLowConfidenceFailTimes)
	transportErrs := len(c.errorSpikeTime)
	transportLowConfidenceErrs := len(c.errorLowConfidenceTimes)
	survivalUntil := c.survivalUntil
	flows := make([]*flowState, 0, len(c.flows))
	for _, f := range c.flows {
		flows = append(flows, f)
	}
	lastTransport := c.lastTransport
	healthyCandidates := make([]policyCandidate, 0, len(flows))
	lowConfidenceCandidates := make([]policyCandidate, 0, len(flows))
	rejectedCandidates := make([]policyCandidate, 0, len(flows))
	for _, f := range flows {
		candidate := c.evaluateFlowCandidateLocked(now, f)
		switch candidate.reason {
		case policyCandidateHealthy:
			healthyCandidates = append(healthyCandidates, candidate)
		case policyCandidateLowConfidence:
			lowConfidenceCandidates = append(lowConfidenceCandidates, candidate)
		default:
			rejectedCandidates = append(rejectedCandidates, candidate)
		}
	}
	degradedTicks := c.degradedTicks
	stableTicks := c.stableTicks
	fastSignalTicks := c.fastSignalTicks
	fastQuietTicks := c.fastQuietTicks
	c.mu.Unlock()

	weightedQuicFails := weightedFailureCount(quicFails, quicLowConfidenceFails)
	weightedTransportErrs := weightedFailureCount(transportErrs, transportLowConfidenceErrs)
	log.Printf("hysteresis_signal_snapshot: mode=%s quic_full=%d quic_low=%d quic_weighted=%.1f transport_full=%d transport_low=%d transport_weighted=%.1f active_flows=%d healthy_candidates=%d low_confidence_candidates=%d rejected_candidates=%d degraded_ticks=%d stable_ticks=%d fast_signal_ticks=%d fast_quiet_ticks=%d",
		mode, quicFails, quicLowConfidenceFails, weightedQuicFails, transportErrs, transportLowConfidenceErrs, weightedTransportErrs, len(flows), len(healthyCandidates), len(lowConfidenceCandidates), len(rejectedCandidates), degradedTicks, stableTicks, fastSignalTicks, fastQuietTicks)

	for _, candidate := range rejectedCandidates {
		log.Printf("policy_candidate_rejected: flow_id=%d transport=%s policy_candidate_reason=%s", candidate.flowID, candidate.transport, candidate.reason)
	}
	for _, candidate := range lowConfidenceCandidates {
		log.Printf("policy_candidate_rejected: flow_id=%d transport=%s policy_candidate_reason=%s", candidate.flowID, candidate.transport, candidate.reason)
		log.Printf("policy_sample_low_confidence: flow_id=%d transport=%s policy_candidate_reason=%s", candidate.flowID, candidate.transport, candidate.reason)
	}

	survivalSignal := weightedQuicFails >= float64(quicFailureThreshold) || weightedTransportErrs >= float64(transportErrorThreshold)
	survivalReason := preferredSurvivalReason(weightedQuicFails, weightedTransportErrs)

	if mode == modeSurvival {
		exitStable := now.After(survivalUntil) &&
			quicFails == 0 &&
			transportErrs == 0 &&
			weightedQuicFails <= survivalExitWeightedMax &&
			weightedTransportErrs <= survivalExitWeightedMax
		c.mu.Lock()
		if exitStable {
			c.stableTicks++
		} else {
			c.stableTicks = 0
		}
		stableTicks = c.stableTicks
		c.mu.Unlock()
		log.Printf("mode_hysteresis_exit_check: from=%s to=%s stable=%t stable_ticks=%d required_stable_ticks=%d quic_weighted=%.1f transport_weighted=%.1f survival_until=%s",
			modeSurvival, modeNormal, exitStable, stableTicks, survivalExitStableTicks, weightedQuicFails, weightedTransportErrs, survivalUntil.Format(time.RFC3339Nano))
		if !exitStable {
			return
		}
		if stableTicks < survivalExitStableTicks {
			log.Printf("mode_switch_suppressed_by_stability_window: from=%s to=%s mode_switch_reason=%s stable_ticks=%d required_stable_ticks=%d",
				modeSurvival, modeNormal, "survival_recovery_stable_window", stableTicks, survivalExitStableTicks)
			return
		}
		c.switchModeAt(now, modeNormal, "survival_recovery_stable_window")
		return
	}

	if survivalSignal {
		c.mu.Lock()
		c.degradedTicks++
		degradedTicks = c.degradedTicks
		c.mu.Unlock()
		log.Printf("mode_hysteresis_enter_check: from=%s to=%s signal=degraded mode_switch_reason=%s quic_weighted=%.1f transport_weighted=%.1f degraded_ticks=%d required_confirm_ticks=%d",
			mode, modeSurvival, survivalReason, weightedQuicFails, weightedTransportErrs, degradedTicks, survivalEnterConfirmTicks)
		if degradedTicks < survivalEnterConfirmTicks {
			log.Printf("mode_switch_suppressed_by_insufficient_signal: from=%s to=%s mode_switch_reason=%s degraded_ticks=%d required_confirm_ticks=%d",
				mode, modeSurvival, survivalReason, degradedTicks, survivalEnterConfirmTicks)
			return
		}
		c.switchModeAt(now, modeSurvival, survivalReason)
		return
	}
	c.mu.Lock()
	c.degradedTicks = 0
	c.mu.Unlock()

	selected := selectPreferredPolicyCandidate(healthyCandidates, lastTransport)
	if selected == nil {
		log.Printf("auto_policy_no_viable_candidate: mode=%s active_flows=%d low_confidence=%d", mode, len(flows), len(lowConfidenceCandidates))
		if mode == modeFast {
			c.mu.Lock()
			c.fastQuietTicks++
			fastQuietTicks = c.fastQuietTicks
			c.mu.Unlock()
			log.Printf("mode_hysteresis_exit_check: from=%s to=%s stable=%t stable_ticks=%d required_stable_ticks=%d mode_switch_reason=%s",
				modeFast, modeNormal, true, fastQuietTicks, fastExitStableTicks, "fast_recovery_quiet_window")
			if fastQuietTicks < fastExitStableTicks {
				log.Printf("mode_switch_suppressed_by_stability_window: from=%s to=%s mode_switch_reason=%s stable_ticks=%d required_stable_ticks=%d",
					modeFast, modeNormal, "fast_recovery_quiet_window", fastQuietTicks, fastExitStableTicks)
				return
			}
			c.switchModeAt(now, modeNormal, "fast_recovery_quiet_window")
		}
		return
	}

	log.Printf("policy_candidate_selected: flow_id=%d transport=%s policy_candidate_reason=%s", selected.flowID, selected.transport, selected.reason)
	log.Printf("auto_policy_used_candidate: flow_id=%d transport=%s policy_candidate_reason=%s", selected.flowID, selected.transport, selected.reason)

	fastSelected, fastReason := selectFastSignal(now, flows, healthyCandidates, lastTransport)
	c.applyFastModeHysteresis(now, mode, fastSelected, fastReason)
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

	rttWindow, lowConfidenceWindow := c.collectRTTWindowLocked(prevAt, now)
	var rttP50Ptr *float64
	var rttP95Ptr *float64
	var capRTTP95Ptr *float64
	if len(rttWindow) > 0 {
		p50 := percentile(rttWindow, 50)
		p95 := percentile(rttWindow, 95)
		rttP50Ptr = &p50
		rttP95Ptr = &p95
		capRTTP95Ptr = &p95
	} else if len(lowConfidenceWindow) > 0 {
		p50 := percentile(lowConfidenceWindow, 50)
		p95 := percentile(lowConfidenceWindow, 95)
		rttP50Ptr = &p50
		rttP95Ptr = &p95
	}

	c.updateAdaptiveCapLocked(now, activeFlows, capRTTP95Ptr)
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

func (c *policyController) appendRTTSampleLocked(at time.Time, ms float64, transport sessionclient.Transport, clientKey string, reason policyCandidateReason) {
	if ms <= 0 {
		return
	}
	c.rttSamples = append(c.rttSamples, rttSample{
		at:            at,
		ms:            ms,
		transport:     transport,
		clientKey:     clientKey,
		reason:        reason,
		lowConfidence: reason == policyCandidateLowConfidence,
	})
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

func (c *policyController) collectRTTWindowLocked(from, now time.Time) ([]float64, []float64) {
	c.pruneRTTSamplesLocked(now.Add(-2 * time.Minute))
	healthy := make([]float64, 0, len(c.rttSamples))
	lowConfidence := make([]float64, 0, len(c.rttSamples))
	for _, sample := range c.rttSamples {
		if sample.at.Before(from) {
			continue
		}
		switch sample.reason {
		case policyCandidateHealthy:
			healthy = append(healthy, sample.ms)
		case policyCandidateLowConfidence:
			lowConfidence = append(lowConfidence, sample.ms)
			log.Printf("policy_sample_low_confidence: transport=%s client_key=%s policy_candidate_reason=%s", sample.transport, sample.clientKey, sample.reason)
		default:
			log.Printf("auto_policy_ignored_sample_due_to_reason: transport=%s client_key=%s policy_candidate_reason=%s", sample.transport, sample.clientKey, sample.reason)
		}
	}
	return healthy, lowConfidence
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

func findFlowByID(flows []*flowState, id uint64) *flowState {
	for _, flow := range flows {
		if flow != nil && flow.id == id {
			return flow
		}
	}
	return nil
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

func clientConfigKey(cfg sessionclient.Config) string {
	return fmt.Sprintf(
		"%s|%d|%d|%s|%s|%s|%t|%t|%t|%t|%t",
		strings.ToLower(strings.TrimSpace(cfg.GatewayHost)),
		cfg.GatewayUDP,
		cfg.GatewayTCP,
		strings.TrimSpace(cfg.RelayBase),
		strings.TrimSpace(cfg.ClientID),
		strings.TrimSpace(cfg.ProtoID),
		cfg.PreferQUIC,
		cfg.DisableQUIC,
		cfg.DisableTCPSession,
		cfg.AllowRelay,
		cfg.ForceIPv4,
	)
}

func proxyBidirectional(local net.Conn, remote sessionclient.TCPFlow, controller *policyController, fs *flowState) {
	defer controller.unregisterFlow(fs.id)

	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			_ = local.Close()
			_ = remote.Close()
		})
	}

	upWriter := &flowWriter{
		dst:          remote,
		flowBytes:    &fs.upBytes,
		total:        &controller.totalUpBytes,
		lastActivity: &fs.lastActivity,
	}
	downWriter := &flowWriter{
		dst:          local,
		flowBytes:    &fs.downBytes,
		total:        &controller.totalDownBytes,
		lastActivity: &fs.lastActivity,
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
		controller.onTransportError("proxy_copy_up", fs.client, fs.clientKey, flowLastActivityAt(fs, time.Now()))
		controller.markClientBad(fs.clientKey, first)
		log.Printf("proxy copy ended with error flow_id=%d dir=up: %v", fs.id, first)
	}
	if !isExpectedPipeErr(second) {
		controller.onTransportError("proxy_copy_down", fs.client, fs.clientKey, flowLastActivityAt(fs, time.Now()))
		controller.markClientBad(fs.clientKey, second)
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
	msg := strings.ToLower(err.Error())
	return msg == "use of closed network connection" ||
		msg == "eof" ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "forcibly closed by the remote host") ||
		strings.Contains(msg, "broken pipe")
}

func isExpectedProbeErr(err error) bool {
	if isExpectedPipeErr(err) {
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

func isSessionClientFatalErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "application error 0x0") ||
		strings.Contains(msg, "no recent network activity") ||
		strings.Contains(msg, "stream reset")
}

func shouldProbeManagedClient(now, lastUsed time.Time, refCount int) bool {
	if refCount > 0 {
		return false
	}
	if lastUsed.IsZero() {
		return true
	}
	return now.Sub(lastUsed) >= managedClientProbeAge
}

func shouldReapManagedClient(now time.Time, mc *managedClient) bool {
	if mc == nil || mc.refCount > 0 {
		return false
	}
	if mc.broken {
		return true
	}
	if mc.lastUsed.IsZero() {
		return true
	}
	return now.Sub(mc.lastUsed) >= managedClientMaxIdle
}

func classifyManagedClientLease(now time.Time, lease sessionclient.SessionLease) managedClientLeaseDecision {
	if lease.ExpiresAt.IsZero() {
		return managedClientLeaseReuse
	}
	if !lease.ExpiresAt.After(now) {
		return managedClientLeaseExpired
	}
	if lease.ExpiresAt.Sub(now) <= managedClientLeaseSkew {
		return managedClientLeaseExpiring
	}
	return managedClientLeaseReuse
}
