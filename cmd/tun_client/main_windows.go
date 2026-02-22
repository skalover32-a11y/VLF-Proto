//go:build windows

package main

import (
	"context"
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

	client  *sessionclient.Client
	udpFlow sessionclient.UDPFlow
	flowRef *flowState

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
	serverPort := flag.Int("port", baseCfg.GatewayUDP, "gateway port for QUIC and TCP session lanes")
	relayBase := flag.String("relay-base", baseCfg.RelayBase, "relay base URL (fallback)")
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
	if *serverPort <= 0 || *serverPort > 65535 {
		log.Fatalf("invalid --port=%d", *serverPort)
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

	gatewayIP, err := resolveGatewayIPv4(cfg.GatewayHost)
	if err != nil {
		log.Fatalf("resolve gateway host %q: %v", cfg.GatewayHost, err)
	}
	route, err := findBestRouteTo(gatewayIP)
	if err != nil {
		log.Fatalf("find route to gateway ip %s: %v", gatewayIP, err)
	}
	if route.NextHop == "" {
		route.NextHop = "0.0.0.0"
	}

	log.Printf("gateway resolved: host=%s ip=%s route_if=%d route_nexthop=%s", cfg.GatewayHost, gatewayIP, route.InterfaceIndex, route.NextHop)

	controller := newPolicyController(cfg, mode, sf)
	defer controller.Close()

	var cleanup cleanupStack
	defer cleanup.Run()

	dev, err := tun.CreateTUN(*tunNameFlag, *mtu)
	if err != nil {
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
	ep.Close()
	ep.Wait()
	wg.Wait()
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
	client, err := sessionclient.Dial(dialCtx, cfg)
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
	controller.onDialSuccess(mode, cfg, client.Transport())

	openCtx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	flow, err := client.OpenTCPFlow(openCtx, dstIP, dstPort)
	cancel()
	if err != nil {
		if permitHeld {
			controller.releaseFlowPermit()
			permitHeld = false
		}
		controller.onTransportError("open_tcp_flow_failed")
		_ = client.Close()
		log.Printf("open tcp flow failed mode=%s for %s:%d -> %s:%d: %v", mode, srcIP, srcPort, dstIP, dstPort, err)
		return
	}

	fs := controller.registerFlow(client, client.Transport(), time.Since(setupStart))
	permitHeld = false

	log.Printf("tun tcp %s:%d -> %s:%d via %s mode=%s flow_id=%d", srcIP, srcPort, dstIP, dstPort, client.Transport(), mode, fs.id)
	proxyBidirectional(local, flow, client, controller, fs)
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
	client, err := sessionclient.Dial(dialCtx, cfg)
	cancel()
	if err != nil {
		if permitHeld {
			m.controller.releaseFlowPermit()
			permitHeld = false
		}
		m.controller.onDialError(cfg, err)
		log.Printf("udp session dial failed mode=%s for %s:%d -> %s:%d target=%s:%d: %v",
			mode, st.srcIP, st.srcPort, st.dstIP, st.dstPort, st.targetHost, st.targetPort, err)
		m.closeState(st, "udp_dial_failed")
		return
	}
	m.controller.onDialSuccess(mode, cfg, client.Transport())
	st.client = client

	openCtx, cancel := context.WithTimeout(context.Background(), m.connectTimeout)
	udpFlow, err := client.OpenUDPFlow(openCtx, st.targetHost, st.targetPort)
	cancel()
	if err != nil {
		if permitHeld {
			m.controller.releaseFlowPermit()
			permitHeld = false
		}
		m.controller.onTransportError("open_udp_flow_failed")
		log.Printf("open udp flow failed mode=%s for %s:%d -> %s:%d target=%s:%d: %v",
			mode, st.srcIP, st.srcPort, st.dstIP, st.dstPort, st.targetHost, st.targetPort, err)
		m.closeState(st, "udp_open_failed")
		return
	}
	st.udpFlow = udpFlow

	fs := m.controller.registerFlow(client, client.Transport(), time.Since(setupStart))
	st.flowRef = fs
	permitHeld = false

	log.Printf("tun udp %s:%d -> %s:%d target=%s:%d via %s mode=%s flow_id=%d",
		st.srcIP, st.srcPort, st.dstIP, st.dstPort, st.targetHost, st.targetPort, client.Transport(), mode, fs.id)

	errCh := make(chan error, 2)
	go func() { errCh <- m.localToRemote(st) }()
	go func() { errCh <- m.remoteToLocal(st) }()

	err = <-errCh
	if !isExpectedUDPErr(err) {
		m.controller.onTransportError("udp_pump_error")
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
		if st.client != nil {
			_ = st.client.Close()
		}
		if st.flowRef != nil {
			m.controller.unregisterFlow(st.flowRef.id)
		}

		m.mu.Lock()
		delete(m.flows, st.key)
		m.mu.Unlock()
		log.Printf("closed udp flow key=%s reason=%s", st.key, reason)
	})
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
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
		lastStatsAt: time.Now(),
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

	if setupDuration > 0 {
		c.appendRTTSampleLocked(now, float64(setupDuration.Microseconds())/1000.0)
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
