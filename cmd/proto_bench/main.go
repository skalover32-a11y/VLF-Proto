package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"vlf-runtime/internal/sessionclient"
)

type benchOptions struct {
	Clients        int
	Duration       time.Duration
	TCPFlows       int
	TCPTotalMB     int
	TCPChunkBytes  int
	TCPMinMbps     float64
	UDPPPS         int
	UDPPayload     int
	UDPBurst       int
	UDPMaxLoss     float64
	UDPMaxJitterMS float64
	TargetTCPHost  string
	TargetTCPPort  int
	TargetUDPHost  string
	TargetUDPPort  int
	PreferQUIC     bool
	DisableQUIC    bool
	DisableTCP     bool
	DisableRelay   bool
	ForceUDPBlock  bool
	Soak           time.Duration
	ReportJSON     string
	ReportMD       string
	MetricsListen  string
}

type benchReport struct {
	StartedAt            time.Time           `json:"started_at"`
	EndedAt              time.Time           `json:"ended_at"`
	HostOS               string              `json:"host_os"`
	HostArch             string              `json:"host_arch"`
	Options              benchOptions        `json:"options"`
	Config               map[string]any      `json:"config"`
	ServerUDPDropReasons map[string]float64  `json:"server_udp_drop_reasons,omitempty"`
	TCP                  tcpThroughputResult `json:"tcp_throughput"`
	UDP                  udpPPSResult        `json:"udp_pps"`
	Concurrent           concurrencyResult   `json:"concurrency"`
	Fallback             fallbackResult      `json:"fallback"`
	Soak                 *soakResult         `json:"soak,omitempty"`
	Errors               []string            `json:"errors,omitempty"`
}

type tcpThroughputResult struct {
	Transport     string  `json:"transport"`
	Flows         int     `json:"flows"`
	BytesTotal    int64   `json:"bytes_total"`
	ElapsedSec    float64 `json:"elapsed_sec"`
	Mbps          float64 `json:"mbps"`
	LatencyP95MS  float64 `json:"latency_p95_ms"`
	LatencyP99MS  float64 `json:"latency_p99_ms"`
	Samples       int     `json:"samples"`
	MinMbps       float64 `json:"min_mbps"`
	PassByQuality bool    `json:"pass_by_quality"`
	QualityReason string  `json:"quality_reason,omitempty"`
	Error         string  `json:"error,omitempty"`
}

type udpPPSResult struct {
	Transport     string  `json:"transport"`
	Sent          int64   `json:"sent"`
	Received      int64   `json:"received"`
	LossRatio     float64 `json:"loss_ratio"`
	LossPercent   float64 `json:"loss_percent"`
	JitterMS      float64 `json:"jitter_ms"`
	RTTP95MS      float64 `json:"rtt_p95_ms"`
	RTTP99MS      float64 `json:"rtt_p99_ms"`
	ElapsedSec    float64 `json:"elapsed_sec"`
	EffectivePPS  float64 `json:"effective_pps"`
	MaxLossRatio  float64 `json:"max_loss_ratio"`
	MaxJitterMS   float64 `json:"max_jitter_ms"`
	PassByQuality bool    `json:"pass_by_quality"`
	QualityReason string  `json:"quality_reason,omitempty"`
	Error         string  `json:"error,omitempty"`
}

type concurrencyResult struct {
	Clients            int            `json:"clients"`
	Success            int            `json:"success"`
	Fail               int            `json:"fail"`
	HandshakeP95MS     float64        `json:"handshake_p95_ms"`
	HandshakeP99MS     float64        `json:"handshake_p99_ms"`
	TransportBreakdown map[string]int `json:"transport_breakdown"`
	Errors             []string       `json:"errors,omitempty"`
}

type fallbackResult struct {
	Attempts           int                `json:"attempts"`
	Success            int                `json:"success"`
	Fail               int                `json:"fail"`
	TransportBreakdown map[string]int     `json:"transport_breakdown"`
	SharePercent       map[string]float64 `json:"share_percent"`
	ForceUDPBlock      bool               `json:"force_udp_block"`
	Note               string             `json:"note,omitempty"`
}

type soakResult struct {
	DurationSec float64 `json:"duration_sec"`
	Iterations  int     `json:"iterations"`
	Success     int     `json:"success"`
	Fail        int     `json:"fail"`
}

type benchMetrics struct {
	registry *prometheus.Registry

	tcpMbps        prometheus.Gauge
	tcpP95         prometheus.Gauge
	tcpP99         prometheus.Gauge
	udpLoss        prometheus.Gauge
	udpJitter      prometheus.Gauge
	udpRecvPPS     prometheus.Gauge
	concSuccess    prometheus.Gauge
	concFail       prometheus.Gauge
	handshakeP95   prometheus.Gauge
	handshakeP99   prometheus.Gauge
	transportShare *prometheus.GaugeVec
}

func main() {
	baseCfg, err := sessionclient.LoadConfigFromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load session config from env: %v\n", err)
		os.Exit(1)
	}

	opts := benchOptions{}
	flag.IntVar(&opts.Clients, "clients", 10, "concurrency sessions for concurrency/fallback tests")
	flag.DurationVar(&opts.Duration, "duration", 30*time.Second, "duration for UDP PPS test")
	flag.IntVar(&opts.TCPFlows, "tcp-flows", 8, "parallel TCP flows in throughput test")
	flag.IntVar(&opts.TCPTotalMB, "tcp-total-mb", 64, "total payload size for TCP throughput test in MB")
	flag.IntVar(&opts.TCPTotalMB, "tcp-mb", 64, "alias for --tcp-total-mb")
	flag.IntVar(&opts.TCPChunkBytes, "tcp-chunk-bytes", 32*1024, "per write chunk size for TCP throughput")
	flag.Float64Var(&opts.TCPMinMbps, "tcp-min-mbps", 1.0, "minimum TCP throughput in Mbps required to pass quality criteria")
	flag.IntVar(&opts.UDPPPS, "udp-pps", 2000, "target packets per second for UDP PPS test")
	flag.IntVar(&opts.UDPPPS, "udp-ps", 2000, "alias for --udp-pps")
	flag.IntVar(&opts.UDPPayload, "udp-payload-bytes", 256, "UDP payload size in bytes")
	flag.IntVar(&opts.UDPBurst, "udp-burst", 10, "max packets sent per pacing tick in UDP PPS test")
	flag.Float64Var(&opts.UDPMaxLoss, "udp-max-loss", 0.05, "maximum allowed UDP loss ratio (0.05 = 5%)")
	flag.Float64Var(&opts.UDPMaxJitterMS, "udp-max-jitter-ms", 50.0, "maximum allowed UDP jitter in milliseconds")
	flag.StringVar(&opts.TargetTCPHost, "target-tcp-host", envOr("BENCH_TARGET_TCP_HOST", "tcp-echo"), "TCP benchmark target host")
	flag.IntVar(&opts.TargetTCPPort, "target-tcp-port", envOrInt("BENCH_TARGET_TCP_PORT", 9000), "TCP benchmark target port")
	flag.StringVar(&opts.TargetUDPHost, "target-udp-host", envOr("BENCH_TARGET_UDP_HOST", "udp-echo"), "UDP benchmark target host")
	flag.IntVar(&opts.TargetUDPPort, "target-udp-port", envOrInt("BENCH_TARGET_UDP_PORT", 9001), "UDP benchmark target port")
	flag.BoolVar(&opts.PreferQUIC, "prefer-quic", baseCfg.PreferQUIC, "prefer QUIC transport first")
	flag.BoolVar(&opts.DisableQUIC, "disable-quic", baseCfg.DisableQUIC, "disable QUIC transport")
	flag.BoolVar(&opts.DisableTCP, "disable-tcp-session", baseCfg.DisableTCPSession, "disable TCP session transport")
	flag.BoolVar(&opts.DisableRelay, "disable-relay-fallback", !baseCfg.AllowRelay, "disable relay fallback transport")
	flag.BoolVar(&opts.ForceUDPBlock, "force-udp-block", false, "force QUIC off to emulate UDP-blocked path")
	flag.DurationVar(&opts.Soak, "soak", 0, "optional soak duration (e.g. 30m, 2h)")
	flag.StringVar(&opts.ReportJSON, "report-json", "proto_bench_report.json", "JSON report output path")
	flag.StringVar(&opts.ReportMD, "report-md", "proto_bench_report.md", "Markdown report output path")
	flag.StringVar(&opts.MetricsListen, "metrics-listen", "", "optional metrics listen addr, e.g. :2112")
	flag.Parse()

	baseCfg.PreferQUIC = opts.PreferQUIC
	baseCfg.DisableQUIC = opts.DisableQUIC || opts.ForceUDPBlock
	baseCfg.DisableTCPSession = opts.DisableTCP
	baseCfg.AllowRelay = !opts.DisableRelay

	metrics, err := maybeStartMetrics(opts.MetricsListen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start metrics: %v\n", err)
		os.Exit(1)
	}

	report := benchReport{
		StartedAt: time.Now().UTC(),
		HostOS:    runtime.GOOS,
		HostArch:  runtime.GOARCH,
		Options:   opts,
		Config: map[string]any{
			"gateway_host":      baseCfg.GatewayHost,
			"gateway_port_udp":  baseCfg.GatewayUDP,
			"gateway_port_tcp":  baseCfg.GatewayTCP,
			"relay_base":        baseCfg.RelayBase,
			"proto_id":          baseCfg.ProtoID,
			"prefer_quic":       baseCfg.PreferQUIC,
			"disable_quic":      baseCfg.DisableQUIC,
			"disable_tcp":       baseCfg.DisableTCPSession,
			"allow_relay":       baseCfg.AllowRelay,
			"force_udp_block":   opts.ForceUDPBlock,
			"udp_burst":         opts.UDPBurst,
			"tcp_min_mbps":      opts.TCPMinMbps,
			"udp_max_loss":      opts.UDPMaxLoss,
			"udp_max_jitter_ms": opts.UDPMaxJitterMS,
			"metrics_listen":    opts.MetricsListen,
		},
	}

	if opts.ForceUDPBlock {
		fmt.Println("NOTE: --force-udp-block enabled. QUIC is disabled in client logic to emulate blocked UDP path.")
		if runtime.GOOS == "windows" {
			fmt.Println("Windows hard block example (optional): netsh advfirewall firewall add rule name=\"VLF_Block_UDP_443\" dir=out action=block protocol=UDP remoteport=443")
		}
	}

	tcpRes := runTCPThroughput(baseCfg, opts)
	report.TCP = tcpRes
	if metrics != nil {
		metrics.tcpMbps.Set(tcpRes.Mbps)
		metrics.tcpP95.Set(tcpRes.LatencyP95MS)
		metrics.tcpP99.Set(tcpRes.LatencyP99MS)
	}
	if tcpRes.Error != "" {
		report.Errors = append(report.Errors, "tcp_throughput: "+tcpRes.Error)
	} else if !tcpRes.PassByQuality {
		report.Errors = append(report.Errors, "tcp_throughput_quality: "+tcpRes.QualityReason)
	}

	udpRes := runUDPPPS(baseCfg, opts)
	report.UDP = udpRes
	if metrics != nil {
		metrics.udpLoss.Set(udpRes.LossPercent)
		metrics.udpJitter.Set(udpRes.JitterMS)
		metrics.udpRecvPPS.Set(udpRes.EffectivePPS)
	}
	if udpRes.Error != "" {
		report.Errors = append(report.Errors, "udp_pps: "+udpRes.Error)
	} else if !udpRes.PassByQuality {
		report.Errors = append(report.Errors, "udp_pps_quality: "+udpRes.QualityReason)
	}

	concRes := runConcurrency(baseCfg, opts)
	report.Concurrent = concRes
	if metrics != nil {
		metrics.concSuccess.Set(float64(concRes.Success))
		metrics.concFail.Set(float64(concRes.Fail))
		metrics.handshakeP95.Set(concRes.HandshakeP95MS)
		metrics.handshakeP99.Set(concRes.HandshakeP99MS)
	}
	if concRes.Fail > 0 {
		report.Errors = append(report.Errors, fmt.Sprintf("concurrency: fail=%d", concRes.Fail))
	}

	fallbackRes := runFallback(baseCfg, opts)
	report.Fallback = fallbackRes
	if metrics != nil {
		for transport, share := range fallbackRes.SharePercent {
			metrics.transportShare.WithLabelValues(transport).Set(share)
		}
	}
	if fallbackRes.Fail > 0 {
		report.Errors = append(report.Errors, fmt.Sprintf("fallback: fail=%d", fallbackRes.Fail))
	}

	if drops, err := scrapeServerUDPDropReasons(baseCfg); err == nil && len(drops) > 0 {
		report.ServerUDPDropReasons = drops
	}

	if opts.Soak > 0 {
		soakRes := runSoak(baseCfg, opts)
		report.Soak = &soakRes
		if soakRes.Fail > 0 {
			report.Errors = append(report.Errors, fmt.Sprintf("soak: fail=%d", soakRes.Fail))
		}
	}

	report.EndedAt = time.Now().UTC()

	printSummary(report)

	if err := writeJSON(opts.ReportJSON, report); err != nil {
		fmt.Fprintf(os.Stderr, "write JSON report: %v\n", err)
		os.Exit(1)
	}
	if err := writeMarkdown(opts.ReportMD, report); err != nil {
		fmt.Fprintf(os.Stderr, "write Markdown report: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nReports:\n- %s\n- %s\n", opts.ReportJSON, opts.ReportMD)
}

func runTCPThroughput(cfg sessionclient.Config, opts benchOptions) tcpThroughputResult {
	res := tcpThroughputResult{
		Flows:         opts.TCPFlows,
		MinMbps:       opts.TCPMinMbps,
		PassByQuality: false,
	}
	if opts.TCPFlows <= 0 {
		res.Error = "tcp-flows must be > 0"
		return res
	}
	if opts.TCPTotalMB <= 0 {
		res.Error = "tcp-total-mb must be > 0"
		return res
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	client, err := sessionclient.Dial(ctx, cfg)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer client.Close()
	res.Transport = string(client.Transport())

	flows := make([]sessionclient.TCPFlow, 0, opts.TCPFlows)
	for i := 0; i < opts.TCPFlows; i++ {
		flow, err := client.OpenTCPFlow(ctx, opts.TargetTCPHost, opts.TargetTCPPort)
		if err != nil {
			res.Error = fmt.Sprintf("open tcp flow %d: %v", i, err)
			for _, f := range flows {
				_ = f.Close()
			}
			return res
		}
		flows = append(flows, flow)
	}
	defer func() {
		for _, f := range flows {
			_ = f.Close()
		}
	}()

	totalBytes := int64(opts.TCPTotalMB) * 1024 * 1024
	perFlow := totalBytes / int64(opts.TCPFlows)
	remainder := totalBytes % int64(opts.TCPFlows)
	chunkSize := opts.TCPChunkBytes
	if chunkSize < 1024 {
		chunkSize = 1024
	}

	var bytesOK atomic.Int64
	latMu := sync.Mutex{}
	latencies := make([]float64, 0, int(totalBytes/int64(chunkSize))+1024)
	errCh := make(chan error, opts.TCPFlows)

	start := time.Now()
	wg := sync.WaitGroup{}
	for idx, flow := range flows {
		flowTarget := perFlow
		if int64(idx) < remainder {
			flowTarget++
		}
		wg.Add(1)
		go func(flow sessionclient.TCPFlow, target int64, seed int64) {
			defer wg.Done()
			r := rand.New(rand.NewSource(seed))
			payload := make([]byte, chunkSize)
			echo := make([]byte, chunkSize)
			sent := int64(0)
			for sent < target {
				n := chunkSize
				left := target - sent
				if left < int64(n) {
					n = int(left)
				}
				if _, err := r.Read(payload[:n]); err != nil {
					errCh <- err
					return
				}
				ts := time.Now()
				if _, err := flow.Write(payload[:n]); err != nil {
					errCh <- err
					return
				}
				if _, err := io.ReadFull(flow, echo[:n]); err != nil {
					errCh <- err
					return
				}
				if !bytesEqual(payload[:n], echo[:n]) {
					errCh <- errors.New("echo mismatch")
					return
				}
				latMS := float64(time.Since(ts).Microseconds()) / 1000.0
				latMu.Lock()
				latencies = append(latencies, latMS)
				latMu.Unlock()
				sent += int64(n)
				bytesOK.Add(int64(n))
			}
		}(flow, flowTarget, int64(idx)+time.Now().UnixNano())
	}
	wg.Wait()
	close(errCh)

	for e := range errCh {
		if e != nil {
			res.Error = e.Error()
			break
		}
	}

	elapsed := time.Since(start)
	res.BytesTotal = bytesOK.Load()
	res.ElapsedSec = elapsed.Seconds()
	if elapsed > 0 {
		res.Mbps = (float64(res.BytesTotal) * 8.0) / elapsed.Seconds() / 1e6
	}
	res.Samples = len(latencies)
	if len(latencies) > 0 {
		res.LatencyP95MS = percentile(latencies, 95)
		res.LatencyP99MS = percentile(latencies, 99)
	}
	if res.Error != "" {
		res.QualityReason = "runtime error"
		return res
	}
	if res.Mbps < opts.TCPMinMbps {
		res.QualityReason = fmt.Sprintf("mbps %.2f is below minimum %.2f", res.Mbps, opts.TCPMinMbps)
		return res
	}
	res.PassByQuality = true
	return res
}

func runUDPPPS(cfg sessionclient.Config, opts benchOptions) udpPPSResult {
	res := udpPPSResult{
		MaxLossRatio:  opts.UDPMaxLoss,
		MaxJitterMS:   opts.UDPMaxJitterMS,
		PassByQuality: false,
	}
	if opts.UDPPPS <= 0 {
		res.Error = "udp-pps must be > 0"
		return res
	}
	if opts.Duration <= 0 {
		res.Error = "duration must be > 0"
		return res
	}
	if opts.UDPPayload < 16 {
		opts.UDPPayload = 16
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Duration+20*time.Second)
	defer cancel()

	client, err := sessionclient.Dial(ctx, cfg)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer client.Close()
	res.Transport = string(client.Transport())

	udpFlow, err := client.OpenUDPFlow(ctx, opts.TargetUDPHost, opts.TargetUDPPort)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer udpFlow.Close()

	type recvItem struct {
		seq uint32
		rtt float64
	}
	recvCh := make(chan recvItem, 1024)
	recvErrCh := make(chan error, 1)

	recvCtx, recvCancel := context.WithCancel(ctx)
	defer recvCancel()

	go func() {
		for {
			payload, err := udpFlow.Recv(recvCtx)
			if err != nil {
				recvErrCh <- err
				return
			}
			if len(payload) < 12 {
				continue
			}
			seq := binary.BigEndian.Uint32(payload[:4])
			sentNs := int64(binary.BigEndian.Uint64(payload[4:12]))
			rttMS := float64(time.Since(time.Unix(0, sentNs)).Microseconds()) / 1000.0
			recvCh <- recvItem{seq: seq, rtt: rttMS}
		}
	}()

	sent := int64(0)
	start := time.Now()
	end := start.Add(opts.Duration)
	seq := uint32(1)
	burst := opts.UDPBurst
	if burst <= 0 {
		burst = 1
	}
	ticksPerSecond := opts.UDPPPS / burst
	ticksPerSecond = max(ticksPerSecond, 20)
	ticksPerSecond = min(ticksPerSecond, 250)
	tickInterval := time.Second / time.Duration(ticksPerSecond)
	if tickInterval <= 0 {
		tickInterval = time.Millisecond
	}
	tokensPerTick := float64(opts.UDPPPS) / float64(ticksPerSecond)
	tokenBudget := 0.0
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for time.Now().Before(end) {
		<-ticker.C
		tokenBudget += tokensPerTick
		sendNow := int(tokenBudget)
		if sendNow <= 0 {
			continue
		}
		if sendNow > burst {
			sendNow = burst
		}
		tokenBudget -= float64(sendNow)

		for i := 0; i < sendNow; i++ {
			if time.Now().After(end) {
				break
			}
			payload := make([]byte, opts.UDPPayload)
			binary.BigEndian.PutUint32(payload[:4], seq)
			binary.BigEndian.PutUint64(payload[4:12], uint64(time.Now().UnixNano()))
			fillPattern(payload[12:], byte(seq))

			if err := udpFlow.Send(ctx, payload); err == nil {
				sent++
			}
			seq++
		}
	}

	time.Sleep(2 * time.Second)
	recvCancel()

	seen := make(map[uint32]struct{}, sent)
	rtts := make([]float64, 0, sent)
	for {
		select {
		case item := <-recvCh:
			if _, ok := seen[item.seq]; ok {
				continue
			}
			seen[item.seq] = struct{}{}
			rtts = append(rtts, item.rtt)
		default:
			goto done
		}
	}
done:
	received := int64(len(seen))

	res.Sent = sent
	res.Received = received
	res.ElapsedSec = time.Since(start).Seconds()
	if sent > 0 {
		res.LossRatio = float64(sent-received) / float64(sent)
		res.LossPercent = res.LossRatio * 100.0
	}
	if res.ElapsedSec > 0 {
		res.EffectivePPS = float64(received) / res.ElapsedSec
	}
	if len(rtts) > 0 {
		res.RTTP95MS = percentile(rtts, 95)
		res.RTTP99MS = percentile(rtts, 99)
		res.JitterMS = jitterFromRTT(rtts)
	}
	if res.Error != "" {
		res.QualityReason = "runtime error"
		return res
	}

	qualityIssues := make([]string, 0, 2)
	if res.LossRatio > opts.UDPMaxLoss {
		qualityIssues = append(qualityIssues, fmt.Sprintf("loss ratio %.4f exceeds max %.4f", res.LossRatio, opts.UDPMaxLoss))
	}
	if res.JitterMS > opts.UDPMaxJitterMS {
		qualityIssues = append(qualityIssues, fmt.Sprintf("jitter %.2fms exceeds max %.2fms", res.JitterMS, opts.UDPMaxJitterMS))
	}
	if len(qualityIssues) > 0 {
		res.QualityReason = strings.Join(qualityIssues, "; ")
		return res
	}

	res.PassByQuality = true
	return res
}

func runConcurrency(cfg sessionclient.Config, opts benchOptions) concurrencyResult {
	res := concurrencyResult{
		Clients:            opts.Clients,
		TransportBreakdown: map[string]int{},
	}
	if opts.Clients <= 0 {
		return res
	}

	wg := sync.WaitGroup{}
	sem := make(chan struct{}, min(opts.Clients, 128))

	hsMu := sync.Mutex{}
	handshakes := make([]float64, 0, opts.Clients)

	var success atomic.Int64
	var fail atomic.Int64
	errs := make(chan string, opts.Clients)
	var transportMu sync.Mutex

	for i := 0; i < opts.Clients; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			hsStart := time.Now()
			client, err := sessionclient.Dial(ctx, cfg)
			hsMS := float64(time.Since(hsStart).Microseconds()) / 1000.0
			hsMu.Lock()
			handshakes = append(handshakes, hsMS)
			hsMu.Unlock()

			if err != nil {
				fail.Add(1)
				errs <- fmt.Sprintf("client %d dial: %v", idx, err)
				return
			}
			defer client.Close()

			transportMu.Lock()
			res.TransportBreakdown[string(client.Transport())]++
			transportMu.Unlock()

			tcpFlow, err := client.OpenTCPFlow(ctx, opts.TargetTCPHost, opts.TargetTCPPort)
			if err != nil {
				fail.Add(1)
				errs <- fmt.Sprintf("client %d open tcp: %v", idx, err)
				return
			}
			payload := []byte("concurrency-tcp-ping")
			echo := make([]byte, len(payload))
			if _, err := tcpFlow.Write(payload); err != nil {
				_ = tcpFlow.Close()
				fail.Add(1)
				errs <- fmt.Sprintf("client %d tcp write: %v", idx, err)
				return
			}
			if _, err := io.ReadFull(tcpFlow, echo); err != nil {
				_ = tcpFlow.Close()
				fail.Add(1)
				errs <- fmt.Sprintf("client %d tcp read: %v", idx, err)
				return
			}
			_ = tcpFlow.Close()

			if !bytesEqual(payload, echo) {
				fail.Add(1)
				errs <- fmt.Sprintf("client %d tcp mismatch", idx)
				return
			}

			udpFlow, err := client.OpenUDPFlow(ctx, opts.TargetUDPHost, opts.TargetUDPPort)
			if err != nil {
				fail.Add(1)
				errs <- fmt.Sprintf("client %d open udp: %v", idx, err)
				return
			}
			defer udpFlow.Close()

			udpPayload := make([]byte, max(16, opts.UDPPayload))
			binary.BigEndian.PutUint32(udpPayload[:4], uint32(idx+1))
			binary.BigEndian.PutUint64(udpPayload[4:12], uint64(time.Now().UnixNano()))
			fillPattern(udpPayload[12:], byte(idx))
			if err := udpFlow.Send(ctx, udpPayload); err != nil {
				fail.Add(1)
				errs <- fmt.Sprintf("client %d udp send: %v", idx, err)
				return
			}
			recvCtx, cancelRecv := context.WithTimeout(ctx, 3*time.Second)
			defer cancelRecv()
			got, err := udpFlow.Recv(recvCtx)
			if err != nil {
				fail.Add(1)
				errs <- fmt.Sprintf("client %d udp recv: %v", idx, err)
				return
			}
			if !bytesEqual(got, udpPayload) {
				fail.Add(1)
				errs <- fmt.Sprintf("client %d udp mismatch", idx)
				return
			}

			success.Add(1)
		}(i)
	}

	wg.Wait()
	close(errs)

	res.Success = int(success.Load())
	res.Fail = int(fail.Load())

	if len(handshakes) > 0 {
		res.HandshakeP95MS = percentile(handshakes, 95)
		res.HandshakeP99MS = percentile(handshakes, 99)
	}

	res.Errors = make([]string, 0, 20)
	for errText := range errs {
		if len(res.Errors) < 20 {
			res.Errors = append(res.Errors, errText)
		}
	}
	return res
}

func runFallback(cfg sessionclient.Config, opts benchOptions) fallbackResult {
	attempts := max(10, opts.Clients)
	res := fallbackResult{
		Attempts:           attempts,
		TransportBreakdown: map[string]int{},
		SharePercent:       map[string]float64{},
		ForceUDPBlock:      opts.ForceUDPBlock,
	}

	if opts.ForceUDPBlock {
		res.Note = "QUIC transport disabled by --force-udp-block"
	}

	for i := 0; i < attempts; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		client, err := sessionclient.Dial(ctx, cfg)
		cancel()
		if err != nil {
			res.Fail++
			continue
		}
		res.Success++
		transport := string(client.Transport())
		res.TransportBreakdown[transport]++
		_ = client.Close()
	}

	for transport, count := range res.TransportBreakdown {
		if res.Success == 0 {
			res.SharePercent[transport] = 0
			continue
		}
		res.SharePercent[transport] = float64(count) * 100.0 / float64(res.Success)
	}
	return res
}

func runSoak(cfg sessionclient.Config, opts benchOptions) soakResult {
	res := soakResult{
		DurationSec: opts.Soak.Seconds(),
	}
	deadline := time.Now().Add(opts.Soak)
	for time.Now().Before(deadline) {
		res.Iterations++
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		client, err := sessionclient.Dial(ctx, cfg)
		if err != nil {
			res.Fail++
			cancel()
			continue
		}

		ok := true
		tcpFlow, err := client.OpenTCPFlow(ctx, opts.TargetTCPHost, opts.TargetTCPPort)
		if err != nil {
			ok = false
		} else {
			payload := []byte("soak")
			echo := make([]byte, len(payload))
			if _, err := tcpFlow.Write(payload); err != nil {
				ok = false
			} else if _, err := io.ReadFull(tcpFlow, echo); err != nil {
				ok = false
			}
			_ = tcpFlow.Close()
		}

		if ok {
			udpFlow, err := client.OpenUDPFlow(ctx, opts.TargetUDPHost, opts.TargetUDPPort)
			if err == nil {
				udpPayload := []byte("soak-udp")
				_ = udpFlow.Send(ctx, udpPayload)
				recvCtx, recvCancel := context.WithTimeout(ctx, 3*time.Second)
				if _, err := udpFlow.Recv(recvCtx); err != nil {
					ok = false
				}
				recvCancel()
				_ = udpFlow.Close()
			}
		}

		_ = client.Close()
		cancel()

		if ok {
			res.Success++
		} else {
			res.Fail++
		}
		time.Sleep(100 * time.Millisecond)
	}

	return res
}

func maybeStartMetrics(listen string) (*benchMetrics, error) {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return nil, nil
	}

	reg := prometheus.NewRegistry()
	bm := &benchMetrics{
		registry: reg,
		tcpMbps: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vlf_bench_tcp_mbps",
			Help: "TCP throughput in Mbps from proto_bench",
		}),
		tcpP95: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vlf_bench_tcp_p95_ms",
			Help: "TCP throughput p95 latency in ms",
		}),
		tcpP99: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vlf_bench_tcp_p99_ms",
			Help: "TCP throughput p99 latency in ms",
		}),
		udpLoss: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vlf_bench_udp_loss_percent",
			Help: "UDP loss percent from proto_bench",
		}),
		udpJitter: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vlf_bench_udp_jitter_ms",
			Help: "UDP jitter in ms from proto_bench",
		}),
		udpRecvPPS: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vlf_bench_udp_effective_pps",
			Help: "UDP effective receive PPS",
		}),
		concSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vlf_bench_concurrency_success",
			Help: "Successful clients in concurrency test",
		}),
		concFail: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vlf_bench_concurrency_fail",
			Help: "Failed clients in concurrency test",
		}),
		handshakeP95: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vlf_bench_handshake_p95_ms",
			Help: "Session handshake p95 latency in ms",
		}),
		handshakeP99: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vlf_bench_handshake_p99_ms",
			Help: "Session handshake p99 latency in ms",
		}),
		transportShare: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "vlf_bench_transport_share_percent",
			Help: "Transport share percentage in fallback test",
		}, []string{"transport"}),
	}

	reg.MustRegister(
		bm.tcpMbps,
		bm.tcpP95,
		bm.tcpP99,
		bm.udpLoss,
		bm.udpJitter,
		bm.udpRecvPPS,
		bm.concSuccess,
		bm.concFail,
		bm.handshakeP95,
		bm.handshakeP99,
		bm.transportShare,
	)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	go func() {
		_ = http.ListenAndServe(listen, mux)
	}()
	return bm, nil
}

var droppedDatagramsRe = regexp.MustCompile(`^vlf_dropped_datagrams_total(?:\{([^}]*)\})?\s+([0-9eE+\-.]+)$`)

func scrapeServerUDPDropReasons(cfg sessionclient.Config) (map[string]float64, error) {
	metricsURL, err := metricsURLFromRelayBase(cfg.RelayBase)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, metricsURL, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metrics status: %s", resp.Status)
	}

	reasons := map[string]float64{}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		matches := droppedDatagramsRe.FindStringSubmatch(line)
		if len(matches) != 3 {
			continue
		}
		labels := parsePromLabels(matches[1])
		reason := labels["reason"]
		if reason == "" {
			reason = "unknown"
		}
		value, err := strconv.ParseFloat(matches[2], 64)
		if err != nil {
			continue
		}
		reasons[reason] = value
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return reasons, nil
}

func metricsURLFromRelayBase(relayBase string) (string, error) {
	base := strings.TrimSpace(relayBase)
	if base == "" {
		return "", errors.New("empty relay base")
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u.Path = "/metrics"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func parsePromLabels(raw string) map[string]string {
	labels := map[string]string{}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return labels
	}
	parts := strings.Split(raw, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.Trim(strings.TrimSpace(kv[1]), "\"")
		if key != "" {
			labels[key] = val
		}
	}
	return labels
}

func printSummary(report benchReport) {
	fmt.Println("\nVLF proto_bench summary")
	fmt.Println("---------------------------------------------------------------")
	fmt.Printf("%-20s %-12s %-12s %-12s\n", "Test", "Transport", "Main", "Status")
	fmt.Println("---------------------------------------------------------------")
	fmt.Printf("%-20s %-12s %-12.2f %-12s\n", "TCP throughput", report.TCP.Transport, report.TCP.Mbps, statusLane(report.TCP.Error, report.TCP.PassByQuality))
	fmt.Printf("%-20s %-12s %-12.2f %-12s\n", "UDP PPS", report.UDP.Transport, report.UDP.EffectivePPS, statusLane(report.UDP.Error, report.UDP.PassByQuality))
	fmt.Printf("%-20s %-12s %-12d %-12s\n", "Concurrency", "-", report.Concurrent.Success, statusFromCounts(report.Concurrent.Fail))
	fmt.Printf("%-20s %-12s %-12d %-12s\n", "Fallback", "-", report.Fallback.Success, statusFromCounts(report.Fallback.Fail))
	if report.Soak != nil {
		fmt.Printf("%-20s %-12s %-12d %-12s\n", "Soak", "-", report.Soak.Success, statusFromCounts(report.Soak.Fail))
	}
	fmt.Println("---------------------------------------------------------------")
	fmt.Printf("TCP threshold: min %.2f Mbps, pass_by_quality=%t\n", report.TCP.MinMbps, report.TCP.PassByQuality)
	fmt.Printf("UDP thresholds: max loss %.2f%%, max jitter %.2f ms, pass_by_quality=%t\n", report.UDP.MaxLossRatio*100.0, report.UDP.MaxJitterMS, report.UDP.PassByQuality)
	fmt.Printf("TCP p95/p99: %.2f / %.2f ms\n", report.TCP.LatencyP95MS, report.TCP.LatencyP99MS)
	fmt.Printf("UDP loss/jitter: %.2f%% / %.2f ms\n", report.UDP.LossPercent, report.UDP.JitterMS)
	fmt.Printf("Handshake p95/p99: %.2f / %.2f ms\n", report.Concurrent.HandshakeP95MS, report.Concurrent.HandshakeP99MS)
	fmt.Printf("Fallback share: %v\n", report.Fallback.SharePercent)
	if len(report.ServerUDPDropReasons) > 0 {
		fmt.Printf("Server UDP drop reasons: %v\n", report.ServerUDPDropReasons)
	}
	if len(report.Errors) > 0 {
		fmt.Printf("Errors: %s\n", strings.Join(report.Errors, " | "))
	}
}

func writeJSON(path string, report benchReport) error {
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func writeMarkdown(path string, report benchReport) error {
	b := &strings.Builder{}
	b.WriteString("# VLF proto_bench report\n\n")
	b.WriteString(fmt.Sprintf("- Started: `%s`\n", report.StartedAt.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("- Ended: `%s`\n", report.EndedAt.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("- Host: `%s/%s`\n", report.HostOS, report.HostArch))
	b.WriteString(fmt.Sprintf("- Clients: `%d`\n", report.Options.Clients))
	b.WriteString(fmt.Sprintf("- Duration: `%s`\n", report.Options.Duration))
	b.WriteString("\n## Summary\n\n")
	b.WriteString("| Test | Transport | Main | Status |\n")
	b.WriteString("|---|---|---:|---|\n")
	b.WriteString(fmt.Sprintf("| TCP throughput | %s | %.2f Mbps | %s |\n", report.TCP.Transport, report.TCP.Mbps, statusLane(report.TCP.Error, report.TCP.PassByQuality)))
	b.WriteString(fmt.Sprintf("| UDP PPS | %s | %.2f pps | %s |\n", report.UDP.Transport, report.UDP.EffectivePPS, statusLane(report.UDP.Error, report.UDP.PassByQuality)))
	b.WriteString(fmt.Sprintf("| Concurrency | - | %d/%d success | %s |\n", report.Concurrent.Success, report.Concurrent.Clients, statusFromCounts(report.Concurrent.Fail)))
	b.WriteString(fmt.Sprintf("| Fallback | - | %d/%d success | %s |\n", report.Fallback.Success, report.Fallback.Attempts, statusFromCounts(report.Fallback.Fail)))
	if report.Soak != nil {
		b.WriteString(fmt.Sprintf("| Soak | - | %d/%d success | %s |\n", report.Soak.Success, report.Soak.Iterations, statusFromCounts(report.Soak.Fail)))
	}
	b.WriteString("\n## Details\n\n")
	b.WriteString(fmt.Sprintf("- TCP threshold: min `%.2f Mbps`, pass_by_quality=`%t`\n", report.TCP.MinMbps, report.TCP.PassByQuality))
	if report.TCP.QualityReason != "" {
		b.WriteString(fmt.Sprintf("- TCP quality reason: `%s`\n", report.TCP.QualityReason))
	}
	b.WriteString(fmt.Sprintf("- UDP thresholds: max_loss=`%.4f` (%.2f%%), max_jitter_ms=`%.2f`, pass_by_quality=`%t`\n", report.UDP.MaxLossRatio, report.UDP.MaxLossRatio*100.0, report.UDP.MaxJitterMS, report.UDP.PassByQuality))
	if report.UDP.QualityReason != "" {
		b.WriteString(fmt.Sprintf("- UDP quality reason: `%s`\n", report.UDP.QualityReason))
	}
	b.WriteString(fmt.Sprintf("- TCP p95/p99 latency: `%.2f / %.2f ms`\n", report.TCP.LatencyP95MS, report.TCP.LatencyP99MS))
	b.WriteString(fmt.Sprintf("- UDP loss/jitter: `%.2f%% / %.2f ms`\n", report.UDP.LossPercent, report.UDP.JitterMS))
	b.WriteString(fmt.Sprintf("- Handshake p95/p99: `%.2f / %.2f ms`\n", report.Concurrent.HandshakeP95MS, report.Concurrent.HandshakeP99MS))
	b.WriteString(fmt.Sprintf("- Fallback share: `%v`\n", report.Fallback.SharePercent))
	if len(report.ServerUDPDropReasons) > 0 {
		b.WriteString(fmt.Sprintf("- Server UDP drop reasons: `%v`\n", report.ServerUDPDropReasons))
	}
	if report.Fallback.Note != "" {
		b.WriteString(fmt.Sprintf("- Fallback note: `%s`\n", report.Fallback.Note))
	}
	if len(report.Errors) > 0 {
		b.WriteString("\n## Errors\n\n")
		for _, err := range report.Errors {
			b.WriteString("- " + err + "\n")
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func statusLane(errText string, passByQuality bool) string {
	if strings.TrimSpace(errText) == "" {
		if passByQuality {
			return "PASS"
		}
		return "FAIL"
	}
	return "FAIL"
}

func statusFromCounts(fail int) string {
	if fail == 0 {
		return "PASS"
	}
	return "FAIL"
}

func percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	cp := make([]float64, len(values))
	copy(cp, values)
	sort.Float64s(cp)
	rank := (p / 100.0) * float64(len(cp)-1)
	low := int(math.Floor(rank))
	high := int(math.Ceil(rank))
	if low == high {
		return cp[low]
	}
	weight := rank - float64(low)
	return cp[low]*(1.0-weight) + cp[high]*weight
}

func jitterFromRTT(rtts []float64) float64 {
	if len(rtts) < 2 {
		return 0
	}
	total := 0.0
	prev := rtts[0]
	for i := 1; i < len(rtts); i++ {
		total += math.Abs(rtts[i] - prev)
		prev = rtts[i]
	}
	return total / float64(len(rtts)-1)
}

func fillPattern(dst []byte, seed byte) {
	for i := range dst {
		dst[i] = seed + byte(i&0x0f)
	}
}

func bytesEqual(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func envOr(name string, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func envOrInt(name string, fallback int) int {
	if v := os.Getenv(name); v != "" {
		if out, err := strconv.Atoi(v); err == nil {
			return out
		}
	}
	return fallback
}
