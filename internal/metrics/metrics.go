package metrics

import (
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	registry *prometheus.Registry

	ActiveSessions   prometheus.Gauge
	ActiveRelayConns prometheus.Gauge
	BytesIn          *prometheus.CounterVec
	BytesOut         *prometheus.CounterVec
	UDPPackets       prometheus.Counter
	UDPPPS           prometheus.Gauge
	TCPStreams       prometheus.Gauge
	AuthFailures     prometheus.Counter
	ReplayDrops      prometheus.Counter
	OpenFailures     *prometheus.CounterVec

	udpPacketsSecond atomic.Uint64
	stopCh           chan struct{}
}

func New() *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		registry: reg,
		ActiveSessions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vlf_active_sessions",
			Help: "Active QUIC sessions",
		}),
		ActiveRelayConns: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vlf_active_relay_conns",
			Help: "Active relay TCP connections",
		}),
		BytesIn: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vlf_bytes_in_total",
			Help: "Total bytes coming into the gateway",
		}, []string{"lane"}),
		BytesOut: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vlf_bytes_out_total",
			Help: "Total bytes leaving the gateway",
		}, []string{"lane"}),
		UDPPackets: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vlf_udp_packets_total",
			Help: "Total UDP datagrams forwarded in session lane",
		}),
		UDPPPS: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vlf_udp_pps",
			Help: "Current UDP packets per second",
		}),
		TCPStreams: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vlf_tcp_streams",
			Help: "Active QUIC TCP streams",
		}),
		AuthFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vlf_auth_failures_total",
			Help: "Authentication failures",
		}),
		ReplayDrops: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vlf_replay_drops_total",
			Help: "Replay-protection drops",
		}),
		OpenFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vlf_open_failures_total",
			Help: "Open failures by lane and reason",
		}, []string{"lane", "reason"}),
		stopCh: make(chan struct{}),
	}

	reg.MustRegister(
		m.ActiveSessions,
		m.ActiveRelayConns,
		m.BytesIn,
		m.BytesOut,
		m.UDPPackets,
		m.UDPPPS,
		m.TCPStreams,
		m.AuthFailures,
		m.ReplayDrops,
		m.OpenFailures,
	)

	go m.ppsLoop()
	return m
}

func (m *Metrics) ppsLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pps := m.udpPacketsSecond.Swap(0)
			m.UDPPPS.Set(float64(pps))
		case <-m.stopCh:
			return
		}
	}
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *Metrics) ObserveUDPPacket() {
	m.UDPPackets.Inc()
	m.udpPacketsSecond.Add(1)
}

func (m *Metrics) Close() {
	close(m.stopCh)
}
