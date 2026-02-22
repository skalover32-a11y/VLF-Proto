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
	UDPForwarded     prometheus.Counter
	UDPDstRX         prometheus.Counter
	UDPToClient      prometheus.Counter
	UDPToClientFail  prometheus.Counter
	UDPPPS           prometheus.Gauge
	RecvDatagrams    prometheus.Counter
	RecvBytes        prometheus.Counter
	DroppedDatagrams *prometheus.CounterVec
	DatagramProcPPS  prometheus.Gauge
	DatagramQueueLen prometheus.Gauge
	TCPStreams       prometheus.Gauge
	AuthFailures     prometheus.Counter
	ReplayDrops      prometheus.Counter
	OpenFailures     *prometheus.CounterVec

	udpPacketsSecond       atomic.Uint64
	datagramProcSecond     atomic.Uint64
	datagramQueueLenAtomic atomic.Int64
	stopCh                 chan struct{}
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
			Help: "Deprecated alias of vlf_udp_forwarded_total",
		}),
		UDPForwarded: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vlf_udp_forwarded_total",
			Help: "Total UDP datagrams forwarded from client to destination in session lane",
		}),
		UDPDstRX: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vlf_udp_dst_rx_total",
			Help: "Total UDP datagrams read from destination sockets in session lane",
		}),
		UDPToClient: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vlf_udp_to_client_total",
			Help: "Total UDP datagrams sent from gateway back to client over QUIC DATAGRAM",
		}),
		UDPToClientFail: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vlf_udp_to_client_fail_total",
			Help: "Total UDP datagrams failed to send from gateway to client over QUIC DATAGRAM",
		}),
		UDPPPS: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vlf_udp_pps",
			Help: "Current UDP forwarded packets per second (client to destination)",
		}),
		RecvDatagrams: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vlf_recv_datagrams_total",
			Help: "Total received QUIC datagrams on session lane",
		}),
		RecvBytes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vlf_recv_bytes_total",
			Help: "Total received QUIC datagram bytes on session lane",
		}),
		DroppedDatagrams: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vlf_dropped_datagrams_total",
			Help: "Dropped received QUIC datagrams by reason",
		}, []string{"reason"}),
		DatagramProcPPS: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vlf_datagrams_processing_pps",
			Help: "Current per-second processed datagrams on session lane",
		}),
		DatagramQueueLen: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vlf_datagram_queue_length",
			Help: "Current in-memory datagram queue length",
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
		m.UDPForwarded,
		m.UDPDstRX,
		m.UDPToClient,
		m.UDPToClientFail,
		m.UDPPPS,
		m.RecvDatagrams,
		m.RecvBytes,
		m.DroppedDatagrams,
		m.DatagramProcPPS,
		m.DatagramQueueLen,
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
			proc := m.datagramProcSecond.Swap(0)
			m.DatagramProcPPS.Set(float64(proc))
		case <-m.stopCh:
			return
		}
	}
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *Metrics) ObserveUDPPacket() {
	m.ObserveUDPForwarded()
}

func (m *Metrics) ObserveUDPForwarded() {
	// Keep old metric for backward compatibility.
	m.UDPPackets.Inc()
	m.UDPForwarded.Inc()
	m.udpPacketsSecond.Add(1)
}

func (m *Metrics) ObserveUDPDstRX() {
	m.UDPDstRX.Inc()
}

func (m *Metrics) ObserveUDPToClient() {
	m.UDPToClient.Inc()
}

func (m *Metrics) ObserveUDPToClientFail() {
	m.UDPToClientFail.Inc()
}

func (m *Metrics) ObserveRecvDatagram(sizeBytes int) {
	m.RecvDatagrams.Inc()
	if sizeBytes > 0 {
		m.RecvBytes.Add(float64(sizeBytes))
	}
}

func (m *Metrics) ObserveProcessedDatagram() {
	m.datagramProcSecond.Add(1)
}

func (m *Metrics) ObserveDroppedDatagram(reason string) {
	if reason == "" {
		reason = "unknown"
	}
	m.DroppedDatagrams.WithLabelValues(reason).Inc()
}

func (m *Metrics) EnsureDroppedDatagramReason(reason string) {
	if reason == "" {
		reason = "unknown"
	}
	m.DroppedDatagrams.WithLabelValues(reason)
}

func (m *Metrics) AddDatagramQueue(delta int64) {
	current := m.datagramQueueLenAtomic.Add(delta)
	if current < 0 {
		m.datagramQueueLenAtomic.Store(0)
		current = 0
	}
	m.DatagramQueueLen.Set(float64(current))
}

func (m *Metrics) DatagramQueueCurrent() int64 {
	return m.datagramQueueLenAtomic.Load()
}

func (m *Metrics) Close() {
	close(m.stopCh)
}
