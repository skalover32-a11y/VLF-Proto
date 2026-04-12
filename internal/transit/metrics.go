package transit

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	registry          *prometheus.Registry
	ActiveTCPConns    *prometheus.GaugeVec
	ActiveUDPSessions *prometheus.GaugeVec
	BytesIn           *prometheus.CounterVec
	BytesOut          *prometheus.CounterVec
	PacketsIn         *prometheus.CounterVec
	PacketsOut        *prometheus.CounterVec
	AcceptErrors      *prometheus.CounterVec
	DialFailures      *prometheus.CounterVec
	SessionsOpened    *prometheus.CounterVec
	SessionsClosed    *prometheus.CounterVec
}

func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		registry: reg,
		ActiveTCPConns: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "vlf_transit_active_tcp_conns",
			Help: "Active transit TCP connections by lane",
		}, []string{"lane"}),
		ActiveUDPSessions: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "vlf_transit_active_udp_sessions",
			Help: "Active transit UDP client mappings by lane",
		}, []string{"lane"}),
		BytesIn: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vlf_transit_bytes_in_total",
			Help: "Bytes received from public clients by lane",
		}, []string{"lane"}),
		BytesOut: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vlf_transit_bytes_out_total",
			Help: "Bytes sent back to public clients by lane",
		}, []string{"lane"}),
		PacketsIn: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vlf_transit_packets_in_total",
			Help: "UDP packets received from public clients by lane",
		}, []string{"lane"}),
		PacketsOut: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vlf_transit_packets_out_total",
			Help: "UDP packets sent back to public clients by lane",
		}, []string{"lane"}),
		AcceptErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vlf_transit_accept_errors_total",
			Help: "Listener accept or read errors by lane",
		}, []string{"lane"}),
		DialFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vlf_transit_dial_failures_total",
			Help: "Backend dial failures by lane",
		}, []string{"lane"}),
		SessionsOpened: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vlf_transit_sessions_opened_total",
			Help: "Transit session opens by lane",
		}, []string{"lane"}),
		SessionsClosed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vlf_transit_sessions_closed_total",
			Help: "Transit session closes by lane and reason",
		}, []string{"lane", "reason"}),
	}
	reg.MustRegister(
		m.ActiveTCPConns,
		m.ActiveUDPSessions,
		m.BytesIn,
		m.BytesOut,
		m.PacketsIn,
		m.PacketsOut,
		m.AcceptErrors,
		m.DialFailures,
		m.SessionsOpened,
		m.SessionsClosed,
	)
	return m
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}
