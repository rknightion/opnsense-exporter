package syslog

import "github.com/prometheus/client_golang/prometheus"

// Metrics are the syslog receiver's self-metrics. The logship pipeline's own
// metrics type is unexported and unreachable from here, so these are constructed
// in main.go against the self-metrics registry and INJECTED (see the design's
// frozen seams). A nil *Metrics is a no-op, so tests and any caller that opts out
// can pass nil.
type Metrics struct {
	// ParseErrors counts lines the receiver could not parse, by stage:
	// "envelope" (not syslog at all) or "filterlog" (envelope OK, body wasn't).
	// A parse error never drops the line — it ships with a raw body.
	ParseErrors *prometheus.CounterVec
	// Rejected counts input dropped before parsing, by reason: "peer" (outside the
	// allowlist) or "oversized" (declared frame > maxMessageBytes).
	Rejected *prometheus.CounterVec
}

// NewMetrics registers the receiver's self-metrics on reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	const ns = "opnsense_exporter"
	m := &Metrics{
		ParseErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_parse_errors_total",
			Help: "Total syslog lines that failed to parse, by stage. The line is still shipped, unparsed.",
		}, []string{"stage"}),
		Rejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_rejected_total",
			Help: "Total syslog input rejected before parsing, by reason (peer not allowed, frame oversized).",
		}, []string{"reason"}),
	}
	if reg != nil {
		reg.MustRegister(m.ParseErrors, m.Rejected)
	}
	return m
}

func (m *Metrics) parseError(stage string) {
	if m == nil || m.ParseErrors == nil {
		return
	}
	m.ParseErrors.WithLabelValues(stage).Inc()
}

func (m *Metrics) reject(reason string) {
	if m == nil || m.Rejected == nil {
		return
	}
	m.Rejected.WithLabelValues(reason).Inc()
}
