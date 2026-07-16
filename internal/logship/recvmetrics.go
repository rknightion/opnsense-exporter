package logship

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// ReceiverMetrics are the self-metrics every push receiver reports, bound to one
// source name.
//
// The underlying CounterVecs are SHARED across receivers and carry a `source`
// label. They have to be: each receiver builds its metrics in its own factory
// against the same self-metrics registry, so two receivers each registering a
// private `logs_parse_errors_total` would panic the exporter at startup on
// duplicate registration. The syslog package previously owned these two generic
// names with no source label, while every other pipeline self-metric
// (logs_shipped_total etc.) already carried one — so syslog was the outlier and
// the zenarmor receiver was simply the first thing to trip it.
//
// Registration uses Register + AlreadyRegisteredError rather than MustRegister so
// the second caller reuses the first caller's collector instead of exploding. That
// is the idiomatic Prometheus answer for a collector with several owners, and
// unlike a sync.Once it keeps working when tests hand in a fresh registry per test.
//
// A nil *ReceiverMetrics is a no-op, so tests and any caller that opts out can pass
// nil.
type ReceiverMetrics struct {
	parseErrors *prometheus.CounterVec
	rejected    *prometheus.CounterVec
	source      string
}

// NewReceiverMetrics returns a handle bound to source, registering the shared vecs
// on reg if they are not there already. reg may be nil, giving a no-op handle.
func NewReceiverMetrics(reg prometheus.Registerer, source string) *ReceiverMetrics {
	const ns = "opnsense_exporter"
	m := &ReceiverMetrics{
		source: source,
		parseErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_parse_errors_total",
			Help: "Total log records that failed to parse, by source and stage. The record is still shipped, unparsed.",
		}, []string{"source", "stage"}),
		rejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_rejected_total",
			Help: "Total receiver input rejected before parsing, by source and reason.",
		}, []string{"source", "reason"}),
	}
	if reg == nil {
		return m
	}
	m.parseErrors = registerOrExisting(reg, m.parseErrors)
	m.rejected = registerOrExisting(reg, m.rejected)
	return m
}

// registerOrExisting registers c, or returns the equivalent collector another
// receiver registered first. Anything other than an AlreadyRegisteredError is a
// programming error and panics, exactly as MustRegister would.
func registerOrExisting(reg prometheus.Registerer, c *prometheus.CounterVec) *prometheus.CounterVec {
	err := reg.Register(c)
	if err == nil {
		return c
	}
	var are prometheus.AlreadyRegisteredError
	if errors.As(err, &are) {
		if existing, ok := are.ExistingCollector.(*prometheus.CounterVec); ok {
			return existing
		}
	}
	panic(err)
}

// ParseError counts one record that failed to parse at the named stage. A parse
// error never drops the record — it ships with a raw body.
func (m *ReceiverMetrics) ParseError(stage string) {
	if m == nil || m.parseErrors == nil {
		return
	}
	m.parseErrors.WithLabelValues(m.source, stage).Inc()
}

// Reject counts one unit of input dropped before parsing, by reason.
func (m *ReceiverMetrics) Reject(reason string) {
	if m == nil || m.rejected == nil {
		return
	}
	m.rejected.WithLabelValues(m.source, reason).Inc()
}
