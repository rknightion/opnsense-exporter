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

// ReceiverVocab is a receiver's CLOSED, code-defined label vocabulary: every reason
// it can Reject with and every stage it can report a ParseError at.
//
// It exists so the counters can be pre-initialised to zero at construction (#280).
// A prometheus CounterVec emits NO series until its first increment, so before this
// a healthy receiver published nothing for its own error metrics and every restart
// reset them to invisible — rate() then returns no-data rather than 0, which is
// indistinguishable from a broken query or a dead exporter.
//
// Both sets MUST be closed and code-defined. Never put a value here that comes off
// the wire: pre-initialising an attacker-influenced or runtime-discovered value
// would turn a bounded set of zeroes into unbounded cardinality. The vocabularies
// are enforced against their call sites by TestReceiverVocabulariesMatchCallSites,
// so a new reason cannot be added without also being pre-initialised here.
type ReceiverVocab struct {
	// Reasons are the logs_rejected_total{reason=...} values this receiver produces.
	Reasons []string
	// Stages are the logs_parse_errors_total{stage=...} values this receiver produces.
	Stages []string
}

// NewReceiverMetrics returns a handle bound to source, registering the shared vecs
// on reg if they are not there already, and pre-initialising vocab's label
// combinations to zero. reg may be nil, giving a no-op handle.
func NewReceiverMetrics(reg prometheus.Registerer, source string, vocab ReceiverVocab) *ReceiverMetrics {
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
	// Pre-initialise only AFTER resolving the shared collectors: when a second
	// receiver registers, registerOrExisting hands back the FIRST receiver's vec and
	// discards the one built above. Seeding before this swap would write the zeroes
	// into a collector that never reaches /metrics.
	m.parseErrors = registerOrExisting(reg, m.parseErrors)
	m.rejected = registerOrExisting(reg, m.rejected)
	for _, reason := range vocab.Reasons {
		m.rejected.WithLabelValues(source, reason)
	}
	for _, stage := range vocab.Stages {
		m.parseErrors.WithLabelValues(source, stage)
	}
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
