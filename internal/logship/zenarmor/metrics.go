package zenarmor

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/internal/logship"
)

// metrics are the receiver's self-metrics. recv carries the two shared,
// source-labelled counters every push receiver reports; the bulk pair is specific
// to this receiver's transport.
//
// A nil *metrics is a no-op throughout, so tests can construct a server without a
// registry.
type metrics struct {
	recv      *logship.ReceiverMetrics
	bulkReqs  *zenarmorCounter
	bulkBytes *zenarmorCounter
	excluded  *zenarmorCounterVec
}

// These named wrappers make AlreadyRegisteredError type checks exact. Prometheus'
// Counter interface is structural, so a Gauge also satisfies it; accepting an
// existing collector through that interface would silently turn a same-name,
// wrong-type collision into a broken metric family.
type zenarmorCounter struct{ prometheus.Counter }
type zenarmorCounterVec struct{ *prometheus.CounterVec }

// newMetrics builds the receiver's metrics. rules are the configured exclude rules,
// used only to pre-initialise logs_zenarmor_excluded_total to zero per rule (#280):
// a rule that has never matched must read 0 rather than vanish, because "no series"
// would otherwise mean both "this rule drops nothing" and "this rule is dropping
// everything but the exporter restarted".
func newMetrics(reg prometheus.Registerer, rules []ExcludeRule) *metrics {
	const ns = "opnsense_exporter"
	m := &metrics{
		recv: logship.NewReceiverMetrics(reg, sourceName, logship.ReceiverVocab{
			Reasons: RejectReasons,
			Stages:  ParseStages,
		}),
		excluded: &zenarmorCounterVec{prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_zenarmor_excluded_total",
			Help: "Total Zenarmor records dropped by a --logs.zenarmor.exclude rule, by rule. The " +
				"rule label is the rule as configured, so the blind spot an exclusion creates is " +
				"visible here rather than only in the exporter's command line. Derived counters are " +
				"observed before the drop, so opnsense_log_events_zenarmor_total still describes " +
				"excluded traffic — but its raw record, and every high-cardinality field on it " +
				"(server_name, query, device_name), is gone for good.",
		}, []string{"rule"})},
		bulkReqs: &zenarmorCounter{prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_zenarmor_bulk_requests_total",
			Help: "Total Elasticsearch _bulk requests accepted from Zenarmor.",
		})},
		bulkBytes: &zenarmorCounter{prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_zenarmor_bulk_bytes_total",
			Help: "Total _bulk request body bytes accepted from Zenarmor, measured after " +
				"decompression so the figure reflects parsed volume rather than what the " +
				"socket carried.",
		})},
	}
	if reg != nil {
		m.bulkReqs = registerCounterOrExisting(reg, m.bulkReqs)
		m.bulkBytes = registerCounterOrExisting(reg, m.bulkBytes)
		m.excluded = registerCounterVecOrExisting(reg, m.excluded)
	}
	// The rule set is closed and known at startup — it is the operator's own config —
	// so pre-initialising is bounded by it, not by anything off the wire.
	for _, r := range rules {
		m.excluded.WithLabelValues(r.Raw)
	}
	return m
}

func registerCounterOrExisting(reg prometheus.Registerer, c *zenarmorCounter) *zenarmorCounter {
	if err := reg.Register(c); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(*zenarmorCounter); ok {
				return existing
			}
		}
		panic(err)
	}
	return c
}

func registerCounterVecOrExisting(reg prometheus.Registerer, c *zenarmorCounterVec) *zenarmorCounterVec {
	if err := reg.Register(c); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(*zenarmorCounterVec); ok {
				return existing
			}
		}
		panic(err)
	}
	return c
}

// exclude counts one record dropped by rule, on both counters: the shared
// logs_rejected_total so an exclusion appears alongside every other configured drop
// (filtered, self_traffic), and logs_zenarmor_excluded_total so the operator can see
// WHICH rule did it. The aggregate alone cannot distinguish a rule that drops
// nothing from one quietly eating the whole stream.
func (m *metrics) exclude(rule ExcludeRule) {
	if m == nil {
		return
	}
	m.reject("excluded")
	m.excluded.WithLabelValues(rule.Raw).Inc()
}

// reject counts one unit of input dropped before parsing.
func (m *metrics) reject(reason string) {
	if m == nil {
		return
	}
	m.recv.Reject(reason)
}

// parseError counts one record that failed to parse. The record still ships.
func (m *metrics) parseError(stage string) {
	if m == nil {
		return
	}
	m.recv.ParseError(stage)
}

// observeBulk counts one accepted _bulk request of n decompressed body bytes.
func (m *metrics) observeBulk(n int) {
	if m == nil {
		return
	}
	m.bulkReqs.Inc()
	m.bulkBytes.Add(float64(n))
}
