package logship

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Drop reasons for logs_dropped_total.
const (
	dropReasonOverflow = "overflow" // queue full, oldest evicted
)

// metrics holds the pipeline self-metrics. They register into the exporter's
// self-metrics registry (so they appear at /metrics and via the OTLP metrics
// bridge). Every metric here is mirrored by a panel on the Logs dashboard tab —
// the grafana coverage gate enforces that.
type metrics struct {
	shipped       *prometheus.CounterVec // logs_shipped_total{source}
	dropped       *prometheus.CounterVec // logs_dropped_total{source,reason}
	shipErrors    prometheus.Counter     // logs_ship_errors_total
	pollErrors    *prometheus.CounterVec // logs_poll_errors_total{source}
	lastEventTime *prometheus.GaugeVec   // logs_last_event_timestamp_seconds{source}
	queueLength   prometheus.GaugeFunc   // logs_queue_length
	queueCapacity prometheus.Gauge       // logs_queue_capacity
	possibleGap   *prometheus.CounterVec // logs_possible_gap_total{source}
}

// newMetrics constructs and registers the pipeline self-metrics on reg. queueLen
// is sampled lazily by the queue_length GaugeFunc.
func newMetrics(reg prometheus.Registerer, capacity int, queueLen func() float64) *metrics {
	const ns = "opnsense_exporter"
	m := &metrics{
		shipped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_shipped_total",
			Help: "Total log records successfully handed to the sink, by source.",
		}, []string{"source"}),
		dropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_dropped_total",
			Help: "Total log records dropped before delivery, by source and reason.",
		}, []string{"source", "reason"}),
		shipErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_ship_errors_total",
			Help: "Total sink Emit errors (a failed batch is dropped and counted).",
		}),
		pollErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_poll_errors_total",
			Help: "Total source Poll errors, by source.",
		}, []string{"source"}),
		lastEventTime: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns, Name: "logs_last_event_timestamp_seconds",
			Help: "Unix timestamp of the most recent event shipped, by source (cursor lag).",
		}, []string{"source"}),
		queueCapacity: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: ns, Name: "logs_queue_capacity",
			Help: "Configured capacity of the log-shipping backpressure queue.",
		}),
		// possibleGap is reserved by the #228 design for any source whose only view of
		// its underlying data is a bounded/count-capped window rather than a true
		// cursor — the unbound per-query DNS log source (#233) is the first consumer:
		// api/unbound/overview/search_queries exposes only the newest 1000 rows
		// resolver-wide, so a busy resolver can silently push older, never-fetched rows
		// out of that window between polls. Incremented whenever a poll's page shows no
		// continuity with the previous cursor (see recordPossibleGap below) — an honest
		// "we know we probably lost some" signal, never a silent drop.
		possibleGap: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_possible_gap_total",
			Help: "Total possible sampling gaps detected by a source whose only view of its " +
				"underlying data is a bounded window (e.g. unbound's latest-1000-row DNS " +
				"query log), by source. Incremented when a poll's page shows no continuity " +
				"with the previous cursor, meaning an unknown amount of data was skipped " +
				"between polls.",
		}, []string{"source"}),
	}
	m.queueLength = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: ns, Name: "logs_queue_length",
		Help: "Current depth of the log-shipping backpressure queue.",
	}, queueLen)

	m.queueCapacity.Set(float64(capacity))
	reg.MustRegister(
		m.shipped, m.dropped, m.shipErrors, m.pollErrors,
		m.lastEventTime, m.queueLength, m.queueCapacity, m.possibleGap,
	)
	setActivePossibleGapVec(m.possibleGap)
	return m
}

// activePossibleGap holds a reference to the running pipeline's possibleGap
// CounterVec so source lanes (internal/logship/<name>.go) can count a possible
// gap without needing their own access to the pipeline's Prometheus registry —
// Source implementations receive only Deps{Client, Logger} (see source.go),
// not a Registerer. This is package-level rather than threaded through the
// Source interface deliberately: source.go/pipeline.go are the frozen
// cross-lane contract for #228's concurrent source lanes, and metrics.go is
// the one file each lane may extend, so new self-metrics land here instead of
// changing that contract. Only one pipeline runs per process in production;
// tests that build a pipeline sequentially (never in parallel) are safe too.
var (
	activePossibleGapMu  sync.Mutex
	activePossibleGapVec *prometheus.CounterVec
)

func setActivePossibleGapVec(v *prometheus.CounterVec) {
	activePossibleGapMu.Lock()
	defer activePossibleGapMu.Unlock()
	activePossibleGapVec = v
}

// recordPossibleGap increments logs_possible_gap_total{source=name}. It is a
// no-op before any pipeline has called newMetrics in this process (e.g. a
// source unit test that never starts a pipeline) so it is always safe to call.
func recordPossibleGap(name string) {
	activePossibleGapMu.Lock()
	v := activePossibleGapVec
	activePossibleGapMu.Unlock()
	if v != nil {
		v.WithLabelValues(name).Inc()
	}
}
