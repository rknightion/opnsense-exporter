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
	shipped        *prometheus.CounterVec // logs_shipped_total{source}
	dropped        *prometheus.CounterVec // logs_dropped_total{source,reason}
	shipErrors     prometheus.Counter     // logs_ship_errors_total
	pollErrors     *prometheus.CounterVec // logs_poll_errors_total{source}
	lastEventTime  *prometheus.GaugeVec   // logs_last_event_timestamp_seconds{source}
	queueLength    prometheus.GaugeFunc   // logs_queue_length
	queueCapacity  prometheus.Gauge       // logs_queue_capacity
	possibleGap    *prometheus.CounterVec // logs_possible_gap_total{source}
	resourceCapped prometheus.Counter     // logs_resource_capped_total
}

// sourceNames declares which sources the pipeline is running, so newMetrics can
// pre-initialise each labelled counter to zero (#280) for exactly the label
// combinations that source can actually produce.
//
// The three lists are deliberately not one list. A push receiver never calls Poll,
// and only a bounded-window source can gap, so seeding those counters for every
// source would publish zeroes that can never rise — which is not an honest zero, it
// claims we are watching something we are not.
type sourceNames struct {
	// all is every enabled source, poll and push: each can ship and can have a
	// record evicted when the shared queue overflows.
	all []string
	// poll is the poll sources only: only they can fail a Poll.
	poll []string
	// gap is the sources implementing GapReportingSource: only they can detect that
	// their bounded window skipped data.
	gap []string
}

// newMetrics constructs and registers the pipeline self-metrics on reg, then
// pre-initialises the labelled counters named by names to zero. queueLen is sampled
// lazily by the queue_length GaugeFunc.
func newMetrics(reg prometheus.Registerer, capacity int, queueLen func() float64, names sourceNames) *metrics {
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
		// resourceCapped counts records shipped with DEGRADED resource labels because
		// the distinct (source, subsystem, action) count hit maxLogResources. The
		// record is not lost — but its opnsense.* index labels are, so every
		// label-scoped query under-reports, and which records lose them depends on
		// arrival order. Before AttrAction existed the cap was genuinely unreachable
		// and this could go uncounted; action multiplies the key count, so it must
		// not be silent any more.
		resourceCapped: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_resource_capped_total",
			Help: "Total log records emitted with degraded resource labels because the distinct " +
				"(source, subsystem, action) count exceeded the sink's resource cap. The records " +
				"still ship, but they carry no opnsense.* index labels, so label-scoped queries " +
				"under-report. A non-zero value means the closed label sets grew beyond budget.",
		}),
	}
	m.queueLength = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: ns, Name: "logs_queue_length",
		Help: "Current depth of the log-shipping backpressure queue.",
	}, queueLen)

	m.queueCapacity.Set(float64(capacity))
	reg.MustRegister(
		m.shipped, m.dropped, m.shipErrors, m.pollErrors,
		m.lastEventTime, m.queueLength, m.queueCapacity, m.possibleGap,
		m.resourceCapped,
	)
	m.preInit(names)
	setActivePossibleGapVec(m.possibleGap)
	setActiveResourceCapped(m.resourceCapped)
	return m
}

// preInit publishes the known label combinations at zero (#280), so a healthy
// pipeline reports a flat 0 rather than nothing at all.
//
// Only the CounterVecs are seeded. lastEventTime is deliberately left alone: it is
// a GaugeVec of an event's unix timestamp, and a zero there would read as 1970 —
// claiming an event arrived at the epoch is worse than reporting no event yet.
func (m *metrics) preInit(names sourceNames) {
	for _, s := range names.all {
		m.shipped.WithLabelValues(s)
		m.dropped.WithLabelValues(s, dropReasonOverflow)
	}
	for _, s := range names.poll {
		m.pollErrors.WithLabelValues(s)
	}
	for _, s := range names.gap {
		m.possibleGap.WithLabelValues(s)
	}
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

// activeResourceCapped mirrors activePossibleGapVec for the OTLP sink's
// cardinality-cap counter: the sink is constructed by buildSink before (and
// independently of) the pipeline's own metrics, so it cannot hold the unexported
// metrics struct.
var (
	activeResourceCappedMu sync.Mutex
	activeResourceCapped   prometheus.Counter
)

func setActiveResourceCapped(c prometheus.Counter) {
	activeResourceCappedMu.Lock()
	defer activeResourceCappedMu.Unlock()
	activeResourceCapped = c
}

// recordResourceCapped increments logs_resource_capped_total. Like
// recordPossibleGap it is a no-op before any pipeline has called newMetrics, so a
// sink unit test that never starts a pipeline is safe.
func recordResourceCapped() {
	activeResourceCappedMu.Lock()
	c := activeResourceCapped
	activeResourceCappedMu.Unlock()
	if c != nil {
		c.Inc()
	}
}
