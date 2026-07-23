package logship

import (
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

// Drop reasons for logs_dropped_total.
const (
	dropReasonOverflow   = "overflow"    // queue full (count or byte budget), oldest evicted
	dropReasonShipFailed = "ship_failed" // shutdown abandoned a batch that was still failing
	// dropReasonShipFailedPermanent is a batch the sink refused for
	// --logs.ship-max-attempts consecutive attempts while the pipeline was still
	// RUNNING. Kept distinct from ship_failed so "we lost records because the process
	// was going down anyway" and "we lost records because the sink permanently rejects
	// them" are separable in a query — they need different operator responses (#325a).
	dropReasonShipFailedPermanent = "ship_failed_permanent"
	// dropReasonRecordTooLarge is a record rejected at INGEST because its estimated
	// retained size exceeded --logs.max-record-bytes. It never entered the queue, so it
	// never displaced other records and never became a batch the sink would refuse (#318).
	dropReasonRecordTooLarge = "record_too_large"
)

// metrics holds the pipeline self-metrics. They register into the exporter's
// self-metrics registry (so they appear at /metrics and via the OTLP metrics
// bridge). Every metric here is mirrored by a panel on the Logs dashboard tab, but
// BY HAND: the grafana coverage gate builds its catalogue from docs/metrics/metrics.md,
// which docgen fills from the collector registry only — no opnsense_exporter_logs*
// metric appears there, so nothing fails when one lands without a panel. Adding a
// metric here means adding its panel yourself.
type metrics struct {
	shipped        *prometheus.CounterVec // logs_shipped_total{source}
	dropped        *prometheus.CounterVec // logs_dropped_total{source,reason}
	shipErrors     prometheus.Counter     // logs_ship_errors_total
	pollErrors     *prometheus.CounterVec // logs_poll_errors_total{source}
	lastEventTime  *prometheus.GaugeVec   // logs_last_event_timestamp_seconds{source}
	queueLength    prometheus.GaugeFunc   // logs_queue_length
	queueCapacity  prometheus.Gauge       // logs_queue_capacity
	queueBytes     prometheus.GaugeFunc   // logs_queue_bytes
	queueMaxBytes  prometheus.Gauge       // logs_queue_max_bytes
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

// queueBounds carries the queue's two bounds and the two lazy samplers that report
// its current occupancy against them. It is a struct rather than four positional
// arguments because the count pair and the byte pair are trivially transposable at a
// call site, and swapping them would silently publish a capacity as a byte budget.
type queueBounds struct {
	capacity int            // record-count cap (--logs.buffer-size)
	maxBytes int            // aggregate byte budget (--logs.buffer-max-bytes), 0 = disabled
	length   func() float64 // current queued record count
	bytes    func() float64 // current estimated queued bytes
}

// newMetrics constructs and registers the pipeline self-metrics on reg, then
// pre-initialises the labelled counters named by names to zero. The occupancy
// samplers on q are read lazily by the queue_length / queue_bytes GaugeFuncs.
func newMetrics(reg prometheus.Registerer, q queueBounds, names sourceNames) *metrics {
	const ns = "opnsense_exporter"
	// A GaugeFunc panics on Gather if its sampler is nil, which would turn a caller
	// that simply does not care about one bound into a /metrics outage. Default the
	// samplers instead: a queue that reports 0 is honest for a caller with no queue.
	if q.length == nil {
		q.length = func() float64 { return 0 }
	}
	if q.bytes == nil {
		q.bytes = func() float64 { return 0 }
	}
	m := &metrics{
		shipped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_shipped_total",
			Help: "Total log records the sink confirmed exported to the OTLP endpoint (a synchronous, " +
				"acknowledged delivery — not merely enqueued), by source.",
		}, []string{"source"}),
		dropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_dropped_total",
			Help: "Total log records dropped before delivery, by source and reason " +
				"(overflow = the backpressure queue evicted the oldest record after exceeding its " +
				"record-count cap or its byte budget; record_too_large = the record exceeded the " +
				"per-record size cap and was rejected at ingest; ship_failed_permanent = the sink " +
				"refused the batch for the maximum number of attempts while running, so it was " +
				"abandoned rather than wedging delivery of every later batch; " +
				"ship_failed = shutdown abandoned a batch that was still failing to export).",
		}, []string{"source", "reason"}),
		shipErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_ship_errors_total",
			Help: "Total sink export attempts that failed. The batch is retried in memory; a batch is " +
				"only lost — and separately counted as logs_dropped_total{reason=\"ship_failed_permanent\"} " +
				"while running, or {reason=\"ship_failed\"} at shutdown — once the retries are exhausted.",
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
			Help: "Configured record-count capacity of the log-shipping backpressure queue.",
		}),
		// The queue is bounded by records AND by bytes (#318). The record count alone
		// says nothing about memory — a receiver retains each record's raw body — so
		// queue_length can sit at 1% of capacity while queue_bytes is at its budget and
		// records are being evicted. Both bounds need their own occupancy series or an
		// operator cannot tell which one is actually biting.
		queueMaxBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: ns, Name: "logs_queue_max_bytes",
			Help: "Configured aggregate byte budget of the log-shipping backpressure queue " +
				"(0 = no byte budget, records bounded by count only).",
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
		Help: "Current depth of the log-shipping backpressure queue, in records.",
	}, q.length)
	m.queueBytes = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: ns, Name: "logs_queue_bytes",
		Help: "Estimated heap currently retained by queued log records (record bodies, source " +
			"names and attributes, plus a fixed per-record and per-attribute allowance). Compare " +
			"against logs_queue_max_bytes: this can be at its budget while logs_queue_length is " +
			"nowhere near capacity, which is exactly the case the record count cannot see.",
	}, q.bytes)

	m.queueCapacity.Set(float64(q.capacity))
	m.queueMaxBytes.Set(float64(q.maxBytes))
	reg.MustRegister(
		m.shipped, m.dropped, m.shipErrors, m.pollErrors,
		m.lastEventTime, m.queueLength, m.queueCapacity, m.possibleGap,
		m.resourceCapped, m.queueBytes, m.queueMaxBytes,
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
		m.dropped.WithLabelValues(s, dropReasonShipFailed)
		m.dropped.WithLabelValues(s, dropReasonShipFailedPermanent)
		m.dropped.WithLabelValues(s, dropReasonRecordTooLarge)
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

// consoleShipped and consoleDropped mirror logs_shipped_total and
// logs_dropped_total as raw, process-lifetime totals for the operator console,
// which differences them over elapsed wall time into a per-second rate.
//
// They exist because the console cannot read the Prometheus counters: those live
// on the exporter's SELF-metrics registry, and the console is built only from the
// metricsnap snapshot of the COLLECTOR registry (internal/server/metrics.go tees
// that one alone), never from a Gather of its own. Two atomic adds per shipped
// batch is cheaper than either alternative.
//
// Package-level for the same reason activePossibleGapVec is: source.go/pipeline.go
// are the frozen cross-lane contract and metrics.go is the file self-metrics land
// in. Only one pipeline runs per process in production.
var (
	consoleShipped atomic.Uint64
	consoleDropped atomic.Uint64
)

// Throughput returns the process-lifetime totals of log records the sink confirmed
// exported and of records lost before delivery (queue overflow, or a batch
// abandoned at shutdown). Both are monotonic within a process, so a caller
// differences successive reads over elapsed wall time to get a rate. Safe to call
// before any pipeline starts — it reads zeroes.
func Throughput() (shipped, dropped uint64) {
	return consoleShipped.Load(), consoleDropped.Load()
}
