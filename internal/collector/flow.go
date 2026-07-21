package collector

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/internal/flow"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

// Default accumulator bounds, overridden by --flow.top-n / --flow.max-keys.
//
// Sized from the live corpus rather than guessed: 24 app_category values x ~5
// interfaces (once the VLAN children are split out) x 4 directions x ~4 transports
// x 3 actions x 4 scopes is ~24,000 theoretically possible, of which 500-2,000 are
// realistically occupied. topN=1000 therefore emits essentially everything real
// while still bounding the family, and maxKeys=2500 bounds the live map a little
// above the realistic occupancy so novelty is capped without steady-state traffic
// ever being folded.
const (
	defaultFlowTopN    = 1000
	defaultFlowMaxKeys = 2500
)

// Flow is the process-wide store of volume counters derived from flow records
// (#346). The Zenarmor lane — and, from phase 2, the NetFlow receiver — feed it out
// of band as a flow.Sink; the flow collector reads the running totals on each
// scrape.
//
// A singleton for the same reason as collector.LogEvents (logevents.go:13): the
// collector self-registers via init() while the receivers are constructed
// separately, so a package-level value is the seam that lets both reach the same
// totals without one package importing the other.
var Flow = newFlowStore(defaultFlowTopN, defaultFlowMaxKeys)

// FlowStore holds the bounded rollup plus the counters for repairs applied on the
// way in.
type FlowStore struct {
	rollup *flow.Rollup
	// payloadByteFallback counts records whose byte figure came from Zenarmor's
	// payload counter because its wire counter read zero. A repair nobody can
	// observe is a repair nobody will trust.
	payloadByteFallback atomic.Uint64
}

func newFlowStore(topN, maxKeys int) *FlowStore {
	return &FlowStore{rollup: flow.NewRollup(topN, maxKeys)}
}

// Observe folds one flow record into the counters. It implements flow.Sink and is
// called from receiver goroutines, so it must not block: the rollup takes a short
// mutex and does no I/O.
func (s *FlowStore) Observe(r flow.Record) {
	if r.Repairs.PayloadByteFallback {
		s.payloadByteFallback.Add(1)
	}
	s.rollup.Observe(r)
}

// setBounds retunes the accumulator in place.
func (s *FlowStore) setBounds(topN, maxKeys int) { s.rollup.SetBounds(topN, maxKeys) }

// ConfigureFlow sizes the process-wide accumulator from operator flags.
//
// main calls it before collector.New, and therefore before StartPolling launches a
// poller per collector. It is also safe to call at any other time: it mutates the
// bounds under the accumulator's own mutex rather than replacing the accumulator,
// so it neither races a running poller nor discards accumulated totals. Sizing by
// replacement would be a data race that -race never reaches, because it would live
// in untested main.go wiring.
func ConfigureFlow(topN, maxKeys int) { Flow.setBounds(topN, maxKeys) }

var _ flow.Sink = (*FlowStore)(nil)

type flowCollector struct {
	log       *slog.Logger
	subsystem string
	instance  string
	store     *FlowStore

	bytes    *prometheus.Desc
	packets  *prometheus.Desc
	records  *prometheus.Desc
	fallback *prometheus.Desc

	rollupKeys    *prometheus.Desc
	rollupKeysMax *prometheus.Desc
	rollupTopN    *prometheus.Desc
	rollupFolded  *prometheus.Desc
	rollupCapped  *prometheus.Desc
}

func init() {
	collectorInstances = append(collectorInstances, &flowCollector{
		subsystem: FlowSubsystem,
		store:     Flow,
	})
}

func (c *flowCollector) Name() string { return c.subsystem }

func (c *flowCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	// Spelled as a LITERAL, not as flow.RollupLabelNames(): scripts/docgen resolves
	// this argument statically (main.go resolveLabelSlice folds a composite literal,
	// a local var assigned one, or an append chain — but not a function call), so a
	// call here documents zero labels and scripts/docgen/verify.go then fails the
	// docs build. A test asserts this literal still matches RollupLabelNames(), so
	// the two spellings cannot drift.
	//
	// Reused across the three volume metrics safely: a composite literal has
	// cap == len, so buildPrometheusDesc's append of the instance label allocates a
	// new array each time instead of writing into this one.
	labels := []string{"interface", "direction", "transport", "category", "action", "source", "scope"}

	c.bytes = buildPrometheusDesc(c.subsystem, "bytes_total",
		"Bytes observed in flow records, by bounded dimension. Keys beyond --flow.top-n fold into "+
			"__other__, which preserves the source label, so the family still sums exactly at any "+
			"limit. A series that leaves the top-N and later returns resumes from the volume it "+
			"accumulated while folded, so it reads as a counter reset — deliberate, since the "+
			"alternative is freezing it at its last value forever. From phase 2 this family carries "+
			"BOTH sources' measurement of the same traffic: pin source= in any query or it "+
			"double-counts. IPs, ports, hostnames, application names, domains and connection ids are "+
			"never labels; they stay as structured metadata on the shipped record.",
		labels,
	)
	c.packets = buildPrometheusDesc(c.subsystem, "packets_total",
		"Packets observed in flow records, by bounded dimension. Same folding, reset and "+
			"cross-source semantics as opnsense_flow_bytes_total.",
		labels,
	)
	c.records = buildPrometheusDesc(c.subsystem, "records_total",
		"Flow records observed, by bounded dimension. Counts records, not connections: a Zenarmor "+
			"conn document is one per connection, but a NetFlow connection produces several records.",
		labels,
	)
	c.fallback = buildPrometheusDesc(c.subsystem, "payload_byte_fallback_total",
		"Flow records whose byte count came from Zenarmor's payload counter because its wire "+
			"counter read zero. Zenarmor only accumulates wire bytes once it has tracked a flow past "+
			"its first packets, so short UDP flows (DNS, STUN, SSDP) report zero; without the "+
			"fallback those records would count toward records_total with no bytes at all.",
		nil,
	)

	c.rollupKeys = buildPrometheusDesc(c.subsystem, "rollup_keys",
		"Distinct label combinations currently tracked by the flow rollup accumulator.", nil)
	c.rollupKeysMax = buildPrometheusDesc(c.subsystem, "rollup_keys_max",
		"Configured ceiling on tracked label combinations (--flow.max-keys); 0 means unbounded. "+
			"At the ceiling every NEW combination folds into __other__ indefinitely, so compare "+
			"against opnsense_flow_rollup_keys to see saturation coming.", nil)
	c.rollupTopN = buildPrometheusDesc(c.subsystem, "rollup_top_n",
		"Configured ceiling on emitted series (--flow.top-n); 0 means unbounded.", nil)
	c.rollupFolded = buildPrometheusDesc(c.subsystem, "rollup_keys_folded",
		"Tracked label combinations currently outside the top-N and therefore folded into "+
			"__other__ rather than emitted individually.", nil)
	c.rollupCapped = buildPrometheusDesc(c.subsystem, "rollup_capped_total",
		"Flow records folded into __other__ because the accumulator was already at "+
			"--flow.max-keys when their label combination first appeared. A rising value means new "+
			"dimensions are being lost to the cap, not merely folded by the top-N.", nil)
}

func (c *flowCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.bytes
	ch <- c.packets
	ch <- c.records
	ch <- c.fallback
	ch <- c.rollupKeys
	ch <- c.rollupKeysMax
	ch <- c.rollupTopN
	ch <- c.rollupFolded
	ch <- c.rollupCapped
}

// Update emits the accumulator's current totals. It ignores the client: this
// collector never calls the API — the receiver lanes feed the store, exactly like
// log_events (logevents.go:193).
func (c *flowCollector) Update(_ context.Context, _ *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	for _, e := range c.store.rollup.Snapshot() {
		vals := append(e.Key.Values(), c.instance)
		ch <- prometheus.MustNewConstMetric(c.bytes, prometheus.CounterValue, float64(e.Bytes), vals...)
		ch <- prometheus.MustNewConstMetric(c.packets, prometheus.CounterValue, float64(e.Packets), vals...)
		ch <- prometheus.MustNewConstMetric(c.records, prometheus.CounterValue, float64(e.Flows), vals...)
	}

	// The self-metrics below are published unconditionally, from zero. A saturation
	// gauge that only appears once it fires is invisible at exactly the moment an
	// operator needs to know whether it has ever fired.
	ch <- prometheus.MustNewConstMetric(c.fallback, prometheus.CounterValue,
		float64(c.store.payloadByteFallback.Load()), c.instance)

	st := c.store.rollup.Stats()
	ch <- prometheus.MustNewConstMetric(c.rollupKeys, prometheus.GaugeValue, float64(st.Keys), c.instance)
	ch <- prometheus.MustNewConstMetric(c.rollupKeysMax, prometheus.GaugeValue, float64(st.MaxKeys), c.instance)
	ch <- prometheus.MustNewConstMetric(c.rollupTopN, prometheus.GaugeValue, float64(st.TopN), c.instance)
	ch <- prometheus.MustNewConstMetric(c.rollupFolded, prometheus.GaugeValue, float64(st.FoldedKeys), c.instance)
	ch <- prometheus.MustNewConstMetric(c.rollupCapped, prometheus.CounterValue, float64(st.Capped), c.instance)
	return nil
}
