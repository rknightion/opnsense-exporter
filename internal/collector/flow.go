package collector

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/internal/flow"
	"github.com/rknightion/opnsense-exporter/internal/flow/netflow"
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
	// uniqueDests and topTalkers are §9's per-interface distinct-destination gauge and
	// opt-in per-host byte ranking (#353). Both are fed from every observed record, so
	// they live beside the rollup; topTalkers is inert until Configure turns it on.
	uniqueDests *flow.DistinctDests
	topTalkers  *flow.TopTalkers
	// delta is §9's NF-vs-Zen byte-ratio histogram (#353). It is fed only from merged
	// records at correlator-emit time (via ObserveDelta), never from the raw arrival
	// path, so it stays empty — and the metric absent — unless both lanes correlate.
	delta *flow.DeltaRatio
	// payloadByteFallback counts records whose byte figure came from Zenarmor's
	// payload counter because its wire counter read zero. A repair nobody can
	// observe is a repair nobody will trust.
	payloadByteFallback atomic.Uint64

	// dnsCache is the source of the DNS answer-cache self-metrics (#353). nil until
	// main builds the cache, which it does whenever flow is enabled; published from
	// zero once wired, since an empty cache is a normal state worth seeing.
	dnsCache atomic.Pointer[func() flow.DNSCacheStats]

	// netflow is nil until the NetFlow receiver is built, which is why the metrics
	// it feeds are absent rather than zero on a deployment that never enables it.
	netflow atomic.Pointer[func() NetflowStats]

	// correlator and flowLog are nil until the flow-log lane is built (only when
	// --flow.log-mode=per_flow). Absent-until-built, like netflow above: a deployment
	// that ships no flow logs has no correlator, so absent is the honest reading rather
	// than a flat zero that implies one exists and has done nothing.
	correlator atomic.Pointer[func() flow.CorrelatorStats]
	flowLog    atomic.Pointer[func() FlowLogStats]
}

// FlowLogStats is the flow-log emission lane's health, mirrored here so the collector
// need not import the flowlog package. main wires the accessor.
type FlowLogStats struct {
	Emitted   uint64
	Truncated uint64 // dropped by the per-window budget
	Dropped   uint64 // no active pipeline (pre-start / post-shutdown)
}

// SetCorrelatorStats installs the source of the correlator self-metrics; main calls it
// once when it builds the flow-log lane.
func (s *FlowStore) SetCorrelatorStats(fn func() flow.CorrelatorStats) { s.correlator.Store(&fn) }

// SetFlowLogStats installs the source of the flow-log self-metrics.
func (s *FlowStore) SetFlowLogStats(fn func() FlowLogStats) { s.flowLog.Store(&fn) }

func (s *FlowStore) correlatorStats() (flow.CorrelatorStats, bool) {
	fn := s.correlator.Load()
	if fn == nil || *fn == nil {
		return flow.CorrelatorStats{}, false
	}
	return (*fn)(), true
}

func (s *FlowStore) flowLogStats() (FlowLogStats, bool) {
	fn := s.flowLog.Load()
	if fn == nil || *fn == nil {
		return FlowLogStats{}, false
	}
	return (*fn)(), true
}

// SetDNSCacheStats installs the source of the DNS answer-cache self-metrics; main
// calls it once when it builds the cache (whenever flow is enabled).
func (s *FlowStore) SetDNSCacheStats(fn func() flow.DNSCacheStats) { s.dnsCache.Store(&fn) }

func (s *FlowStore) dnsCacheStats() (flow.DNSCacheStats, bool) {
	fn := s.dnsCache.Load()
	if fn == nil || *fn == nil {
		return flow.DNSCacheStats{}, false
	}
	return (*fn)(), true
}

func newFlowStore(topN, maxKeys int) *FlowStore {
	return &FlowStore{
		rollup:      flow.NewRollup(topN, maxKeys),
		uniqueDests: flow.NewDistinctDests(),
		topTalkers:  flow.NewTopTalkers(),
		delta:       flow.NewDeltaRatio(),
	}
}

// NetflowStats is everything the NetFlow lane knows about what it received and what
// it chose not to trust, gathered from the four components that own the counters.
type NetflowStats struct {
	Listener netflow.ListenerStats
	Decoder  netflow.Stats
	Pipeline flow.ProcessorStats
	Repair   flow.RepairStats
	IfMap    flow.IfMapStats
	IfMapAge time.Duration
}

// SetNetflowStats installs the source of the NetFlow self-metrics. main calls it
// once, when it builds the receiver.
//
// Until it is called the NetFlow metrics are not emitted AT ALL, rather than emitted
// as zeros. That is the opposite of the rule the rollup saturation metrics follow,
// and deliberately so: a zero there means "this has never fired", which is worth
// knowing, whereas a zero here would mean "a receiver exists and has seen nothing",
// which is false on the many deployments that never turn the listener on.
func (s *FlowStore) SetNetflowStats(fn func() NetflowStats) { s.netflow.Store(&fn) }

func (s *FlowStore) netflowStats() (NetflowStats, bool) {
	fn := s.netflow.Load()
	if fn == nil || *fn == nil {
		return NetflowStats{}, false
	}
	return (*fn)(), true
}

// Observe folds one flow record into the counters. It implements flow.Sink and is
// called from receiver goroutines, so it must not block: the rollup takes a short
// mutex and does no I/O.
func (s *FlowStore) Observe(r flow.Record) {
	if r.Repairs.PayloadByteFallback {
		s.payloadByteFallback.Add(1)
	}
	s.rollup.Observe(r)
	s.uniqueDests.Observe(r)
	s.topTalkers.Observe(r)
}

// ObserveDelta folds one merged record's source disagreement into the byte-ratio
// histogram. main calls it from the correlator's emit path, NOT from Observe: the
// ratio needs both sources' counters on one record, which only the correlator
// produces. DeltaRatio.Observe ignores anything that is not a genuine merge.
func (s *FlowStore) ObserveDelta(r flow.Record) { s.delta.Observe(r) }

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

// ConfigureTopTalkers enables the opt-in per-host byte ranking and pins the single
// source it counts (§9, #353). primary is the flow source that is actually active,
// so a box running both lanes never adds a host's bytes twice — the metric carries
// no source label to separate them.
func ConfigureTopTalkers(enabled bool, primary flow.Source) {
	Flow.topTalkers.Configure(enabled, primary)
}

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

	nfDatagrams  *prometheus.Desc
	nfBytes      *prometheus.Desc
	nfDecoded    *prometheus.Desc
	nfEmitted    *prometheus.Desc
	nfDropped    *prometheus.Desc
	nfTemplates  *prometheus.Desc
	nfUnexpected *prometheus.Desc

	egressCorrected *prometheus.Desc
	dedupeEntries   *prometheus.Desc
	dedupeDropped   *prometheus.Desc

	ifIndexEntries   *prometheus.Desc
	ifIndexConflicts *prometheus.Desc
	ifIndexAge       *prometheus.Desc
	ifIndexUnmapped  *prometheus.Desc

	corrEntries *prometheus.Desc
	corrEmitted *prometheus.Desc
	corrMatched *prometheus.Desc
	corrEvicted *prometheus.Desc
	corrExpired *prometheus.Desc

	logEmitted   *prometheus.Desc
	logTruncated *prometheus.Desc
	logDropped   *prometheus.Desc

	uniqueDests *prometheus.Desc
	topTalker   *prometheus.Desc
	deltaRatio  *prometheus.Desc

	dnsCacheEntries  *prometheus.Desc
	dnsCacheHits     *prometheus.Desc
	dnsCacheMisses   *prometheus.Desc
	dnsCacheRejected *prometheus.Desc
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
	c.registerNetflow()

	c.rollupCapped = buildPrometheusDesc(c.subsystem, "rollup_capped_total",
		"Flow records folded into __other__ because the accumulator was already at "+
			"--flow.max-keys when their label combination first appeared. A rising value means new "+
			"dimensions are being lost to the cap, not merely folded by the top-N.", nil)
	c.registerCorrelator()
	c.registerExtras()
}

// registerExtras builds the §9 volume/talker metrics and the DNS answer-cache
// self-metrics (#353).
func (c *flowCollector) registerExtras() {
	// Literals, for the same docgen static-resolution reason as the volume labels.
	ifaceLabel := []string{"interface"}
	hostDirLabel := []string{"host", "direction"}

	c.uniqueDests = buildPrometheusDesc(c.subsystem, "unique_destinations",
		"Distinct destination addresses seen per interface — a bounded stand-in for a per-destination "+
			"series (one gauge per interface, never one per destination). A set, not a sum, so a "+
			"destination reported by both the NetFlow and Zenarmor lanes counts once. Saturates at an "+
			"internal per-interface cap; a value pinned at the cap means the true count is at least "+
			"that high, which is itself a scanning/fan-out signal.",
		ifaceLabel,
	)
	c.topTalker = buildPrometheusDesc(c.subsystem, "top_talker_bytes_total",
		"Bytes per internal host and direction, top-N with an __other__ remainder per direction so a "+
			"sum-by-direction stays exact. OPT-IN behind --flow.top-talkers because the host label is "+
			"unbounded cardinality the other flow metrics refuse. Counts a single source, so on a box "+
			"running both lanes a host's bytes are not doubled; it therefore has no source label. A "+
			"host that leaves and re-enters the top-N reads as a counter reset on that one series.",
		hostDirLabel,
	)
	c.deltaRatio = buildPrometheusDesc(c.subsystem, "source_byte_delta_ratio",
		"Histogram of NetFlow-over-Zenarmor byte ratios on merged flow records, by interface — the "+
			"payoff of correlating the two sources (#346 decision 3). 1.0 is agreement; a value well "+
			"above 1 means Zenarmor inspected far fewer bytes than crossed the wire, which is a security "+
			"signal, not an error. Present only where both lanes run and correlate (--flow.log-mode="+
			"per_flow); absent otherwise, since there is no disagreement to measure.",
		ifaceLabel,
	)

	c.dnsCacheEntries = buildPrometheusDesc(c.subsystem, "dns_cache_entries",
		"Answers currently held in the DNS answer cache, which gives a flow to a bare IP its "+
			"dst.domain (§7). Compare against --flow.dns-cache.size to see it approaching the insert cap.",
		nil)
	c.dnsCacheHits = buildPrometheusDesc(c.subsystem, "dns_cache_hits_total",
		"DNS answer-cache lookups that resolved a domain for a flow's destination.", nil)
	c.dnsCacheMisses = buildPrometheusDesc(c.subsystem, "dns_cache_misses_total",
		"DNS answer-cache lookups with no cached (or a TTL-expired) answer. High against hits is normal "+
			"for a mostly-IP workload; it is the denominator that tells a cold cache from a thrashing one.",
		nil)
	c.dnsCacheRejected = buildPrometheusDesc(c.subsystem, "dns_cache_rejected_total",
		"DNS answers refused insertion because the cache was already at --flow.dns-cache.size. Over the "+
			"cap it stops inserting rather than evicting hot entries, so a rising value means the cap is "+
			"binding and domain enrichment is going stale for new answers.", nil)
}

// registerCorrelator builds the self-metrics for the correlator and the flow-log
// emission lane. Both are absent unless --flow.log-mode=per_flow built the lane, for
// the same reason the NetFlow metrics are (see SetNetflowStats).
func (c *flowCollector) registerCorrelator() {
	c.corrEntries = buildPrometheusDesc(c.subsystem, "correlator_entries",
		"Connection-windows the correlator is currently holding, waiting for their window to elapse "+
			"or a Zenarmor conn document to arrive.", nil)
	c.corrEmitted = buildPrometheusDesc(c.subsystem, "correlator_emitted_total",
		"Flow-log records the correlator has emitted: NetFlow fragments collapsed into one record per "+
			"connection-window, merged with Zenarmor L7 where a conn document matched.", nil)
	c.corrMatched = buildPrometheusDesc(c.subsystem, "correlator_matched_total",
		"Subset of emitted records that carried Zenarmor enrichment (source=merged). Against "+
			"correlator_emitted_total this is the join hit-rate, which #346 shows is materially lower "+
			"for long flows whose NetFlow records arrive up to ~30m after the connection ended.", nil)
	c.corrEvicted = buildPrometheusDesc(c.subsystem, "correlator_evicted_total",
		"Entries force-emitted early because the map hit --flow.correlate.max-entries. A forced emit "+
			"loses no bytes, but a rising rate means the cap is binding under load and should be raised.",
		nil)
	c.corrExpired = buildPrometheusDesc(c.subsystem, "correlator_expired_total",
		"Entries emitted on the normal window-expiry path (the healthy path, as opposed to eviction).",
		nil)

	c.logEmitted = buildPrometheusDesc(c.subsystem, "logs_emitted_total",
		"Flow records shipped to the OTLP log pipeline. Zero when --flow.log-mode=off even though the "+
			"correlator still runs and its metrics still move.", nil)
	c.logTruncated = buildPrometheusDesc(c.subsystem, "logs_truncated_total",
		"Flow log records dropped by the --flow.max-logs-per-window budget. Truncated, never sampled, "+
			"and counted: a flood on the unauthenticated NetFlow ingress is visible here rather than as "+
			"a silently thinned stream. Metrics are never truncated.", nil)
	c.logDropped = buildPrometheusDesc(c.subsystem, "logs_dropped_total",
		"Flow log records dropped because the log pipeline was not accepting records — before it "+
			"started or after shutdown began. Distinct from a budget truncation.", nil)
}

// registerNetflow builds the NetFlow lane's self-metrics.
//
// Every one of these is a "what did we refuse to trust" counter. A receiver that
// drops input silently is indistinguishable from a network with nothing on it, and
// on an unauthenticated UDP ingress that difference is the whole security story.
func (c *flowCollector) registerNetflow() {
	// Literals, for the same docgen reason as the volume labels above.
	resultLabel := []string{"result"}
	reasonLabel := []string{"reason"}

	c.nfDatagrams = buildPrometheusDesc(c.subsystem, "netflow_datagrams_total",
		"NetFlow datagrams by outcome. result=\"accepted\" passed the peer allowlist; "+
			"\"peer_rejected\" came from outside --flow.netflow.allowed-peers; \"queue_dropped\" arrived "+
			"faster than the decoders drained them (the read loop never blocks, because blocking makes "+
			"the KERNEL drop datagrams where nothing can count them); \"read_error\" is a socket error. "+
			"Decode outcomes are counted separately below and are a subset of \"accepted\".",
		resultLabel,
	)
	c.nfBytes = buildPrometheusDesc(c.subsystem, "netflow_bytes_received_total",
		"Bytes received on the NetFlow socket, before decoding. This is wire volume of the export "+
			"itself, NOT the traffic it describes — opnsense_flow_bytes_total is that.",
		nil,
	)
	c.nfDecoded = buildPrometheusDesc(c.subsystem, "netflow_records_decoded_total",
		"Flow records successfully decoded out of NetFlow datagrams. The head of the funnel: "+
			"decoded = emitted + dropped, with records lost before decoding counted as "+
			"opnsense_flow_netflow_records_dropped_total{reason=\"no_template\"}.",
		nil,
	)
	c.nfEmitted = buildPrometheusDesc(c.subsystem, "netflow_records_emitted_total",
		"Decoded records that survived repair and reached the rollup. The tail of the funnel: "+
			"compare against decoded_total to see what the repair stage removed.",
		nil,
	)
	c.nfDropped = buildPrometheusDesc(c.subsystem, "netflow_records_dropped_total",
		"Records the NetFlow lane discarded, by reason. \"no_template\" is a data flowset arriving "+
			"before the template describing it — normal for up to ~2 minutes after either end restarts, "+
			"since ng_netflow resends templates about every 2 minutes, and a sustained rate means "+
			"template datagrams are being lost. \"vlan_duplicate\" is the parent-interface copy of a "+
			"VLAN flow, which ng_netflow captures twice (~4% of bytes on the reference box) and which "+
			"would otherwise be counted twice AND attributed to the parent. \"no_address\" is a record "+
			"with unusable endpoints.",
		reasonLabel,
	)
	c.nfTemplates = buildPrometheusDesc(c.subsystem, "netflow_templates_total",
		"NetFlow v9 template events. \"learned\" is a template id seen for the first time; "+
			"\"replaced\" is a known id re-sent with a DIFFERENT field shape, which invalidates the "+
			"decoder's understanding of every record behind it. A steady replaced rate means the "+
			"exporter is flapping between configurations.",
		resultLabel,
	)
	c.nfUnexpected = buildPrometheusDesc(c.subsystem, "netflow_unexpected_field_total",
		"Records carrying a field the decoder asserts is always empty on this export. Today only "+
			"field=\"out_bytes\": OUT_BYTES/OUT_PKTS are declared in the template but were zero across "+
			"all 84,513 records of the reference capture, so they are ignored rather than added to the "+
			"volume. A non-zero rate here means that assumption has expired and the decoder needs "+
			"revisiting — it does NOT mean volume is currently wrong.",
		[]string{"field"},
	)

	c.egressCorrected = buildPrometheusDesc(c.subsystem, "egress_corrected_total",
		"Flow records whose egress interface was corrected from the WAN the FIB lookup named to the "+
			"WAN the traffic actually left by. ng_netflow derives OUTPUT_SNMP from a route lookup, but "+
			"OPNsense multi-WAN policy routing happens in pf, which ng_netflow never sees: on the "+
			"reference capture this mislabelled 3.36 GB of WAN2 traffic as WAN1, a 99% under-report of "+
			"WAN2. A zero rate on a single-WAN box is expected; a zero rate on a policy-routed "+
			"multi-WAN box means the correction is not firing and per-WAN volume is wrong.",
		nil,
	)
	c.dedupeEntries = buildPrometheusDesc(c.subsystem, "dedupe_entries",
		"Flow instances currently held in the VLAN de-duplication table.",
		nil,
	)
	c.dedupeDropped = buildPrometheusDesc(c.subsystem, "dedupe_entries_dropped_total",
		"Entries removed from the de-duplication table. reason=\"ttl\" is the healthy path — the "+
			"instance aged out having done its job. reason=\"capacity\" means the table was full and an "+
			"entry was evicted early, so a duplicate arriving afterwards is NO LONGER SUPPRESSED and "+
			"reaches the rollup twice; a non-zero rate is the signal to raise the bound.",
		reasonLabel,
	)

	c.ifIndexEntries = buildPrometheusDesc(c.subsystem, "ifindex_entries",
		"Entries in the NetFlow ifIndex-to-interface map, including the synthetic index 0 "+
			"(traffic originated by the firewall itself).",
		nil,
	)
	c.ifIndexConflicts = buildPrometheusDesc(c.subsystem, "ifindex_conflicts",
		"Operator overrides from --flow.netflow.ifindex-map that DISAGREE with the map derived from "+
			"the API. Non-zero is the alarm that the derived enumeration does not reproduce the box's "+
			"own ifinfo ordering — the override is winning, so labels are right, but every index the "+
			"operator did not pin is suspect.",
		nil,
	)
	c.ifIndexAge = buildPrometheusDesc(c.subsystem, "ifindex_map_age_seconds",
		"Age of the ifIndex map. ng_netflow's indices are positional over ifinfo output, so adding or "+
			"removing ANY interface renumbers everything and silently remaps historical series. A map "+
			"that stops being refreshed is therefore a correctness problem, not a staleness nuisance.",
		nil,
	)
	c.ifIndexUnmapped = buildPrometheusDesc(c.subsystem, "ifindex_unmapped_total",
		"ifIndex lookups that resolved to no interface. These records are still counted, with an "+
			"EMPTY interface label — a wrong interface name is worse than a missing one. A rising rate "+
			"after a network change means the enumeration shifted and --flow.netflow.ifindex-map needs "+
			"setting.",
		nil,
	)
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
	ch <- c.nfDatagrams
	ch <- c.nfBytes
	ch <- c.nfDecoded
	ch <- c.nfEmitted
	ch <- c.nfDropped
	ch <- c.nfTemplates
	ch <- c.nfUnexpected
	ch <- c.egressCorrected
	ch <- c.dedupeEntries
	ch <- c.dedupeDropped
	ch <- c.ifIndexEntries
	ch <- c.ifIndexConflicts
	ch <- c.ifIndexAge
	ch <- c.ifIndexUnmapped
	ch <- c.corrEntries
	ch <- c.corrEmitted
	ch <- c.corrMatched
	ch <- c.corrEvicted
	ch <- c.corrExpired
	ch <- c.logEmitted
	ch <- c.logTruncated
	ch <- c.logDropped
	ch <- c.uniqueDests
	ch <- c.topTalker
	ch <- c.deltaRatio
	ch <- c.dnsCacheEntries
	ch <- c.dnsCacheHits
	ch <- c.dnsCacheMisses
	ch <- c.dnsCacheRejected
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

	c.collectNetflow(ch)
	c.collectCorrelator(ch)
	c.collectExtras(ch)
	return nil
}

// collectExtras emits the §9 volume/talker metrics and the DNS answer-cache
// self-metrics (#353). Each is driven by its accumulator's snapshot, so a metric with
// no data (top-talkers disabled, no merged records, an interface never seen) emits no
// series rather than a misleading zero. The DNS cache stats are the exception: once
// wired they publish from zero, because an empty cache is a state worth seeing.
func (c *flowCollector) collectExtras(ch chan<- prometheus.Metric) {
	for iface, n := range c.store.uniqueDests.Snapshot() {
		ch <- prometheus.MustNewConstMetric(c.uniqueDests, prometheus.GaugeValue, float64(n), iface, c.instance)
	}
	for _, e := range c.store.topTalkers.Snapshot() {
		ch <- prometheus.MustNewConstMetric(c.topTalker, prometheus.CounterValue, float64(e.Bytes),
			e.Host, e.Direction, c.instance)
	}
	for iface, h := range c.store.delta.Snapshot() {
		ch <- prometheus.MustNewConstHistogram(c.deltaRatio, h.Count, h.Sum, h.Buckets, iface, c.instance)
	}

	if st, ok := c.store.dnsCacheStats(); ok {
		ch <- prometheus.MustNewConstMetric(c.dnsCacheEntries, prometheus.GaugeValue, float64(st.Entries), c.instance)
		ch <- prometheus.MustNewConstMetric(c.dnsCacheHits, prometheus.CounterValue, float64(st.Hits), c.instance)
		ch <- prometheus.MustNewConstMetric(c.dnsCacheMisses, prometheus.CounterValue, float64(st.Misses), c.instance)
		ch <- prometheus.MustNewConstMetric(c.dnsCacheRejected, prometheus.CounterValue, float64(st.Rejected), c.instance)
	}
}

// collectCorrelator emits the correlator and flow-log self-metrics, and emits nothing
// when the flow-log lane was never built (--flow.log-mode=off), for the same reason
// collectNetflow does: a zero here would claim a lane exists and has been idle.
func (c *flowCollector) collectCorrelator(ch chan<- prometheus.Metric) {
	if st, ok := c.store.correlatorStats(); ok {
		ch <- prometheus.MustNewConstMetric(c.corrEntries, prometheus.GaugeValue, float64(st.Entries), c.instance)
		ch <- prometheus.MustNewConstMetric(c.corrEmitted, prometheus.CounterValue, float64(st.Emitted), c.instance)
		ch <- prometheus.MustNewConstMetric(c.corrMatched, prometheus.CounterValue, float64(st.Matched), c.instance)
		ch <- prometheus.MustNewConstMetric(c.corrEvicted, prometheus.CounterValue, float64(st.Evicted), c.instance)
		ch <- prometheus.MustNewConstMetric(c.corrExpired, prometheus.CounterValue, float64(st.Expired), c.instance)
	}
	if st, ok := c.store.flowLogStats(); ok {
		ch <- prometheus.MustNewConstMetric(c.logEmitted, prometheus.CounterValue, float64(st.Emitted), c.instance)
		ch <- prometheus.MustNewConstMetric(c.logTruncated, prometheus.CounterValue, float64(st.Truncated), c.instance)
		ch <- prometheus.MustNewConstMetric(c.logDropped, prometheus.CounterValue, float64(st.Dropped), c.instance)
	}
}

// collectNetflow emits the NetFlow lane's self-metrics, and emits nothing at all
// when the lane was never built — see SetNetflowStats for why absent beats zero here.
func (c *flowCollector) collectNetflow(ch chan<- prometheus.Metric) {
	nf, ok := c.store.netflowStats()
	if !ok {
		return
	}
	counter := func(d *prometheus.Desc, v uint64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, float64(v),
			append(labels, c.instance)...)
	}
	gauge := func(d *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, append(labels, c.instance)...)
	}

	// "accepted" deliberately excludes the decode outcomes rather than double
	// counting them: a malformed datagram was accepted by the listener AND rejected
	// by the decoder, and summing the two would exceed what the socket received.
	counter(c.nfDatagrams, nf.Listener.Datagrams, "accepted")
	counter(c.nfDatagrams, nf.Listener.PeerRejected, "peer_rejected")
	counter(c.nfDatagrams, nf.Listener.QueueDropped, "queue_dropped")
	counter(c.nfDatagrams, nf.Listener.ReadErrors, "read_error")
	counter(c.nfDatagrams, nf.Decoder.Malformed, "malformed")
	counter(c.nfDatagrams, nf.Decoder.UnsupportedVersion, "unsupported_version")
	counter(c.nfDatagrams, nf.Decoder.VarLenRejected, "varlen_rejected")
	counter(c.nfBytes, nf.Listener.Bytes)

	counter(c.nfDecoded, nf.Decoder.Records)
	counter(c.nfEmitted, nf.Pipeline.RecordsEmitted)
	counter(c.nfDropped, nf.Decoder.NoTemplate, "no_template")
	counter(c.nfDropped, nf.Pipeline.RecordsDropped, "vlan_duplicate")
	counter(c.nfDropped, nf.Pipeline.RecordsNoAddr, "no_address")

	counter(c.nfTemplates, nf.Decoder.TemplatesLearned, "learned")
	counter(c.nfTemplates, nf.Decoder.TemplatesReplaced, "replaced")
	counter(c.nfUnexpected, nf.Decoder.UnexpectedOutBytes, "out_bytes")

	counter(c.egressCorrected, nf.Repair.EgressCorrected)
	gauge(c.dedupeEntries, float64(nf.Repair.DedupeEntries))
	counter(c.dedupeDropped, nf.Repair.DedupeEvicted, "ttl")
	counter(c.dedupeDropped, nf.Repair.DedupeCapped, "capacity")

	gauge(c.ifIndexEntries, float64(nf.IfMap.Entries))
	gauge(c.ifIndexConflicts, float64(nf.IfMap.Conflicts))
	gauge(c.ifIndexAge, nf.IfMapAge.Seconds())
	counter(c.ifIndexUnmapped, nf.IfMap.UnmappedLookups)
}
