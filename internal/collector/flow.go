package collector

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/internal/flow"
	"github.com/rknightion/opnsense2otel/v4/internal/flow/netflow"
	"github.com/rknightion/opnsense2otel/v4/internal/geoip"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
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
	// lastSeen is when a NetFlow record was last attributed to each interface. It
	// backs the "configured to capture, exporting nothing" signal (#366), which the
	// netflow collector crosses with the box's own capture config.
	lastSeen   *flow.LastSeen
	topTalkers *flow.TopTalkers
	// delta is §9's NF-vs-Zen byte-ratio histogram (#353). It is fed only from merged
	// records at correlator-emit time (via ObserveDelta), never from the raw arrival
	// path, so it stays empty — and the metric absent — unless both lanes correlate.
	delta *flow.DeltaRatio
	// payloadByteFallback counts records whose byte figure came from Zenarmor's
	// payload counter because its wire counter read zero. A repair nobody can
	// observe is a repair nobody will trust.
	payloadByteFallback atomic.Uint64
	// interfaceUnresolved counts records emitted with the unresolved-interface
	// sentinel because the enrichment snapshot had not arrived yet (#606).
	interfaceUnresolved atomic.Uint64

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

	// geoip is nil until main builds the GeoIP databases, which it does only when
	// --geoip.enabled is set. Absent-until-built for the same reason as netflow: a
	// zero would claim a database exists and has answered nothing, which is false on
	// every deployment that never turned geo on.
	geoip atomic.Pointer[func() GeoIPStats]
}

// GeoIPStats is the GeoIP databases' and the flow enricher's health together, so the
// collector need not import internal/geoip. main wires the accessor.
type GeoIPStats struct {
	DB   geoip.Stats
	Flow flow.GeoStats
}

// SetGeoIPStats installs the source of the GeoIP self-metrics; main calls it once,
// when it opens the databases.
func (s *FlowStore) SetGeoIPStats(fn func() GeoIPStats) { s.geoip.Store(&fn) }

func (s *FlowStore) geoipStats() (GeoIPStats, bool) {
	fn := s.geoip.Load()
	if fn == nil || *fn == nil {
		return GeoIPStats{}, false
	}
	return (*fn)(), true
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
		lastSeen:    flow.NewLastSeen(),
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
	// IfMapEntries is the resolved map itself, rendered as one entry per ifIndex.
	// It backs the device-to-description info metric (#368) and is the only
	// NetflowStats field that is a list rather than a counter, because it is the
	// only one whose VALUE is a set of label combinations.
	IfMapEntries []flow.IfaceEntry
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
	if r.In.Unresolved || r.Out.Unresolved {
		s.interfaceUnresolved.Add(1)
	}
	s.rollup.Observe(r)
	s.uniqueDests.Observe(r)
	s.topTalkers.Observe(r)
	s.lastSeen.Observe(r, time.Now())
}

// netflowLastSeen reports when a NetFlow record was last attributed to each
// interface. Interfaces that have never produced one are absent, not zero.
func (s *FlowStore) netflowLastSeen() map[string]time.Time { return s.lastSeen.Snapshot() }

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

	bytes               *prometheus.Desc
	packets             *prometheus.Desc
	records             *prometheus.Desc
	fallback            *prometheus.Desc
	interfaceUnresolved *prometheus.Desc

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
	nfUnmapped   *prometheus.Desc
	nfTemplates  *prometheus.Desc
	nfUnexpected *prometheus.Desc

	nfUnidentified *prometheus.Desc

	egressCorrected    *prometheus.Desc
	policyRouteCorr    *prometheus.Desc
	policyRouteRefused *prometheus.Desc
	pfStateEntries     *prometheus.Desc
	pfStateAge         *prometheus.Desc
	dedupeEntries      *prometheus.Desc
	dedupeDropped      *prometheus.Desc
	vlanChildPreferred *prometheus.Desc
	vlanSubnetAttrib   *prometheus.Desc
	vlanLateChildCopy  *prometheus.Desc
	repairHeld         *prometheus.Desc

	interfaceInfo    *prometheus.Desc
	captureUnsupp    *prometheus.Desc
	ifIndexEntries   *prometheus.Desc
	ifIndexConflicts *prometheus.Desc
	ifIndexAge       *prometheus.Desc
	ifIndexUnmapped  *prometheus.Desc
	ifIndexGuard     *prometheus.Desc

	corrEntries          *prometheus.Desc
	corrEmitted          *prometheus.Desc
	corrMatched          *prometheus.Desc
	corrEvicted          *prometheus.Desc
	corrExpired          *prometheus.Desc
	corrEnrichOverwrites *prometheus.Desc
	corrFragDisagree     *prometheus.Desc
	corrFragMirrored     *prometheus.Desc

	logEmitted   *prometheus.Desc
	logTruncated *prometheus.Desc
	logDropped   *prometheus.Desc

	uniqueDests       *prometheus.Desc
	uniqueDestsCapped *prometheus.Desc
	topTalker         *prometheus.Desc
	deltaRatio        *prometheus.Desc
	deltaExcluded     *prometheus.Desc

	dnsCacheEntries  *prometheus.Desc
	dnsCacheHits     *prometheus.Desc
	dnsCacheMisses   *prometheus.Desc
	dnsCacheRejected *prometheus.Desc

	geoLookups      *prometheus.Desc
	geoReloads      *prometheus.Desc
	geoDownloads    *prometheus.Desc
	geoBuildTime    *prometheus.Desc
	geoEnriched     *prometheus.Desc
	geoCountryAgree *prometheus.Desc
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
	labels := []string{"interface", "direction", "transport", "category", "action", "source", "scope", "country"}

	c.bytes = buildPrometheusDesc(c.subsystem, "bytes_total",
		"Bytes observed in flow records, by bounded dimension. Keys beyond --flow.top-n fold into "+
			"__other__, which preserves the source label, so the family still sums exactly at any "+
			"limit. A series that leaves the top-N and later returns resumes from the volume it "+
			"accumulated while folded, so it reads as a counter reset - deliberate, since the "+
			"alternative is freezing it at its last value forever. From phase 2 this family carries "+
			"BOTH sources' measurement of the same traffic: pin source= in any query or it "+
			"double-counts. IPs, ports, hostnames, application names, domains and connection ids are "+
			"never labels; they stay as structured metadata on the shipped record. The country label "+
			"is populated by default (#537) and names the REMOTE end of the flow whichever end that "+
			"is; it reads empty where GeoIP cannot answer, and on a deployment without "+
			"--geoip.enabled it is empty on every series. Set --flow.geoip.metric-dims=false to drop "+
			"it entirely.",
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

	c.interfaceUnresolved = buildPrometheusDesc(c.subsystem, "interface_unresolved_total",
		"Flow records emitted with interface=\"unresolved\" because the interface table had not "+
			"arrived yet. The source states a kernel device; the DESCRIPTION comes from the "+
			"enrichment snapshot, which lands on the exporter's own schedule, so a push lane can "+
			"ingest for minutes before it can label anything. Emitting the raw device instead would "+
			"invent a SECOND series for an interface that already has one and make every "+
			"`sum by (interface)` under-report both (#606). This is a startup artifact and it "+
			"closes on its own: on the reference box every such record landed with the process less "+
			"than 300 seconds old, across 7 days and 51 restarts. A rate that continues past that "+
			"means the interface fetch itself is failing, not that a restart happened.",
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
	c.registerGeoIP()
}

// registerExtras builds the §9 volume/talker metrics and the DNS answer-cache
// self-metrics (#353).
func (c *flowCollector) registerExtras() {
	// Literals, for the same docgen static-resolution reason as the volume labels.
	ifaceLabel := []string{"interface"}
	hostDirLabel := []string{"host", "direction"}

	c.uniqueDests = buildPrometheusDesc(c.subsystem, "unique_destinations",
		"Distinct destination addresses seen per interface - a bounded stand-in for a per-destination "+
			"series (one gauge per interface, never one per destination). A set, not a sum, so a "+
			"destination reported by both the NetFlow and Zenarmor lanes counts once. Saturates at an "+
			"internal per-interface cap; a value pinned at the cap means the true count is at least "+
			"that high, which is itself a scanning/fan-out signal.",
		ifaceLabel,
	)
	c.uniqueDestsCapped = buildPrometheusDesc(c.subsystem, "unique_destinations_capped_total",
		"Observations folded into the __other__ interface bucket because a previously unseen "+
			"interface label arrived when the distinct-destination tracker was already at its "+
			"interface budget. The interface and VLAN strings are chosen by the Zenarmor sender, so "+
			"without an outer bound an admitted sender could mint one map and one series per novel "+
			"combination (#563). A rising value means interface labels beyond the budget are being "+
			"merged, so per-interface distinct-destination counts are no longer complete - either "+
			"the box genuinely has more interfaces than the budget, or a sender is inventing them.",
		nil,
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
		"Histogram of NetFlow-over-Zenarmor byte ratios on merged flow records, by interface - the "+
			"payoff of correlating the two sources (#346 decision 3). 1.0 is agreement; a value well "+
			"above 1 means Zenarmor inspected far fewer bytes than crossed the wire, which is a security "+
			"signal, not an error. Present only where both lanes run and correlate (--flow.log-mode="+
			"per_flow); absent otherwise, since there is no disagreement to measure. "+
			"READ THE DEVIATION CAREFULLY: it is not all source disagreement (#604). NetFlow counts "+
			"WIRE bytes; Zenarmor falls back to PAYLOAD bytes on roughly half of all flow records "+
			"(short UDP, where it has not yet accumulated wire bytes), so on that population the "+
			"histogram is reporting per-packet header overhead - the gap clusters at 28 bytes, the "+
			"IPv4 IP+UDP header, and the p90 there alone reaches 1.96. The record states its own basis, "+
			"so a consumer can tell the two apart. Window partials - where this window's NetFlow bytes "+
			"would be compared against a whole connection's Zenarmor bytes - are EXCLUDED entirely and "+
			"counted in source_byte_delta_excluded_total, so the impossible sub-1.0 tail is gone rather "+
			"than explained away. For the underlying security question (is traffic evading inspection) "+
			"prefer a BYTE-WEIGHTED comparison - the ratio of summed bytes on merged records - over a "+
			"percentile of per-flow ratios.",
		ifaceLabel,
	)
	c.deltaExcluded = buildPrometheusDesc(c.subsystem, "source_byte_delta_excluded_total",
		"Merged flow records deliberately kept OUT of source_byte_delta_ratio because their two "+
			"sides are not totalling the same thing (#604). Today that is exactly the window-partial "+
			"case: corrKey buckets by flow-end, so a connection longer than --flow.correlate.window "+
			"emits one record per window carrying only THAT window's NetFlow bytes, while the single "+
			"Zenarmor conn document carries the whole connection's counters and merges into one of "+
			"them. Comparing those reads as \"the firewall counted 75x fewer bytes than crossed the "+
			"wire\", which is impossible. The records still SHIP with both sides' counters - only the "+
			"comparison is meaningless - so this is the histogram's coverage gap, not lost volume. "+
			"On a box with a long active timeout expect a steady non-zero rate; a sudden rise means "+
			"connections are outliving the correlate window more often.",
		nil,
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

// registerGeoIP builds the self-metrics for the local MaxMind databases and the flow
// geo enricher (#520). All of them are absent unless --geoip.enabled opened a
// database, for the same reason the NetFlow metrics are (see SetNetflowStats).
func (c *flowCollector) registerGeoIP() {
	// Literals, for the same docgen static-resolution reason as the volume labels.
	dbResultLabels := []string{"database", "result"}
	dbLabel := []string{"database"}
	resultLabel := []string{"result"}

	c.geoLookups = buildPrometheusDesc(c.subsystem, "geoip_lookups_total",
		"GeoIP enrichment lookups, by database (\"country\", \"asn\" or \"skipped\") and result. "+
			"\"hit\" means a record was found; \"miss\" means the loaded database has no record for "+
			"that address; \"skipped\" (always with database=\"skipped\") counts addresses that never "+
			"reached a database because they are not globally routable - loopback, RFC 1918, "+
			"link-local, and carrier-grade NAT, which MaxMind publishes no records for at all. A "+
			"database that is not loaded contributes neither hits nor misses, so a country hit rate of "+
			"zero with a non-zero ASN rate means the country database specifically failed to load.",
		dbResultLabels,
	)
	c.geoReloads = buildPrometheusDesc(c.subsystem, "geoip_reloads_total",
		"GeoIP database hot-swaps, by database and result. A \"success\" means a changed file on disk "+
			"was read and swapped in atomically, which is how an operator's geoipupdate cron or the "+
			"built-in downloader replaces a database under a running exporter. A \"failure\" means the "+
			"new file could not be read or parsed, in which case the PREVIOUSLY loaded database keeps "+
			"serving - a bad update costs freshness, never availability. An unchanged file is not "+
			"counted at all. Failures are not attributable to one database without threading the path "+
			"out of the reload, so they carry database=\"skipped\", a value no real database uses.",
		dbResultLabels,
	)
	c.geoDownloads = buildPrometheusDesc(c.subsystem, "geoip_downloads_total",
		"MaxMind database downloads, by result: \"updated\" (a newer build was fetched, verified "+
			"against its published SHA-256, and installed), \"unmodified\" (the conditional request "+
			"returned 304 - the healthy steady state, and what keeps a daily updater inside MaxMind's "+
			"download limit), or \"failure\". Emitted only when --geoip.download.enabled is set; an "+
			"operator-managed deployment leaves this at zero forever, which is correct.",
		resultLabel,
	)
	c.geoBuildTime = buildPrometheusDesc(c.subsystem, "geoip_database_build_timestamp_seconds",
		"Unix timestamp of the loaded GeoIP database's build, per database. This is the publisher's "+
			"BUILD date, not when the file was downloaded, so it is the right thing to alert staleness "+
			"on: time() - this > 45d catches a refresh that has silently stopped, which the fail-open "+
			"design makes otherwise invisible. 45d rather than something tighter because it has to "+
			"cover every database the exporter can load, and the DB-IP Lite copy bundled in the image "+
			"republishes monthly while GeoLite2 rebuilds twice a week. ABSENT for a database that is "+
			"not loaded, rather than zero - a zero would read as \"built in 1970\" and fire every "+
			"staleness alert ever written against it.",
		dbLabel,
	)
	c.geoEnriched = buildPrometheusDesc(c.subsystem, "geoip_enriched_records_total",
		"Flow records that gained at least one fact from OUR database. It is the \"is this feature "+
			"doing anything\" signal, and it is what distinguishes a database that failed to load from "+
			"a network whose traffic is genuinely all internal - both of which otherwise look like "+
			"silence, because enrichment is fail-open by design.",
		nil,
	)
	c.geoCountryAgree = buildPrometheusDesc(c.subsystem, "geoip_country_comparisons_total",
		"Flow endpoints where BOTH our database and Zenarmor's answered with a country, by whether "+
			"they agreed. This is what makes the cost of the ours-wins precedence rule measurable "+
			"rather than assumed: Zenarmor's database is a commercial GeoIP2-City build (verified on a "+
			"live firewall - database_type \"GeoIP2-City\", 126 MB against a stock GeoLite2's 63 MB), so "+
			"overwriting its answer with a free GeoLite2 lookup can genuinely replace a better "+
			"attribution with a worse one. A rising disagree rate is the signal to look; ours still "+
			"wins the exported country either way, and the disagreeing value is kept on the log record "+
			"as <src|dst>.geo.zen_country. Absent entirely without Zenarmor, since there is nothing to "+
			"compare against.",
		resultLabel,
	)
}

// collectGeoIP emits the GeoIP self-metrics, and emits nothing when no database was
// ever opened — see SetGeoIPStats for why absent beats zero here.
func (c *flowCollector) collectGeoIP(ch chan<- prometheus.Metric) {
	st, ok := c.store.geoipStats()
	if !ok {
		return
	}
	counter := func(d *prometheus.Desc, v int64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, float64(v),
			append(labels, c.instance)...)
	}

	counter(c.geoLookups, st.DB.CountryHits, "country", "hit")
	counter(c.geoLookups, st.DB.CountryMisses, "country", "miss")
	counter(c.geoLookups, st.DB.ASNHits, "asn", "hit")
	counter(c.geoLookups, st.DB.ASNMisses, "asn", "miss")
	counter(c.geoLookups, st.DB.Skipped, "skipped", "skipped")

	counter(c.geoReloads, st.DB.CountryReloads, "country", "success")
	counter(c.geoReloads, st.DB.ASNReloads, "asn", "success")
	counter(c.geoReloads, st.DB.ReloadFailures, "skipped", "failure")

	counter(c.geoDownloads, st.DB.DownloadsUpdated, "updated")
	counter(c.geoDownloads, st.DB.DownloadsUnmodified, "unmodified")
	counter(c.geoDownloads, st.DB.DownloadsFailed, "failure")

	counter(c.geoEnriched, int64(st.Flow.Enriched)) //nolint:gosec // a counter, never near 2^63
	counter(c.geoCountryAgree, int64(st.Flow.CountryAgreements), "agree")
	counter(c.geoCountryAgree, int64(st.Flow.CountryDisagreements), "disagree")

	// Omitted entirely for a database that is not loaded: a zero build time reads as
	// 1970 and would fire every staleness alert written against it, forever.
	if !st.DB.CountryBuildTime.IsZero() {
		ch <- prometheus.MustNewConstMetric(c.geoBuildTime, prometheus.GaugeValue,
			float64(st.DB.CountryBuildTime.Unix()), "country", c.instance)
	}
	if !st.DB.ASNBuildTime.IsZero() {
		ch <- prometheus.MustNewConstMetric(c.geoBuildTime, prometheus.GaugeValue,
			float64(st.DB.ASNBuildTime.Unix()), "asn", c.instance)
	}
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
	c.corrEnrichOverwrites = buildPrometheusDesc(c.subsystem, "correlator_enrichment_overwrites_total",
		"A second Zenarmor conn document landing for a key that already held one (#590). The second "+
			"REPLACES the first wholesale rather than merging - L7, verdict, enrichment and geo the "+
			"first document carried and the second doesn't repeat are gone with no trace. Zero on "+
			"every deployment where each conversation gets one conn document, which is the common "+
			"case; a non-zero rate means Zenarmor is re-reporting a connection and only the latest "+
			"report survives.",
		nil)
	c.corrFragDisagree = buildPrometheusDesc(c.subsystem, "correlator_fragment_disagreement_total",
		"A NetFlow fragment whose interface, direction, VLAN or enrichment disagreed with the entry's "+
			"first fragment OF ITS OWN ORIENTATION (#590, #605). The disagreeing fragment's bytes still "+
			"count toward the emitted total; only its DIMENSIONS are dropped, silently until this "+
			"counter. Two exclusions, both because the field differs by design rather than in error: "+
			"TCPFlags is unioned across fragments (#585), and the conversation's reverse half mirrors "+
			"interface and direction by construction - that case is counted by "+
			"correlator_fragment_mirrored_total instead.",
		nil)
	c.corrFragMirrored = buildPrometheusDesc(c.subsystem, "correlator_fragment_mirrored_total",
		"A NetFlow fragment belonging to the conversation's OTHER direction - the reverse half, which "+
			"shares a correlator key by design because the community id is direction-independent. This "+
			"is the expected case for any bidirectional flow, not an anomaly, and it is counted rather "+
			"than merely excluded so the exclusion stays visible: a collapse to zero would mean the two "+
			"halves stopped sharing a key, which would break correlation itself. Before #605 these were "+
			"counted as disagreements and were 48.6% of every fragment that counter could examine.",
		nil)

	c.logEmitted = buildPrometheusDesc(c.subsystem, "logs_emitted_total",
		"Flow records shipped to the OTLP log pipeline. Zero when --flow.log-mode=off even though the "+
			"correlator still runs and its metrics still move.", nil)
	c.logTruncated = buildPrometheusDesc(c.subsystem, "logs_truncated_total",
		"Flow log records dropped by the --flow.max-logs-per-window budget. Truncated, never sampled, "+
			"and counted: a flood on the unauthenticated NetFlow ingress is visible here rather than as "+
			"a silently thinned stream. Metrics are never truncated.", nil)
	c.logDropped = buildPrometheusDesc(c.subsystem, "logs_dropped_total",
		"Flow log records dropped because the log pipeline was not accepting records - before it "+
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
			"itself, NOT the traffic it describes - opnsense_flow_bytes_total is that.",
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
			"before the template describing it - normal for up to ~2 minutes after either end restarts, "+
			"since ng_netflow resends templates about every 2 minutes, and a sustained rate means "+
			"template datagrams are being lost. \"vlan_duplicate\" is the parent-interface copy of a "+
			"VLAN flow, which ng_netflow captures twice (~4% of bytes on the reference box) and which "+
			"would otherwise be counted twice AND attributed to the parent. \"no_address\" is a record "+
			"with unusable endpoints.",
		reasonLabel,
	)
	c.nfUnmapped = buildPrometheusDesc(c.subsystem, "netflow_records_unmapped_total",
		"Records whose ifIndexes resolved to NO interface, so they carry an empty interface label. "+
			"They are still emitted and still counted in the volume totals - this is not a drop, and it "+
			"is deliberately not a reason on records_dropped_total. Distinct from "+
			"opnsense_flow_ifindex_unmapped_total, which counts failed LOOKUPS against a map that "+
			"exists: this counts RECORDS, and it is the only counter that fires at all while the map is "+
			"still nil, which is the cold-start window between the receiver starting and the first "+
			"interface fetch landing. A burst right after a restart is that window and is expected to "+
			"stop; a sustained rate means the enumeration shifted and --flow.netflow.ifindex-map needs "+
			"setting. Before #365 this window was completely silent, which put gigabytes into the "+
			"empty-label bucket with every health metric reading clean.",
		nil,
	)
	c.nfTemplates = buildPrometheusDesc(c.subsystem, "netflow_templates_total",
		"NetFlow v9 template events. \"learned\" is a template id seen for the first time; "+
			"\"replaced\" is a known id re-sent with a DIFFERENT field shape, which invalidates the "+
			"decoder's understanding of every record behind it. A steady replaced rate means the "+
			"exporter is flapping between configurations. \"evicted\" is a template dropped because "+
			"the cache was already at its budget when a new (exporter, source id, template id) "+
			"arrived: the listener is unauthenticated, so an admitted sender could otherwise grow "+
			"the cache without bound (#564). Eviction is least-recently-used, and a refresh of an "+
			"existing key never evicts — so a non-zero rate here means either genuinely more "+
			"observation domains than the budget allows, or a sender minting novel ids.",
		resultLabel,
	)
	c.nfUnexpected = buildPrometheusDesc(c.subsystem, "netflow_unexpected_field_total",
		"Records carrying a field the decoder asserts is always empty on this export. "+
			"field=\"out_bytes\": OUT_BYTES/OUT_PKTS are declared in the template but were zero across "+
			"all 84,513 records of the reference capture, so they are ignored rather than added to the "+
			"volume. field=\"src_as\"/\"dst_as\" (#586): ng_netflow hardcodes SRC_AS/DST_AS to zero on "+
			"every export path under an explicit source comment, so the fields were deleted from the "+
			"record entirely rather than stored - a better ASN already ships via the GeoIP asn label. "+
			"A non-zero rate on ANY of these means that assumption has expired and the decoder needs "+
			"revisiting - it does NOT mean volume is currently wrong.",
		[]string{"field"},
	)
	c.nfUnidentified = buildPrometheusDesc(c.subsystem, "netflow_unidentified_total",
		"Things in the export this decoder could not interpret and stepped over, by kind. "+
			"kind=\"unknown_field\" is a template element the decoder does not model, counted once "+
			"per element when a template shape is first learned or CHANGED (never on the ~2-minutely "+
			"re-send); a non-zero value is EXPECTED on OPNsense, whose IPv4 template declares four "+
			"such elements, so it is a CHANGE here that means the export gained something. "+
			"kind=\"options_template\" and kind=\"unknown_flowset\" are control flowsets stepped "+
			"over by length. Stepping over is the correct parse behaviour - doing it silently was "+
			"not, and --flow.netflow.debug-capture=unidentified keeps the datagrams. The element and "+
			"flowset IDs themselves are deliberately NOT labels: this arrives on an unauthenticated "+
			"socket, so they go to the log line and the capture file instead.",
		[]string{"kind"},
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
	c.policyRouteCorr = buildPrometheusDesc(c.subsystem, "policy_route_corrected_total",
		"Flow records whose egress interface was replaced by the device pf's own state table says "+
			"the traffic left by. This is the PRE-NAT copy of a policy-routed flow - the only copy "+
			"that can correlate with Zenarmor - which inherits ng_netflow's OUTPUT_SNMP and therefore "+
			"names the default-route WAN whatever pf did. It is distinct from egress_corrected_total, "+
			"which resolves the POST-NAT copy from its source address and cannot see this case at all. "+
			"A zero rate on a single-WAN box is expected; a zero rate on a policy-routed multi-WAN box "+
			"means correlated per-WAN volume is still misattributed.",
		nil,
	)
	c.policyRouteRefused = buildPrometheusDesc(c.subsystem, "policy_route_refused_total",
		"Pre-NAT WAN-egress records the policy-route repair REFUSED to correct, by reason. "+
			"reason=\"no_state\" is the mechanism's genuine miss window: the flow ended and its pf "+
			"state expired before the NetFlow record arrived (short flows; the reference box runs "+
			"inactiveTimeout=15). NO poll interval closes it, and the traffic is left exactly as "+
			"ng_netflow reported it rather than guessed. reason=\"unresolved_device\" means pf named "+
			"an egress device the interface enumeration does not know - the fix is the enumeration, "+
			"and labelling the record with the raw kernel name would split one interface across two "+
			"series.",
		[]string{"reason"},
	)
	c.pfStateEntries = buildPrometheusDesc(c.subsystem, "pf_state_entries",
		"Pre-NAT pf states the policy-route repair can resolve against, by kind. kind=\"total\" is "+
			"every direction=\"in\" state that could be keyed; kind=\"policy_routed\" is the subset "+
			"carrying a route-to, i.e. the ones that can actually change a record's egress. "+
			"kind=\"skipped\" is rows that could not be keyed at all (an unmodelled protocol, an "+
			"unparseable address or port) and kind=\"conflict\" is keys that were already taken - "+
			"measured zero on the reference box, so a non-zero value means the tuple stopped being "+
			"unique upstream and every answer from this table wants re-checking.",
		[]string{"kind"},
	)
	c.pfStateAge = buildPrometheusDesc(c.subsystem, "pf_state_age_seconds",
		"Age of the pf state snapshot the policy-route repair resolves against. It is polled on the "+
			"cold tier (the full table is ~3 MB and ~650 ms on the reference box), so a value rising "+
			"past a few multiples of that interval means the fetch is failing and corrections are "+
			"being made against a stale routing picture.",
		nil,
	)
	c.dedupeEntries = buildPrometheusDesc(c.subsystem, "dedupe_entries",
		"Flow instances currently held in the VLAN de-duplication table.",
		nil,
	)
	c.vlanChildPreferred = buildPrometheusDesc(c.subsystem, "vlan_child_preferred_total",
		"VLAN duplicates resolved in favour of the VLAN CHILD copy after the trunk copy had already "+
			"been held. ng_netflow exports the trunk hook's flows and the child hook's flows in "+
			"separate datagrams, trunk first, so without this the surviving copy attributes every "+
			"VLAN's traffic to the trunk interface. A zero rate on a box with VLAN interfaces means "+
			"the attribution fix is not firing and per-VLAN volume is collapsed onto the trunk.",
		nil,
	)
	c.vlanSubnetAttrib = buildPrometheusDesc(c.subsystem, "vlan_subnet_attributed_total",
		"Flow records moved from a TRUNK interface onto the VLAN child whose configured subnet owns "+
			"the address, resolved on first sight instead of by waiting to see which copy the exporter "+
			"flushed first. The 2-second hold that preceded this covers only 70.8% of real "+
			"trunk/child pairs (measured p50 gap 954 ms but p95 5.7 s and p99 31.2 s), and for the "+
			"other 29.2% the trunk copy had already been emitted, so every one of those flows was "+
			"attributed to the trunk. This also attributes records that have NO second copy at all - "+
			"247,105 of them in an 18h35m measurement - which no hold window of any size could reach. "+
			"A zero rate on a box with VLAN interfaces that carry configured subnets means the "+
			"attribution is not firing and per-VLAN volume is collapsing onto the trunk.",
		nil,
	)
	c.vlanLateChildCopy = buildPrometheusDesc(c.subsystem, "vlan_late_child_copies_total",
		"VLAN duplicates that arrived attributing the flow BETTER than the copy already emitted, and "+
			"therefore too late to correct it. This is the residual the repair stage cannot fix: an "+
			"emitted record has been counted and shipped, so it cannot be taken back, and emitting "+
			"the better copy as well would double-count real bytes. It is counted rather than left "+
			"silent because it is the exact measure of remaining misattribution - it was 29.2% of "+
			"pairs before subnet attribution existed and should sit near zero now, moving only for "+
			"addresses that match no VLAN child subnet or several of them. A sustained non-zero rate "+
			"means subnet evidence is missing for a VLAN that needs it: check that the interface has "+
			"a configured subnet and that no two children overlap.",
		nil,
	)
	c.repairHeld = buildPrometheusDesc(c.subsystem, "repair_held_records",
		"Flow records parked in the repair stage waiting to see whether a copy on a VLAN child beats "+
			"them. They are neither emitted nor dropped yet, so this is the term that closes "+
			"records_in = emitted + dropped + no_address + held. A value that grows without bound "+
			"means records are not being released.",
		nil,
	)
	c.dedupeDropped = buildPrometheusDesc(c.subsystem, "dedupe_entries_dropped_total",
		"Entries removed from the de-duplication table. reason=\"ttl\" is the healthy path - the "+
			"instance aged out having done its job. reason=\"capacity\" means the table was full and an "+
			"entry was evicted early, so a duplicate arriving afterwards is NO LONGER SUPPRESSED and "+
			"reaches the rollup twice; a non-zero rate is the signal to raise the bound.",
		reasonLabel,
	)

	c.interfaceInfo = buildPrometheusDesc(c.subsystem, "interface_info",
		"The resolved NetFlow ifIndex map as an info metric, one series per index, always 1 - the "+
			"data is in the labels. It exists to make two label spaces joinable: the box's own "+
			"per-hook counters (opnsense_netflow_cache_*) are keyed by kernel DEVICE, while every "+
			"flow and capture metric is keyed by the configured DESCRIPTION, and the single most "+
			"valuable NetFlow health statement spans both - \"this interface is configured for "+
			"capture and its OWN ng_netflow node has been frozen at zero\". Join through it with "+
			"group_left: a dead hook is otherwise a two-panel eyeball correlation, because a fresh "+
			"record age proves only that the interface was NAMED (ng_netflow fills the far side of "+
			"each flow from a FIB lookup), never that its own hook is alive. ifindex is a POSITION "+
			"in the box's ifinfo output, so it renumbers when any interface is added or removed - "+
			"treat a changed value as the map having moved, not as a relabel. device is empty for "+
			"index 0, which is traffic the firewall itself originated; interface is empty for a "+
			"port with no OPNsense assignment, which still holds a slot in the enumeration.",
		[]string{"device", "interface", "ifindex"},
	)

	c.captureUnsupp = buildPrometheusDesc(c.subsystem, "interface_capture_unsupported",
		"Interfaces whose kernel device can NEVER capture NetFlow, whatever the box's capture "+
			"configuration says. Present (and always 1) only for such a device; ABSENT means capable, "+
			"so this is an exception marker rather than a per-interface flag. "+
			"reason=\"pppoe_framing_node\" is the only value today: ng_netflow attaches to mpd's "+
			"framing node rather than the ng_iface node ng_pppoe exposes, so `ngctl mkpeer` on a PPPoE "+
			"interface SUCCEEDS, creates the node, and then counts zero packets forever (#368). No "+
			"configuration clears it, which is why this suppresses OPNsenseNetFlowHookDead rather than "+
			"raising an alert of its own. Nothing is lost when it appears: ng_netflow fills the far "+
			"side of every flow from a FIB lookup, so the WAN's traffic is still captured through the "+
			"other interfaces' hooks and still attributed to it - 2.09 GB in 45m on the reference box "+
			"while this very device's hook read zero. Untick the interface in Reporting/NetFlow to "+
			"stop asking for a capture that cannot happen; leaving it selected costs only a dead "+
			"netgraph node.",
		[]string{"device", "interface", "reason"},
	)
	c.ifIndexEntries = buildPrometheusDesc(c.subsystem, "ifindex_entries",
		"Entries in the NetFlow ifIndex-to-interface map, including the synthetic index 0 "+
			"(traffic originated by the firewall itself).",
		nil,
	)
	c.ifIndexConflicts = buildPrometheusDesc(c.subsystem, "ifindex_conflicts",
		"Operator overrides from --flow.netflow.ifindex-map that DISAGREE with the map derived from "+
			"the API. reason=\"derived_differs\" counts pins where the derivation produced a DIFFERENT "+
			"interface at that index; reason=\"derived_absent\" counts pins at an index the derivation "+
			"produced nothing for at all, which is normal for an index beyond the enumeration and says "+
			"nothing about the ordering. Non-zero does NOT say which side is right: a pin is a static "+
			"assertion, and adding or removing ANY interface renumbers every position above it, so a "+
			"pin that was correct when written goes stale on its own - that is what #516 turned out to "+
			"be, a new VLAN shifting three pins by one and relabelling the WAN as the tailnet. Settle "+
			"it against the box, not this counter: `ifinfo` order, or decisively the ifaceN hook names "+
			"on its ng_netflow nodes (`ngctl show netflow_<device>:`). The override wins either way, so "+
			"a stale pin is actively mislabelling while a correct one leaves every unpinned index suspect.",
		reasonLabel,
	)
	c.ifIndexAge = buildPrometheusDesc(c.subsystem, "ifindex_map_age_seconds",
		"Age of the ifIndex map. ng_netflow's indices are positional over ifinfo output, so adding or "+
			"removing ANY interface renumbers everything and silently remaps historical series. A map "+
			"that stops being refreshed is therefore a correctness problem, not a staleness nuisance.",
		nil,
	)
	c.ifIndexGuard = buildPrometheusDesc(c.subsystem, "ifindex_source_disagreements",
		"Cross-checks that failed on the derived ifIndex enumeration. "+
			"reason=\"stated_index\" counts devices where the ifIndex the API states differs from the "+
			"position the enumeration put them at, which means an interface was removed and every "+
			"index above it shifted down. reason=\"unlisted_device\" counts "+
			"interfaces the box reports that the enumeration does not contain at all, so they can "+
			"never be resolved from an ifIndex. Either one non-zero means the labels on every NetFlow "+
			"series are suspect - the derivation was measurably wrong this way for months (#361).",
		reasonLabel,
	)
	c.ifIndexUnmapped = buildPrometheusDesc(c.subsystem, "ifindex_unmapped_total",
		"ifIndex lookups that resolved to no interface. These records are still counted, with an "+
			"EMPTY interface label - a wrong interface name is worse than a missing one. A rising rate "+
			"after a network change means the enumeration shifted and --flow.netflow.ifindex-map needs "+
			"setting.",
		nil,
	)
}

// captureUnsupportedReason names why a kernel device can never capture NetFlow,
// or "" when nothing is known against it.
//
// Matched on the DEVICE and as a PREFIX, both deliberately. The device is the
// kernel's own name and is the thing netgraph attaches to, while the description
// is operator-chosen free text — exempting an interface someone happened to call
// "pppoe-backup" would silently disarm the alert that protects it.
//
// pppoe only. pptp and l2tp are built on the same mpd/netgraph framing and are
// very likely identical, but that is UNVERIFIED — this list states what has been
// observed on a real box, not what is probable, because a wrong entry here
// silences a genuinely dead hook rather than merely failing to explain one.
func captureUnsupportedReason(device string) string {
	if strings.HasPrefix(device, "pppoe") {
		return "pppoe_framing_node"
	}
	return ""
}

func (c *flowCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.bytes
	ch <- c.packets
	ch <- c.records
	ch <- c.fallback
	ch <- c.interfaceUnresolved
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
	ch <- c.nfUnmapped
	ch <- c.nfTemplates
	ch <- c.nfUnexpected
	ch <- c.nfUnidentified
	ch <- c.egressCorrected
	ch <- c.policyRouteCorr
	ch <- c.policyRouteRefused
	ch <- c.pfStateEntries
	ch <- c.pfStateAge
	ch <- c.dedupeEntries
	ch <- c.dedupeDropped
	ch <- c.vlanChildPreferred
	ch <- c.vlanSubnetAttrib
	ch <- c.vlanLateChildCopy
	ch <- c.repairHeld
	ch <- c.interfaceInfo
	ch <- c.captureUnsupp
	ch <- c.ifIndexEntries
	ch <- c.ifIndexConflicts
	ch <- c.ifIndexAge
	ch <- c.ifIndexUnmapped
	ch <- c.ifIndexGuard
	ch <- c.corrEntries
	ch <- c.corrEmitted
	ch <- c.corrMatched
	ch <- c.corrEvicted
	ch <- c.corrExpired
	ch <- c.corrEnrichOverwrites
	ch <- c.corrFragDisagree
	ch <- c.corrFragMirrored
	ch <- c.logEmitted
	ch <- c.logTruncated
	ch <- c.logDropped
	ch <- c.uniqueDests
	ch <- c.uniqueDestsCapped
	ch <- c.topTalker
	ch <- c.deltaRatio
	ch <- c.deltaExcluded
	ch <- c.dnsCacheEntries
	ch <- c.dnsCacheHits
	ch <- c.dnsCacheMisses
	ch <- c.dnsCacheRejected
	ch <- c.geoLookups
	ch <- c.geoReloads
	ch <- c.geoDownloads
	ch <- c.geoBuildTime
	ch <- c.geoEnriched
	ch <- c.geoCountryAgree
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
	ch <- prometheus.MustNewConstMetric(c.interfaceUnresolved, prometheus.CounterValue,
		float64(c.store.interfaceUnresolved.Load()), c.instance)

	st := c.store.rollup.Stats()
	ch <- prometheus.MustNewConstMetric(c.rollupKeys, prometheus.GaugeValue, float64(st.Keys), c.instance)
	ch <- prometheus.MustNewConstMetric(c.rollupKeysMax, prometheus.GaugeValue, float64(st.MaxKeys), c.instance)
	ch <- prometheus.MustNewConstMetric(c.rollupTopN, prometheus.GaugeValue, float64(st.TopN), c.instance)
	ch <- prometheus.MustNewConstMetric(c.rollupFolded, prometheus.GaugeValue, float64(st.FoldedKeys), c.instance)
	ch <- prometheus.MustNewConstMetric(c.rollupCapped, prometheus.CounterValue, float64(st.Capped), c.instance)

	c.collectNetflow(ch)
	c.collectCorrelator(ch)
	c.collectExtras(ch)
	c.collectGeoIP(ch)
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
	{
		st := c.store.uniqueDests.Stats()
		ch <- prometheus.MustNewConstMetric(c.uniqueDestsCapped, prometheus.CounterValue, float64(st.Capped), c.instance)
	}
	for _, e := range c.store.topTalkers.Snapshot() {
		ch <- prometheus.MustNewConstMetric(c.topTalker, prometheus.CounterValue, float64(e.Bytes),
			e.Host, e.Direction, c.instance)
	}
	// Emitted unconditionally, including zero: an exclusion counter that only appears
	// once something has been excluded cannot be alerted on, and "the histogram is
	// complete" is exactly the claim it exists to let a reader check.
	ch <- prometheus.MustNewConstMetric(c.deltaExcluded, prometheus.CounterValue,
		float64(c.store.delta.Excluded()), c.instance)
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
		ch <- prometheus.MustNewConstMetric(c.corrEnrichOverwrites, prometheus.CounterValue,
			float64(st.EnrichmentOverwrites), c.instance)
		ch <- prometheus.MustNewConstMetric(c.corrFragDisagree, prometheus.CounterValue,
			float64(st.FragmentDisagreements), c.instance)
		ch <- prometheus.MustNewConstMetric(c.corrFragMirrored, prometheus.CounterValue,
			float64(st.FragmentMirrored), c.instance)
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
	// Not a drop reason: an unmapped record emits with an empty interface label, so
	// folding it into records_dropped_total would break decoded = emitted + dropped
	// AND claim data was discarded when it was counted (#367).
	counter(c.nfUnmapped, nf.Pipeline.RecordsUnmapped)

	counter(c.nfTemplates, nf.Decoder.TemplatesLearned, "learned")
	counter(c.nfTemplates, nf.Decoder.TemplatesReplaced, "replaced")
	counter(c.nfTemplates, nf.Decoder.TemplatesEvicted, "evicted")
	counter(c.nfUnexpected, nf.Decoder.UnexpectedOutBytes, "out_bytes")
	counter(c.nfUnexpected, nf.Decoder.UnexpectedSrcAS, "src_as")
	counter(c.nfUnexpected, nf.Decoder.UnexpectedDstAS, "dst_as")
	counter(c.nfUnidentified, nf.Decoder.UnknownFields, "unknown_field")
	counter(c.nfUnidentified, nf.Decoder.OptionsTemplates, "options_template")
	counter(c.nfUnidentified, nf.Decoder.UnknownFlowsets, "unknown_flowset")

	counter(c.egressCorrected, nf.Repair.EgressCorrected)
	counter(c.policyRouteCorr, nf.Repair.PolicyRouteCorrected)
	counter(c.policyRouteRefused, nf.Repair.PolicyRouteNoState, "no_state")
	counter(c.policyRouteRefused, nf.Repair.PolicyRouteUnresolvedDevice, "unresolved_device")
	gauge(c.pfStateEntries, float64(nf.Repair.RouteTableEntries), "total")
	gauge(c.pfStateEntries, float64(nf.Repair.RouteTablePolicyRouted), "policy_routed")
	gauge(c.pfStateEntries, float64(nf.Repair.RouteTableSkipped), "skipped")
	gauge(c.pfStateEntries, float64(nf.Repair.RouteTableConflicts), "conflict")
	gauge(c.pfStateAge, nf.Repair.RouteTableAge.Seconds())
	gauge(c.dedupeEntries, float64(nf.Repair.DedupeEntries))
	counter(c.dedupeDropped, nf.Repair.DedupeEvicted, "ttl")
	counter(c.dedupeDropped, nf.Repair.DedupeCapped, "capacity")
	counter(c.dedupeDropped, nf.Repair.HoldOverflow, "hold_overflow")
	counter(c.vlanChildPreferred, nf.Repair.VLANChildPreferred)
	counter(c.vlanSubnetAttrib, nf.Repair.VLANSubnetAttributed)
	counter(c.vlanLateChildCopy, nf.Repair.VLANLateChildCopies)
	gauge(c.repairHeld, float64(nf.Pipeline.RecordsHeld))

	// One series per resolved index, value always 1: the payload is the label
	// triple. Every entry is published, including the ones with an empty label —
	// an index whose device or description we do not know is exactly the case an
	// operator needs to SEE, and dropping it would make the map look complete.
	for _, e := range nf.IfMapEntries {
		gauge(c.interfaceInfo, 1, e.Device, e.Name, strconv.FormatUint(uint64(e.Index), 10))
		if reason := captureUnsupportedReason(e.Device); reason != "" {
			gauge(c.captureUnsupp, 1, e.Device, e.Name, reason)
		}
	}

	gauge(c.ifIndexEntries, float64(nf.IfMap.Entries))
	gauge(c.ifIndexConflicts, float64(nf.IfMap.ConflictsDiffering), "derived_differs")
	gauge(c.ifIndexConflicts, float64(nf.IfMap.ConflictsAbsent), "derived_absent")
	gauge(c.ifIndexAge, nf.IfMapAge.Seconds())
	counter(c.ifIndexUnmapped, nf.IfMap.UnmappedLookups)
	gauge(c.ifIndexGuard, float64(nf.IfMap.StatedIndexDisagreements), "stated_index")
	gauge(c.ifIndexGuard, float64(nf.IfMap.UnlistedDevices), "unlisted_device")
}
