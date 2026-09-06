package collector

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

type unboundDNSCollector struct {
	log    *slog.Logger
	uptime *prometheus.Desc

	// Counter descriptors (no extra labels)
	queriesTotal         *prometheus.Desc
	cacheHitsTotal       *prometheus.Desc
	cacheMissTotal       *prometheus.Desc
	prefetchTotal        *prometheus.Desc
	expiredTotal         *prometheus.Desc
	recursiveReplies     *prometheus.Desc
	queriesTimedOutTotal *prometheus.Desc
	queriesIPRatelimited *prometheus.Desc
	answersSecureTotal   *prometheus.Desc
	answersBogusTotal    *prometheus.Desc
	rrsetBogusTotal      *prometheus.Desc

	// Query drop/limit counters and error reporting (#237) — base statistics,
	// unlike the extended-only descriptors above.
	queriesDiscardTimeoutTotal *prometheus.Desc
	queriesWaitLimitTotal      *prometheus.Desc
	queriesReplyAddrLimitTotal *prometheus.Desc
	dnsErrorReportsTotal       *prometheus.Desc

	// Counter descriptors (with labels)
	queriesByType   *prometheus.Desc
	queriesByProto  *prometheus.Desc
	answersByRcode  *prometheus.Desc
	unwantedTotal   *prometheus.Desc
	queryFlagsTotal *prometheus.Desc
	ednsTotal       *prometheus.Desc

	// Gauge descriptors (no extra labels)
	requestListAvg      *prometheus.Desc
	requestListMax      *prometheus.Desc
	recursionTimeAvg    *prometheus.Desc
	recursionTimeMedian *prometheus.Desc

	// Gauge descriptors (with labels)
	cacheCount         *prometheus.Desc
	memoryBytes        *prometheus.Desc
	requestListCurrent *prometheus.Desc

	// Counter descriptors (no extra labels, request list)
	requestListOverwritten *prometheus.Desc
	requestListExceeded    *prometheus.Desc

	// Gauge descriptors (no extra labels, additional)
	tcpUsage         *prometheus.Desc
	blocklistEnabled *prometheus.Desc
	serviceRunning   *prometheus.Desc

	// Reply-time histogram + the DNSSEC validator's workload (#581). Both are
	// extended-statistics sourced; the histogram carries its own presence flag
	// from the client rather than riding ExtendedPresent.
	recursionHistogram   *prometheus.Desc
	validationOperations *prometheus.Desc

	// Infra cache descriptors — only emitted when infraEnabled.
	infraRTT *prometheus.Desc
	infraRTO *prometheus.Desc

	// Per-upstream health flags (#581) — same opt-in switch as the RTT/RTO pair
	// above, because they have the same shape and the same per-upstream
	// cardinality.
	infraHostLame       *prometheus.Desc
	infraHostDNSSECLame *prometheus.Desc
	infraHostEDNSBroken *prometheus.Desc

	infraEnabled bool

	// DNSBL query-stats + local-data descriptors (#209) — only emitted when
	// qstatsEnabled (--exporter.enable-unbound-qstats). Every one of these is
	// a GAUGE: the underlying qstats backend is a rolling 7-day window that
	// can and does decrease (logger.py truncates it hourly, and `qstats
	// reset` truncates it entirely), so a counter would read that as a
	// phantom reset.
	qstatsEnabledDesc  *prometheus.Desc
	dnsblBlocklistSize *prometheus.Desc
	qstatsQueries7d    *prometheus.Desc
	qstatsQueriesTotal *prometheus.Desc
	qstatsStartTime    *prometheus.Desc
	localZones         *prometheus.Desc
	localDataRecords   *prometheus.Desc
	insecureDomains    *prometheus.Desc

	qstatsEnabled bool

	// Top-domain leaderboards (#587), each behind its own bounded inventory. See
	// the const block below for why they are two inventories and one metric.
	qstatsTopDomains *prometheus.Desc
	cardinalityCap   *prometheus.Desc

	topPassed  *boundedInventory[string, int64]
	topBlocked *boundedInventory[string, int64]

	// now is the clock the leaderboard inventories age against, injectable so a
	// test can drive retirement without sleeping.
	now func() time.Time

	subsystem string
	instance  string
}

// Bounds on the top-domain leaderboards (#587).
//
// The KEY CAP is not stated here: it is opnsense.UnboundTopDomainsMax, which is
// also the {max} row limit in the endpoint URL. One number, because {max} binds
// straight to the backend's SQL LIMIT and is therefore a hard ceiling on what can
// ever reach us — a second, larger cap here would be decorative. See that const
// for the full reasoning, including why neither is a CLI flag.
const (
	// unboundTopDomainTTL retires a domain that has not appeared in the
	// leaderboard for five minutes — deliberately much shorter than
	// zenarmorDeviceTTL's 24h, because the two inventories answer different
	// questions. The Zenarmor one is a device PICKER, where an entry that visited
	// this morning is still worth offering tonight. This one mirrors a payload
	// that arrives complete and pre-truncated on every poll, so a long TTL would
	// not preserve anything useful; it would OSSIFY the budget, letting the first
	// poll's 512 domains hold every slot while genuinely-top newcomers are refused
	// for the rest of the day. Five minutes is roughly five polls at the default
	// interval: long enough that a domain oscillating around the cut-off does not
	// flap its series every scrape, short enough that the budget turns over.
	//
	// A domain still in the inventory but absent from the current payload keeps
	// its last count for up to this long. That staleness is deliberate and cheap:
	// the value is an aggregate over a SEVEN-DAY rolling window, so five minutes
	// is 0.05% of it.
	unboundTopDomainTTL = 5 * time.Minute

	// Family label values for the refusal counter. Code-defined constants, never
	// wire values — a label value must never come off the wire on the one metric
	// whose job is to report that wire values are being refused.
	unboundFamilyTopPassed  = "top_domain_passed"
	unboundFamilyTopBlocked = "top_domain_blocked"
)

func init() {
	collectorInstances = append(collectorInstances, &unboundDNSCollector{
		subsystem: UnboundDNSSubsystem,
	})
}

func (c *unboundDNSCollector) Name() string {
	return c.subsystem
}

func (c *unboundDNSCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	if c.now == nil {
		c.now = time.Now
	}
	c.setTopDomainBounds(opnsense.UnboundTopDomainsMax, unboundTopDomainTTL)

	c.uptime = buildPrometheusDesc(c.subsystem, "uptime_seconds",
		"Uptime of the unbound DNS service in seconds",
		nil,
	)

	// Counters without extra labels
	c.queriesTotal = buildPrometheusDesc(c.subsystem, "queries_total",
		"Total number of queries received",
		nil,
	)
	c.cacheHitsTotal = buildPrometheusDesc(c.subsystem, "cache_hits_total",
		"Total number of cache hits",
		nil,
	)
	c.cacheMissTotal = buildPrometheusDesc(c.subsystem, "cache_miss_total",
		"Total number of cache misses",
		nil,
	)
	c.prefetchTotal = buildPrometheusDesc(c.subsystem, "prefetch_total",
		"Total number of cache prefetches",
		nil,
	)
	c.expiredTotal = buildPrometheusDesc(c.subsystem, "expired_total",
		"Total number of expired entries served",
		nil,
	)
	c.recursiveReplies = buildPrometheusDesc(c.subsystem, "recursive_replies_total",
		"Total number of recursive replies sent",
		nil,
	)
	c.queriesTimedOutTotal = buildPrometheusDesc(c.subsystem, "queries_timed_out_total",
		"Total number of queries that timed out",
		nil,
	)
	c.queriesIPRatelimited = buildPrometheusDesc(c.subsystem, "queries_ip_ratelimited_total",
		"Total number of queries that were IP rate limited",
		nil,
	)
	c.answersSecureTotal = buildPrometheusDesc(c.subsystem, "answers_secure_total",
		"Total number of DNSSEC secure answers",
		nil,
	)
	c.answersBogusTotal = buildPrometheusDesc(c.subsystem, "answers_bogus_total",
		"Total number of DNSSEC bogus answers",
		nil,
	)
	c.rrsetBogusTotal = buildPrometheusDesc(c.subsystem, "rrset_bogus_total",
		"Total number of DNSSEC bogus rrsets",
		nil,
	)

	// Query drop/limit counters and error reporting (#237). These are base
	// statistics — populated even with extended-statistics: no, the 26.7 default.
	c.queriesDiscardTimeoutTotal = buildPrometheusDesc(c.subsystem, "queries_discard_timeout_total",
		"Total number of queries discarded after timing out waiting for a reply",
		nil,
	)
	c.queriesWaitLimitTotal = buildPrometheusDesc(c.subsystem, "queries_wait_limit_total",
		"Total number of queries dropped because the per-IP wait limit was reached",
		nil,
	)
	c.queriesReplyAddrLimitTotal = buildPrometheusDesc(c.subsystem, "queries_replyaddr_limit_total",
		"Total number of queries dropped because the per-reply-address rate limit was reached",
		nil,
	)
	c.dnsErrorReportsTotal = buildPrometheusDesc(c.subsystem, "dns_error_reports_total",
		"Total number of RFC 9567 DNS error reports generated",
		nil,
	)

	// Counters with labels
	c.queriesByType = buildPrometheusDesc(c.subsystem, "queries_by_type_total",
		"Total queries by DNS record type",
		[]string{"type"},
	)
	c.queriesByProto = buildPrometheusDesc(c.subsystem, "queries_by_protocol_total",
		"Total queries by protocol",
		[]string{"protocol"},
	)
	c.answersByRcode = buildPrometheusDesc(c.subsystem, "answers_by_rcode_total",
		"Total answers by response code",
		[]string{"rcode"},
	)
	c.unwantedTotal = buildPrometheusDesc(c.subsystem, "unwanted_total",
		"Total number of unwanted queries or replies",
		[]string{"type"},
	)
	c.queryFlagsTotal = buildPrometheusDesc(c.subsystem, "query_flags_total",
		"Total queries by DNS flag",
		[]string{"flag"},
	)
	c.ednsTotal = buildPrometheusDesc(c.subsystem, "edns_total",
		"Total EDNS queries by type",
		[]string{"type"},
	)

	// Gauges without extra labels
	c.requestListAvg = buildPrometheusDesc(c.subsystem, "request_list_avg",
		"Average number of requests in the internal request list",
		nil,
	)
	c.requestListMax = buildPrometheusDesc(c.subsystem, "request_list_max",
		"Maximum number of requests in the internal request list",
		nil,
	)
	c.recursionTimeAvg = buildPrometheusDesc(c.subsystem, "recursion_time_avg_seconds",
		"Average recursion time in seconds",
		nil,
	)
	c.recursionTimeMedian = buildPrometheusDesc(c.subsystem, "recursion_time_median_seconds",
		"Median recursion time in seconds",
		nil,
	)

	// Gauges with labels
	c.cacheCount = buildPrometheusDesc(c.subsystem, "cache_count",
		"Number of entries in cache by cache type",
		[]string{"cache"},
	)
	c.memoryBytes = buildPrometheusDesc(c.subsystem, "memory_bytes",
		"Memory usage in bytes by component",
		[]string{"component"},
	)
	c.requestListCurrent = buildPrometheusDesc(c.subsystem, "request_list_current",
		"Current number of requests in the internal request list by scope",
		[]string{"scope"},
	)

	// Counters without extra labels (request list)
	c.requestListOverwritten = buildPrometheusDesc(c.subsystem, "request_list_overwritten_total",
		"Total number of request list entries overwritten by newer entries",
		nil,
	)
	c.requestListExceeded = buildPrometheusDesc(c.subsystem, "request_list_exceeded_total",
		"Total number of request list entries that exceeded the maximum",
		nil,
	)

	c.tcpUsage = buildPrometheusDesc(c.subsystem, "tcp_usage_ratio",
		"TCP connection usage ratio for the DNS resolver (0.0 to 1.0)",
		nil,
	)

	c.blocklistEnabled = buildPrometheusDesc(c.subsystem, "blocklist_enabled",
		"Whether the DNS blocklist is enabled (1 = enabled, 0 = disabled)",
		nil,
	)

	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the service is running (1 = running, 0 = stopped/disabled)",
		nil,
	)

	// Reply-time histogram (#581). A real histogram, not per-bucket gauges:
	// unbound's buckets are cumulative-since-start counters and the client has
	// already made them cumulative in the ascending sense Prometheus needs, so
	// histogram_quantile() over rate(..._bucket[...]) answers "what is my DNS p99"
	// correctly. _sum is real too — see UnboundRecursionHistogram for how it is
	// recovered from the mean unbound divides it out of.
	c.recursionHistogram = buildPrometheusDesc(c.subsystem, "recursion_time_seconds",
		"How long Unbound's recursive lookups took, bucketed - the p50/p99 companion to the "+
			"recursion_time_avg_seconds and recursion_time_median_seconds gauges. Buckets are "+
			"unbound's own: exponential, doubling from 1us to 2^19s. Cumulative since the "+
			"resolver started, so query it through rate(). "+
			"ONLY EXISTS WHEN THE RESOLVER RUNS WITH extended-statistics: yes, which is OFF by "+
			"default from OPNsense 26.7 - unbound does not compute the histogram's output at all "+
			"otherwise, and the exporter emits no series rather than a fabricated empty one. "+
			"The _sum is reconstructed by multiplying unbound's reported mean back by this "+
			"histogram's own count, which is exact to the microsecond that mean is printed at; "+
			"unbound never publishes the accumulated total directly.",
		nil,
	)
	c.validationOperations = buildPrometheusDesc(c.subsystem, "validation_operations_total",
		"RRSIG verification operations the DNSSEC validator has attempted, counted whether they "+
			"passed or failed (unbound's num.valops). This is the denominator answers_secure_total "+
			"and answers_bogus_total lack: a validator doing heavy work for few secure answers is a "+
			"different problem from one doing none at all, and the two are indistinguishable "+
			"without it. Extended-statistics sourced, so absent when the box runs "+
			"extended-statistics: no (the OPNsense 26.7 default).",
		nil,
	)

	c.infraRTT = buildPrometheusDesc(c.subsystem, "infra_rtt_seconds",
		"Smoothed round-trip time to an upstream server in Unbound's infra cache. Only emitted when --exporter.enable-unbound-infra is set.",
		[]string{"ip", "host"},
	)
	c.infraRTO = buildPrometheusDesc(c.subsystem, "infra_rto_seconds",
		"Retransmission timeout for an upstream server in Unbound's infra cache. Only emitted when --exporter.enable-unbound-infra is set.",
		[]string{"ip", "host"},
	)

	// Per-upstream health flags (#581). These answer the failure the RTT/RTO pair
	// above structurally CANNOT: once Unbound marks an upstream lame it stops
	// asking it, so that upstream's timing series stays perfect precisely because
	// it is no longer being used.
	c.infraHostLame = buildPrometheusDesc(c.subsystem, "infra_host_lame",
		"Whether Unbound has marked an upstream server lame - not authoritative for the zone it "+
			"was asked about - by lameness kind (1 = lame, 0 = fine). kind=recursion means the "+
			"server answers by recursing on our behalf instead of serving the zone; kind=type_a and "+
			"kind=other split lameness by query type, because a server can serve A records fine and "+
			"be lame for everything else. THIS IS THE SIGNAL RTT CANNOT CARRY: Unbound stops "+
			"querying a lame server, so its RTT stays healthy while resolution through it fails. "+
			"Only emitted when --exporter.enable-unbound-infra is set.",
		[]string{"ip", "host", "kind"},
	)
	c.infraHostDNSSECLame = buildPrometheusDesc(c.subsystem, "infra_host_dnssec_lame",
		"Whether Unbound has marked an upstream server DNSSEC-lame (1 = lame, 0 = fine): it "+
			"answers the zone but will not serve the DNSSEC records needed to validate those "+
			"answers. Tracked separately from infra_host_lame because Unbound tracks it separately "+
			"and it fails differently - queries succeed, validation does not. Only emitted when "+
			"--exporter.enable-unbound-infra is set.",
		[]string{"ip", "host"},
	)
	c.infraHostEDNSBroken = buildPrometheusDesc(c.subsystem, "infra_host_edns_broken",
		"Whether Unbound has determined that EDNS queries or replies are being dropped in transit "+
			"to an upstream server (1 = broken, 0 = fine), from its cached EDNS version for that "+
			"host. Distinct from lameness: the server answers, but every EDNS-bearing exchange with "+
			"it is eaten somewhere on the path, which silently disables DNSSEC and forces "+
			"fallbacks. Usually a middlebox or MTU problem rather than the server itself. Only "+
			"emitted when --exporter.enable-unbound-infra is set.",
		[]string{"ip", "host"},
	)

	// DNSBL query-stats + local-data (#209). Only emitted when
	// --exporter.enable-unbound-qstats is set: the query-stats backend is
	// expensive (configd spawns python+pandas+DuckDB per call, ~1s).
	c.qstatsEnabledDesc = buildPrometheusDesc(c.subsystem, "qstats_enabled",
		"Whether Unbound query-stats logging (general.stats) is on (1 = enabled, 0 = disabled). Only emitted when --exporter.enable-unbound-qstats is set.",
		nil,
	)
	c.dnsblBlocklistSize = buildPrometheusDesc(c.subsystem, "dnsbl_blocklist_size",
		"Number of entries in the currently loaded DNSBL blocklist. Gauge: reflects whatever list is loaded right now. Only emitted when --exporter.enable-unbound-qstats is set and query-stats logging is on.",
		nil,
	)
	c.qstatsQueries7d = buildPrometheusDesc(c.subsystem, "qstats_queries_7d",
		"DNSBL query-stats outcome totals over Unbound's rolling query-stats window (typically the last 7 days), by result. Gauge, not a counter: the underlying window is truncated hourly and can decrease. Only emitted when --exporter.enable-unbound-qstats is set and query-stats logging is on.",
		[]string{"result"},
	)
	c.qstatsQueriesTotal = buildPrometheusDesc(c.subsystem, "qstats_queries_total_7d",
		"Total DNS queries over Unbound's rolling query-stats window. Gauge, not a counter, for the same reason as qstats_queries_7d. Only emitted when --exporter.enable-unbound-qstats is set and query-stats logging is on.",
		nil,
	)
	c.qstatsStartTime = buildPrometheusDesc(c.subsystem, "qstats_start_time_timestamp_seconds",
		"Unix timestamp the current query-stats rolling window starts from. A jump forward beyond the expected daily roll-off signals the underlying qstats database was reset. Only emitted when --exporter.enable-unbound-qstats is set and query-stats logging is on.",
		nil,
	)
	c.localZones = buildPrometheusDesc(c.subsystem, "local_zones",
		"Number of configured Unbound local zones, by zone type. Only emitted when --exporter.enable-unbound-qstats is set.",
		[]string{"type"},
	)
	c.localDataRecords = buildPrometheusDesc(c.subsystem, "local_data_records",
		"Total number of configured Unbound local-data resource records. Only emitted when --exporter.enable-unbound-qstats is set.",
		nil,
	)
	c.insecureDomains = buildPrometheusDesc(c.subsystem, "insecure_domains",
		"Number of domains configured as DNSSEC-insecure in Unbound. Only emitted when --exporter.enable-unbound-qstats is set.",
		nil,
	)

	// Top-domain leaderboards (#587). ONE metric with a result label rather than
	// two metrics, mirroring the qstats_queries_7d{result} totals it is the
	// per-domain breakdown of, so the two can be divided against each other
	// without a join across metric names.
	c.qstatsTopDomains = buildPrometheusDesc(c.subsystem, "qstats_top_domain_queries_7d",
		"Queries for one domain over Unbound's rolling query-stats window (typically 7 days), for "+
			"the busiest domains only, split by outcome: result=passed is the top-N of queries "+
			"Unbound answered, result=blocked the top-N a DNSBL policy blocked - the pi-hole-style "+
			"leaderboard. A domain can appear under both, since some queries for it may predate the "+
			"policy that now blocks it. Gauge, not a counter: the window is truncated hourly and a "+
			"qstats reset empties it, so these totals decrease. "+
			"BOUNDED ON BOTH AXES and truncated by design - the API is asked for at most 512 rows "+
			"per outcome, at most 512 domains are tracked per outcome, and a domain is retired 5 "+
			"minutes after it last appeared. This is the busiest domains, never all of them, and "+
			"summing it does not reconstruct qstats_queries_7d. Domains carry unbound's trailing "+
			"root dot. Refusals past the cap surface as cardinality_capped_total; a rising refusal "+
			"count means something is minting domains faster than the cap allows (random-subdomain "+
			"or DNS-tunnelling traffic does exactly this) and the leaderboard below it is no longer "+
			"the real top-N. Only emitted when --exporter.enable-unbound-qstats is set and "+
			"query-stats logging is on.",
		[]string{"domain", "result"},
	)
	c.cardinalityCap = buildPrometheusDesc(c.subsystem, "cardinality_capped_total",
		"Domains refused their own series because the leaderboard already held its full key "+
			"budget when they were first seen. Non-zero and rising means the top-N is saturated "+
			"and no longer reflects the real busiest domains - the usual cause is "+
			"random-subdomain or DNS-tunnelling traffic churning the leaderboard, which is worth "+
			"looking at in its own right. There is deliberately no companion gauge for the live "+
			"key count: count() over qstats_top_domain_queries_7d derives it exactly.",
		[]string{"family"},
	)
}

// setTopDomainBounds (re)builds the leaderboard inventories with the given key
// budget and retirement window. Called from Register with the production values;
// exists as a seam so a test can drive the cap and the TTL without a 512-domain
// fixture or a five-minute sleep.
func (c *unboundDNSCollector) setTopDomainBounds(max int, ttl time.Duration) {
	c.topPassed = newBoundedInventory[string, int64](max, ttl, strings.Compare)
	c.topBlocked = newBoundedInventory[string, int64](max, ttl, strings.Compare)
}

// SetInfraEnabled toggles the per-upstream infra cache metrics
// (--exporter.enable-unbound-infra).
func (c *unboundDNSCollector) SetInfraEnabled(enabled bool) {
	c.infraEnabled = enabled
}

// SetQStatsEnabled toggles the DNSBL query-stats totals, blocklist size and
// local-zone/data/insecure-domain rider metrics (--exporter.enable-unbound-qstats, #209).
func (c *unboundDNSCollector) SetQStatsEnabled(enabled bool) {
	c.qstatsEnabled = enabled
}

func (c *unboundDNSCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.uptime
	ch <- c.queriesTotal
	ch <- c.cacheHitsTotal
	ch <- c.cacheMissTotal
	ch <- c.prefetchTotal
	ch <- c.expiredTotal
	ch <- c.recursiveReplies
	ch <- c.queriesTimedOutTotal
	ch <- c.queriesIPRatelimited
	ch <- c.answersSecureTotal
	ch <- c.answersBogusTotal
	ch <- c.rrsetBogusTotal
	ch <- c.queriesDiscardTimeoutTotal
	ch <- c.queriesWaitLimitTotal
	ch <- c.queriesReplyAddrLimitTotal
	ch <- c.dnsErrorReportsTotal
	ch <- c.queriesByType
	ch <- c.queriesByProto
	ch <- c.answersByRcode
	ch <- c.unwantedTotal
	ch <- c.queryFlagsTotal
	ch <- c.ednsTotal
	ch <- c.requestListAvg
	ch <- c.requestListMax
	ch <- c.recursionTimeAvg
	ch <- c.recursionTimeMedian
	ch <- c.cacheCount
	ch <- c.memoryBytes
	ch <- c.requestListCurrent
	ch <- c.requestListOverwritten
	ch <- c.requestListExceeded
	ch <- c.tcpUsage
	ch <- c.blocklistEnabled
	ch <- c.serviceRunning
	ch <- c.recursionHistogram
	ch <- c.validationOperations
	ch <- c.infraRTT
	ch <- c.infraRTO
	ch <- c.infraHostLame
	ch <- c.infraHostDNSSECLame
	ch <- c.infraHostEDNSBroken
	ch <- c.qstatsEnabledDesc
	ch <- c.dnsblBlocklistSize
	ch <- c.qstatsQueries7d
	ch <- c.qstatsQueriesTotal
	ch <- c.qstatsStartTime
	ch <- c.localZones
	ch <- c.localDataRecords
	ch <- c.insecureDomains
	ch <- c.qstatsTopDomains
	ch <- c.cardinalityCap
}

// emitServiceRunning fetches the unbound service running-state and emits the
// service_running gauge. Kept separate so it is emitted both on the normal path
// and when the stats envelope is unavailable (#90).
func (c *unboundDNSCollector) emitServiceRunning(ch chan<- prometheus.Metric, client *opnsense.Client) {
	status, sErr := client.FetchServiceStatus("unboundServiceStatus")
	if sErr != nil {
		c.log.Warn("failed to fetch service status", "err", sErr)
		return
	}
	val := 0.0
	if status == "running" {
		val = 1.0
	}
	ch <- prometheus.MustNewConstMetric(
		c.serviceRunning, prometheus.GaugeValue,
		val, c.instance,
	)
}

// updateExtended emits every series sourced from unbound's EXTENDED statistics
// sections (data.num, data.mem, data.msg, data.rrset, data.infra, data.key,
// data.unwanted). Called only when UnboundDNSOverview.ExtendedPresent is true —
// i.e. the box actually reported those sections (`extended-statistics: yes`).
func (c *unboundDNSCollector) updateExtended(data opnsense.UnboundDNSOverview, ch chan<- prometheus.Metric) {
	// DNSSEC (data.num.answer / data.num.rrset)
	ch <- prometheus.MustNewConstMetric(
		c.answersSecureTotal, prometheus.CounterValue,
		float64(data.AnswerSecureTotal), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.answersBogusTotal, prometheus.CounterValue,
		float64(data.AnswerBogusTotal), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.rrsetBogusTotal, prometheus.CounterValue,
		float64(data.RrsetBogusTotal), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.validationOperations, prometheus.CounterValue,
		float64(data.ValidationOperations), c.instance,
	)

	// Queries by type (data.num.query.type)
	for qtype, count := range data.QueryTypesByType {
		ch <- prometheus.MustNewConstMetric(
			c.queriesByType, prometheus.CounterValue,
			float64(count), qtype, c.instance,
		)
	}

	// Queries by protocol (data.num.query.*)
	protocols := map[string]int64{
		"tcp":    data.QueryTCP,
		"tcpout": data.QueryTCPOut,
		"udpout": data.QueryUDPOut,
		"tls":    data.QueryTLS,
		"ipv6":   data.QueryIPv6,
		"https":  data.QueryHTTPS,
	}
	for proto, count := range protocols {
		ch <- prometheus.MustNewConstMetric(
			c.queriesByProto, prometheus.CounterValue,
			float64(count), proto, c.instance,
		)
	}

	// Answers by rcode (data.num.answer.rcode)
	for rcode, count := range data.AnswerRcodesByRcode {
		ch <- prometheus.MustNewConstMetric(
			c.answersByRcode, prometheus.CounterValue,
			float64(count), rcode, c.instance,
		)
	}

	// Unwanted (data.unwanted)
	ch <- prometheus.MustNewConstMetric(
		c.unwantedTotal, prometheus.CounterValue,
		float64(data.UnwantedQueries), "queries", c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.unwantedTotal, prometheus.CounterValue,
		float64(data.UnwantedReplies), "replies", c.instance,
	)

	// Query flags (data.num.query.flags)
	for flag, count := range data.FlagsByFlag {
		ch <- prometheus.MustNewConstMetric(
			c.queryFlagsTotal, prometheus.CounterValue,
			float64(count), flag, c.instance,
		)
	}

	// EDNS (data.num.query.edns)
	ch <- prometheus.MustNewConstMetric(
		c.ednsTotal, prometheus.CounterValue,
		float64(data.EdnsPresent), "present", c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ednsTotal, prometheus.CounterValue,
		float64(data.EdnsDO), "DO", c.instance,
	)

	// Cache counts (data.rrset/msg/infra/key .cache.count)
	caches := map[string]int64{
		"rrset":   data.CacheRrsetCount,
		"message": data.CacheMessageCount,
		"infra":   data.CacheInfraCount,
		"key":     data.CacheKeyCount,
	}
	for cache, count := range caches {
		ch <- prometheus.MustNewConstMetric(
			c.cacheCount, prometheus.GaugeValue,
			float64(count), cache, c.instance,
		)
	}

	// Memory bytes (data.mem)
	memComponents := map[string]int64{
		"rrset_cache":   data.MemCacheRrset,
		"message_cache": data.MemCacheMessage,
		"iterator":      data.MemModIterator,
		"validator":     data.MemModValidator,
		"respip":        data.MemModRespip,
		"streamwait":    data.MemStreamwait,
	}
	for component, bytes := range memComponents {
		ch <- prometheus.MustNewConstMetric(
			c.memoryBytes, prometheus.GaugeValue,
			float64(bytes), component, c.instance,
		)
	}
}

func (c *unboundDNSCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchUnboundOverview()
	if err != nil {
		return err
	}

	// When unbound-control is unavailable (Unbound stopped/restarting, or disabled
	// on a dnsmasq-only box) the stats envelope is not "ok". Emit only the
	// running-state signal and skip the ~60 stats series entirely — emitting them
	// as zero would look like real zero-traffic and corrupt rate() with phantom
	// resets (#90).
	if !data.Present {
		c.emitServiceRunning(ch, client)
		return nil
	}

	// Uptime gauge
	ch <- prometheus.MustNewConstMetric(
		c.uptime,
		prometheus.GaugeValue,
		data.UptimeSeconds,
		c.instance,
	)

	// Counters without extra labels
	ch <- prometheus.MustNewConstMetric(
		c.queriesTotal, prometheus.CounterValue,
		float64(data.QueriesTotal), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.cacheHitsTotal, prometheus.CounterValue,
		float64(data.CacheHits), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.cacheMissTotal, prometheus.CounterValue,
		float64(data.CacheMiss), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.prefetchTotal, prometheus.CounterValue,
		float64(data.Prefetch), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.expiredTotal, prometheus.CounterValue,
		float64(data.ExpiredTotal), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.recursiveReplies, prometheus.CounterValue,
		float64(data.RecursiveReplies), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.queriesTimedOutTotal, prometheus.CounterValue,
		float64(data.QueriesTimedOut), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.queriesIPRatelimited, prometheus.CounterValue,
		float64(data.QueriesIPRateLimited), c.instance,
	)

	// Query drop/limit counters and error reporting (#237). Base statistics —
	// populated even with extended-statistics: no, so these are emitted
	// unconditionally alongside the other base counters above, gated only on
	// data.Present like the rest of this block.
	ch <- prometheus.MustNewConstMetric(
		c.queriesDiscardTimeoutTotal, prometheus.CounterValue,
		float64(data.QueriesDiscardTimeout), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.queriesWaitLimitTotal, prometheus.CounterValue,
		float64(data.QueriesWaitLimit), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.queriesReplyAddrLimitTotal, prometheus.CounterValue,
		float64(data.QueriesReplyAddrLimit), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.dnsErrorReportsTotal, prometheus.CounterValue,
		float64(data.DNSErrorReports), c.instance,
	)

	// Extended statistics. Unbound only reports data.num/data.mem/data.msg/… when it
	// runs with `extended-statistics: yes` — the OPNsense 26.1 default, but OFF by
	// default on 26.7, where those sections are simply absent from the payload. Skip
	// every series they feed when they are: emitting ~40 zeros would look like real
	// zero-traffic and corrupt rate() with phantom resets, the same failure class as
	// the stats-envelope gate above (#90). Re-enabling extended-statistics on the box
	// brings them all straight back.
	if data.ExtendedPresent {
		c.updateExtended(data, ch)
	}

	// Reply-time histogram. Gated on ITS OWN presence flag rather than on
	// ExtendedPresent: it is a separate section on the wire (data.histogram, not
	// data.num), and borrowing a sibling section's flag is exactly how an all-zero
	// 40-bucket histogram gets published for a resolver that never reported one.
	if h := data.RecursionHistogram; h.Present {
		ch <- prometheus.MustNewConstHistogram(
			c.recursionHistogram, h.Count, h.Sum, h.Buckets, c.instance,
		)
	}

	// Gauges without extra labels
	ch <- prometheus.MustNewConstMetric(
		c.requestListAvg, prometheus.GaugeValue,
		data.RequestListAvg, c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.requestListMax, prometheus.GaugeValue,
		float64(data.RequestListMax), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.recursionTimeAvg, prometheus.GaugeValue,
		data.RecursionTimeAvg, c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.recursionTimeMedian, prometheus.GaugeValue,
		data.RecursionTimeMedian, c.instance,
	)

	// Request list current
	ch <- prometheus.MustNewConstMetric(
		c.requestListCurrent, prometheus.GaugeValue,
		float64(data.RequestListCurrentAll), "all", c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.requestListCurrent, prometheus.GaugeValue,
		float64(data.RequestListCurrentUser), "user", c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.requestListCurrent, prometheus.GaugeValue,
		float64(data.RequestListCurrentReplies), "replies", c.instance,
	)

	// Request list counters
	ch <- prometheus.MustNewConstMetric(
		c.requestListOverwritten, prometheus.CounterValue,
		float64(data.RequestListOverwritten), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.requestListExceeded, prometheus.CounterValue,
		float64(data.RequestListExceeded), c.instance,
	)

	ch <- prometheus.MustNewConstMetric(
		c.tcpUsage, prometheus.GaugeValue,
		data.TCPUsage, c.instance,
	)

	enabled, blErr := client.FetchUnboundBlockListStatus()
	if blErr != nil {
		c.log.Warn("failed to fetch unbound blocklist status", "err", blErr)
	} else {
		val := 0.0
		if enabled {
			val = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			c.blocklistEnabled, prometheus.GaugeValue,
			val, c.instance,
		)
	}

	c.emitServiceRunning(ch, client)

	if c.infraEnabled {
		infra, ierr := client.FetchUnboundInfra()
		if ierr != nil {
			c.log.Warn("failed to fetch unbound infra cache", "err", ierr)
		} else {
			for _, h := range infra.Hosts {
				ch <- prometheus.MustNewConstMetric(
					c.infraRTT, prometheus.GaugeValue,
					h.RTTMilliseconds/1000.0, h.IP, h.Host, c.instance,
				)
				ch <- prometheus.MustNewConstMetric(
					c.infraRTO, prometheus.GaugeValue,
					h.RTOMilliseconds/1000.0, h.IP, h.Host, c.instance,
				)

				// Health flags (#581). Emitted for every host, including a healthy
				// one reading 0 - an omitted series and a healthy series look
				// identical on a graph and only one of them is true, and a lameness
				// flag that appears only once it fires has no baseline to alert
				// against.
				for kind, lame := range map[string]bool{
					"recursion": h.RecursionLame,
					"type_a":    h.TypeALame,
					"other":     h.OtherLame,
				} {
					ch <- prometheus.MustNewConstMetric(
						c.infraHostLame, prometheus.GaugeValue,
						boolToFloat64(lame), h.IP, h.Host, kind, c.instance,
					)
				}
				ch <- prometheus.MustNewConstMetric(
					c.infraHostDNSSECLame, prometheus.GaugeValue,
					boolToFloat64(h.DNSSECLame), h.IP, h.Host, c.instance,
				)
				ch <- prometheus.MustNewConstMetric(
					c.infraHostEDNSBroken, prometheus.GaugeValue,
					boolToFloat64(h.EDNSBroken), h.IP, h.Host, c.instance,
				)
			}
		}
	}

	if c.qstatsEnabled {
		c.updateQStats(ctx, client, ch)
	}

	return nil
}

// updateQStats emits the #209 DNSBL query-stats totals, blocklist size and
// local-zone/data/insecure-domain rider metrics. Only called when
// --exporter.enable-unbound-qstats is set.
func (c *unboundDNSCollector) updateQStats(_ context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) {
	stats, qErr := client.FetchUnboundQueryStats()
	if qErr != nil {
		c.log.Warn("failed to fetch unbound query stats", "err", qErr)
	} else {
		qstatsEnabledVal := 0.0
		if stats.Enabled {
			qstatsEnabledVal = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			c.qstatsEnabledDesc, prometheus.GaugeValue,
			qstatsEnabledVal, c.instance,
		)

		// TotalsPresent is false when query-stats logging is off — the
		// expensive totals call was skipped entirely rather than paying for it
		// just to derive zeros (the #90 lesson). Emitting the rest of these as
		// zero here would look like real zero-traffic and corrupt downstream
		// analysis even though these series are gauges, so skip them.
		if stats.TotalsPresent {
			ch <- prometheus.MustNewConstMetric(
				c.dnsblBlocklistSize, prometheus.GaugeValue,
				float64(stats.BlocklistSize), c.instance,
			)
			ch <- prometheus.MustNewConstMetric(
				c.qstatsQueriesTotal, prometheus.GaugeValue,
				float64(stats.QueriesTotal7d), c.instance,
			)
			ch <- prometheus.MustNewConstMetric(
				c.qstatsStartTime, prometheus.GaugeValue,
				float64(stats.StartTimeSeconds), c.instance,
			)

			results := map[string]int64{
				"passed":   stats.PassedTotal7d,
				"resolved": stats.ResolvedTotal7d,
				"blocked":  stats.BlockedTotal7d,
				"local":    stats.LocalTotal7d,
			}
			for result, count := range results {
				ch <- prometheus.MustNewConstMetric(
					c.qstatsQueries7d, prometheus.GaugeValue,
					float64(count), result, c.instance,
				)
			}

			c.updateTopDomains(stats, ch)
		}
	}

	// Refusal counters are emitted whether or not this poll produced a payload:
	// they are in-process state, and a counter that disappears while the box has
	// query-stats logging switched off would read as a reset when it came back.
	ch <- prometheus.MustNewConstMetric(
		c.cardinalityCap, prometheus.CounterValue,
		c.topPassed.refused(), unboundFamilyTopPassed, c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.cardinalityCap, prometheus.CounterValue,
		c.topBlocked.refused(), unboundFamilyTopBlocked, c.instance,
	)

	// Rider metrics (#209): cheap, slow-moving unbound-control diagnostics,
	// independent of whether query-stats logging is on.
	localData, lErr := client.FetchUnboundLocalData()
	if lErr != nil {
		c.log.Warn("failed to fetch unbound local zone/data diagnostics", "err", lErr)
		return
	}

	for zoneType, count := range localData.ZonesByType {
		ch <- prometheus.MustNewConstMetric(
			c.localZones, prometheus.GaugeValue,
			float64(count), zoneType, c.instance,
		)
	}
	ch <- prometheus.MustNewConstMetric(
		c.localDataRecords, prometheus.GaugeValue,
		float64(localData.LocalDataRecords), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.insecureDomains, prometheus.GaugeValue,
		float64(localData.InsecureDomains), c.instance,
	)
}

// updateTopDomains folds this poll's two leaderboards into their bounded
// inventories and emits what is currently live (#587).
//
// The inventories are what make this safe to ship default-on where #209 refused
// it. The payload itself is already truncated to UnboundTopDomainsMax rows, so a
// single scrape could never mint more than that many series - but over TIME an
// untracked leaderboard mints a fresh series set on every poll the moment anything
// churns the top-N, which is what random-subdomain and DNS-tunnelling traffic does
// by construction. The inventory bounds the series set ACROSS polls, not within
// one, and counts what it turns away so the truncation is visible rather than
// looking like a quiet network.
//
// The residual risk is real and deliberately accepted: under that churn the budget
// fills with junk and a genuinely busy domain can be refused a series. The refusal
// counter is what makes that state legible - a rising cardinality_capped_total on
// this family means "the leaderboard below is no longer the real top-N", not "the
// exporter is broken".
func (c *unboundDNSCollector) updateTopDomains(stats opnsense.UnboundQueryStats, ch chan<- prometheus.Metric) {
	now := c.now()
	for _, board := range []struct {
		result string
		rows   map[string]int64
		inv    *boundedInventory[string, int64]
	}{
		{"passed", stats.TopPassedDomains, c.topPassed},
		{"blocked", stats.TopBlockedDomains, c.topBlocked},
	} {
		// PRUNE BEFORE ADMITTING, and the discarded return value is the point.
		// boundedInventory frees a retired key's budget slot inside live(), not on
		// a timer, so admitting first would have every new domain refused against a
		// budget still held by entries that expired minutes ago - the inventory
		// would fill once at startup and never turn over again, which is the exact
		// failure TestUnboundDNSCollector_TopDomainsRetired pins. There is no
		// prune-only entry point on the primitive; this is it.
		board.inv.live(now)
		for domain, count := range board.rows {
			board.inv.seen(domain, count, now)
		}
		for _, entry := range board.inv.live(now) {
			ch <- prometheus.MustNewConstMetric(
				c.qstatsTopDomains, prometheus.GaugeValue,
				float64(entry.val), entry.key, board.result, c.instance,
			)
		}
	}
}
