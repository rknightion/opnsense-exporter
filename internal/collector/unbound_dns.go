package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
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

	// Infra cache descriptors — only emitted when infraEnabled.
	infraRTT *prometheus.Desc
	infraRTO *prometheus.Desc

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

	subsystem string
	instance  string
}

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

	c.infraRTT = buildPrometheusDesc(c.subsystem, "infra_rtt_seconds",
		"Smoothed round-trip time to an upstream server in Unbound's infra cache. Only emitted when --exporter.enable-unbound-infra is set.",
		[]string{"ip", "host"},
	)
	c.infraRTO = buildPrometheusDesc(c.subsystem, "infra_rto_seconds",
		"Retransmission timeout for an upstream server in Unbound's infra cache. Only emitted when --exporter.enable-unbound-infra is set.",
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
	c.qstatsStartTime = buildPrometheusDesc(c.subsystem, "qstats_start_time_seconds",
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
	ch <- c.infraRTT
	ch <- c.infraRTO
	ch <- c.qstatsEnabledDesc
	ch <- c.dnsblBlocklistSize
	ch <- c.qstatsQueries7d
	ch <- c.qstatsQueriesTotal
	ch <- c.qstatsStartTime
	ch <- c.localZones
	ch <- c.localDataRecords
	ch <- c.insecureDomains
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
		}
	}

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
