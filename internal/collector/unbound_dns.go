package collector

import (
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
}

func (c *unboundDNSCollector) Update(client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchUnboundOverview()
	if err != nil {
		return err
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

	// Queries by type
	for qtype, count := range data.QueryTypesByType {
		ch <- prometheus.MustNewConstMetric(
			c.queriesByType, prometheus.CounterValue,
			float64(count), qtype, c.instance,
		)
	}

	// Queries by protocol
	protocols := map[string]int{
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

	// Answers by rcode
	for rcode, count := range data.AnswerRcodesByRcode {
		ch <- prometheus.MustNewConstMetric(
			c.answersByRcode, prometheus.CounterValue,
			float64(count), rcode, c.instance,
		)
	}

	// Unwanted
	ch <- prometheus.MustNewConstMetric(
		c.unwantedTotal, prometheus.CounterValue,
		float64(data.UnwantedQueries), "queries", c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.unwantedTotal, prometheus.CounterValue,
		float64(data.UnwantedReplies), "replies", c.instance,
	)

	// Query flags
	for flag, count := range data.FlagsByFlag {
		ch <- prometheus.MustNewConstMetric(
			c.queryFlagsTotal, prometheus.CounterValue,
			float64(count), flag, c.instance,
		)
	}

	// EDNS
	ch <- prometheus.MustNewConstMetric(
		c.ednsTotal, prometheus.CounterValue,
		float64(data.EdnsPresent), "present", c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ednsTotal, prometheus.CounterValue,
		float64(data.EdnsDO), "DO", c.instance,
	)

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

	// Cache counts
	caches := map[string]int{
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

	// Memory bytes
	memComponents := map[string]int{
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

	// Request list current
	ch <- prometheus.MustNewConstMetric(
		c.requestListCurrent, prometheus.GaugeValue,
		float64(data.RequestListCurrentAll), "all", c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.requestListCurrent, prometheus.GaugeValue,
		float64(data.RequestListCurrentUser), "user", c.instance,
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

	return nil
}
