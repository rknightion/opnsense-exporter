package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type mbufCollector struct {
	log *slog.Logger

	mbufCurrent       *prometheus.Desc
	mbufCache         *prometheus.Desc
	mbufTotal         *prometheus.Desc
	mbufMax           *prometheus.Desc
	clusterCurrent    *prometheus.Desc
	clusterCache      *prometheus.Desc
	clusterTotal      *prometheus.Desc
	clusterMax        *prometheus.Desc
	failuresTotal     *prometheus.Desc
	sleepsTotal       *prometheus.Desc
	bytesInUse        *prometheus.Desc
	bytesTotal        *prometheus.Desc
	bytesInCache      *prometheus.Desc
	poolCurrent       *prometheus.Desc
	poolCache         *prometheus.Desc
	poolTotal         *prometheus.Desc
	poolMax           *prometheus.Desc
	sendfileSyscalls  *prometheus.Desc
	sendfileIOCount   *prometheus.Desc
	sendfilePagesSent *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &mbufCollector{
		subsystem: MbufSubsystem,
	})
}

func (c *mbufCollector) Name() string {
	return c.subsystem
}

func (c *mbufCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.mbufCurrent = buildPrometheusDesc(c.subsystem, "current",
		"Current number of mbufs in use",
		nil,
	)
	c.mbufCache = buildPrometheusDesc(c.subsystem, "cache",
		"Number of mbufs in cache",
		nil,
	)
	c.mbufTotal = buildPrometheusDesc(c.subsystem, "total",
		"Total number of mbufs available",
		nil,
	)
	c.mbufMax = buildPrometheusDesc(c.subsystem, "max",
		"Maximum number of mbufs (the mbuf pool's ceiling, mirroring cluster_max). May read 0 on "+
			"OPNsense >=26.1.11, where upstream removed this key -- that means no ceiling was "+
			"reported, not a ceiling of zero, so guard any current/max ratio against a zero "+
			"denominator (#543).",
		nil,
	)
	c.clusterCurrent = buildPrometheusDesc(c.subsystem, "cluster_current",
		"Current number of mbuf clusters in use",
		nil,
	)
	c.clusterCache = buildPrometheusDesc(c.subsystem, "cluster_cache",
		"Number of mbuf clusters in cache",
		nil,
	)
	c.clusterTotal = buildPrometheusDesc(c.subsystem, "cluster_total",
		"Total number of mbuf clusters available",
		nil,
	)
	c.clusterMax = buildPrometheusDesc(c.subsystem, "cluster_max",
		"Maximum number of mbuf clusters",
		nil,
	)
	c.failuresTotal = buildPrometheusDesc(c.subsystem, "failures_total",
		"Total number of mbuf allocation failures by type",
		[]string{"type"},
	)
	c.sleepsTotal = buildPrometheusDesc(c.subsystem, "sleeps_total",
		"Total number of mbuf allocation sleeps by type",
		[]string{"type"},
	)
	c.bytesInUse = buildPrometheusDesc(c.subsystem, "bytes_in_use",
		"Number of bytes of memory currently in use by mbufs",
		nil,
	)
	c.bytesTotal = buildPrometheusDesc(c.subsystem, "bytes_total",
		"Total number of bytes of memory available for mbufs",
		nil,
	)
	c.bytesInCache = buildPrometheusDesc(c.subsystem, "bytes_in_cache",
		"Number of bytes of memory sitting in the mbuf allocator's cache -- already charged to the "+
			"mbuf/cluster/jumbo pools but not currently in use, so available for immediate reuse "+
			"without a new system allocation. Complements bytes_in_use (currently used) and "+
			"bytes_total (the ceiling both draw from) (#579).",
		nil,
	)
	c.poolCurrent = buildPrometheusDesc(c.subsystem, "pool_current",
		"Current number of items in use in this secondary mbuf pool: jumbo9 (9k jumbo clusters), "+
			"jumbo16 (16k jumbo clusters), or packet (the secondary zone that pre-combines an "+
			"mbuf+cluster for m_getcl()). These pools are only reported on OPNsense releases whose "+
			"underlying FreeBSD netstat -m emits them (26.1+); a pool missing from a scrape means the "+
			"box's release predates it, not that the pool is empty -- distinguish via absence, never "+
			"read a missing pool as zero (#579).",
		[]string{"pool"},
	)
	c.poolCache = buildPrometheusDesc(c.subsystem, "pool_cache",
		"Number of items sitting free in this secondary mbuf pool's cache, ready for immediate "+
			"reuse without a new system allocation. For pool=\"packet\" this resolves netstat's "+
			"packet-free field -- its own human-readable text labels the line \"(current/cache)\", "+
			"the same current/cache shape as the jumbo9/jumbo16 pools, just a differently-spelled "+
			"JSON key (#579).",
		[]string{"pool"},
	)
	c.poolTotal = buildPrometheusDesc(c.subsystem, "pool_total",
		"Total number of items ever allocated to this secondary mbuf pool. NEVER reported for "+
			"pool=\"packet\": that zone borrows memory from the mbuf and cluster zones rather than "+
			"owning its own allocation, so upstream's netstat -m has no packet-total key and no "+
			"series is emitted for it (#579).",
		[]string{"pool"},
	)
	c.poolMax = buildPrometheusDesc(c.subsystem, "pool_max",
		"Configured ceiling on this secondary mbuf pool. NEVER reported for pool=\"packet\", for "+
			"the same reason as pool_total. jumbo16's ceiling is read from upstream's jumbo16-limit "+
			"key and normalised onto this same metric even though jumbo9's equivalent key is spelled "+
			"jumbo9-max -- verified against FreeBSD's usr.bin/netstat/mbuf.c: both fields come from an "+
			"otherwise-identical xo_emit format string whose human-readable label reads "+
			"\"(current/cache/total/max)\" in both cases, so the two JSON keys are one quantity under "+
			"an inconsistent upstream name, not two different things (#579).",
		[]string{"pool"},
	)
	c.sendfileSyscalls = buildPrometheusDesc(c.subsystem, "sendfile_syscalls_total",
		"Total number of sendfile syscalls",
		nil,
	)
	c.sendfileIOCount = buildPrometheusDesc(c.subsystem, "sendfile_io_total",
		"Total number of sendfile I/O operations",
		nil,
	)
	c.sendfilePagesSent = buildPrometheusDesc(c.subsystem, "sendfile_pages_sent_total",
		"Total number of pages sent via sendfile",
		nil,
	)
}

func (c *mbufCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.mbufCurrent
	ch <- c.mbufCache
	ch <- c.mbufTotal
	ch <- c.mbufMax
	ch <- c.clusterCurrent
	ch <- c.clusterCache
	ch <- c.clusterTotal
	ch <- c.clusterMax
	ch <- c.failuresTotal
	ch <- c.sleepsTotal
	ch <- c.bytesInUse
	ch <- c.bytesTotal
	ch <- c.bytesInCache
	ch <- c.poolCurrent
	ch <- c.poolCache
	ch <- c.poolTotal
	ch <- c.poolMax
	ch <- c.sendfileSyscalls
	ch <- c.sendfileIOCount
	ch <- c.sendfilePagesSent
}

func (c *mbufCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchMbufStatistics()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(
		c.mbufCurrent,
		prometheus.GaugeValue,
		float64(data.MbufCurrent),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.mbufCache,
		prometheus.GaugeValue,
		float64(data.MbufCache),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.mbufTotal,
		prometheus.GaugeValue,
		float64(data.MbufTotal),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.mbufMax,
		prometheus.GaugeValue,
		float64(data.MbufMax),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.clusterCurrent,
		prometheus.GaugeValue,
		float64(data.ClusterCurrent),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.clusterCache,
		prometheus.GaugeValue,
		float64(data.ClusterCache),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.clusterTotal,
		prometheus.GaugeValue,
		float64(data.ClusterTotal),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.clusterMax,
		prometheus.GaugeValue,
		float64(data.ClusterMax),
		c.instance,
	)

	for typeName, count := range data.FailuresByType {
		ch <- prometheus.MustNewConstMetric(
			c.failuresTotal,
			prometheus.CounterValue,
			float64(count),
			typeName,
			c.instance,
		)
	}

	for typeName, count := range data.SleepsByType {
		ch <- prometheus.MustNewConstMetric(
			c.sleepsTotal,
			prometheus.CounterValue,
			float64(count),
			typeName,
			c.instance,
		)
	}

	ch <- prometheus.MustNewConstMetric(
		c.bytesInUse,
		prometheus.GaugeValue,
		float64(data.BytesInUse),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.bytesTotal,
		prometheus.GaugeValue,
		float64(data.BytesTotal),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.bytesInCache,
		prometheus.GaugeValue,
		float64(data.BytesInCache),
		c.instance,
	)

	// Secondary mbuf pool utilization (#579): jumbo9, jumbo16, packet. Ranging over
	// the maps means a pool the box didn't report (nil in the client, so absent from
	// the map) emits no series at all -- never a fabricated 0.
	for poolName, count := range data.PoolCurrent {
		ch <- prometheus.MustNewConstMetric(
			c.poolCurrent,
			prometheus.GaugeValue,
			float64(count),
			poolName,
			c.instance,
		)
	}
	for poolName, count := range data.PoolCache {
		ch <- prometheus.MustNewConstMetric(
			c.poolCache,
			prometheus.GaugeValue,
			float64(count),
			poolName,
			c.instance,
		)
	}
	for poolName, count := range data.PoolTotal {
		ch <- prometheus.MustNewConstMetric(
			c.poolTotal,
			prometheus.GaugeValue,
			float64(count),
			poolName,
			c.instance,
		)
	}
	for poolName, count := range data.PoolMax {
		ch <- prometheus.MustNewConstMetric(
			c.poolMax,
			prometheus.GaugeValue,
			float64(count),
			poolName,
			c.instance,
		)
	}

	ch <- prometheus.MustNewConstMetric(
		c.sendfileSyscalls,
		prometheus.CounterValue,
		float64(data.SendfileSyscalls),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.sendfileIOCount,
		prometheus.CounterValue,
		float64(data.SendfileIOCount),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.sendfilePagesSent,
		prometheus.CounterValue,
		float64(data.SendfilePagesSent),
		c.instance,
	)

	return nil
}
