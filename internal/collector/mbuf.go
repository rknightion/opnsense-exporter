package collector

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type mbufCollector struct {
	log *slog.Logger

	mbufCurrent       *prometheus.Desc
	mbufCache         *prometheus.Desc
	mbufTotal         *prometheus.Desc
	clusterCurrent    *prometheus.Desc
	clusterCache      *prometheus.Desc
	clusterTotal      *prometheus.Desc
	clusterMax        *prometheus.Desc
	failuresTotal     *prometheus.Desc
	sleepsTotal       *prometheus.Desc
	bytesInUse        *prometheus.Desc
	bytesTotal        *prometheus.Desc
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
	ch <- c.clusterCurrent
	ch <- c.clusterCache
	ch <- c.clusterTotal
	ch <- c.clusterMax
	ch <- c.failuresTotal
	ch <- c.sleepsTotal
	ch <- c.bytesInUse
	ch <- c.bytesTotal
	ch <- c.sendfileSyscalls
	ch <- c.sendfileIOCount
	ch <- c.sendfilePagesSent
}

func (c *mbufCollector) Update(client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
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
