package collector

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type networkDiagCollector struct {
	log *slog.Logger

	// netisr metrics
	netisrDispatched       *prometheus.Desc
	netisrHybridDispatched *prometheus.Desc
	netisrQueued           *prometheus.Desc
	netisrHandled          *prometheus.Desc
	netisrQueueDrops       *prometheus.Desc
	netisrQueueLength      *prometheus.Desc
	netisrQueueWatermark   *prometheus.Desc
	netisrQueueLimit       *prometheus.Desc

	// socket metrics
	socketsActive    *prometheus.Desc
	socketsUnixTotal *prometheus.Desc

	// route metrics
	routesTotal *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &networkDiagCollector{
		subsystem: NetworkDiagSubsystem,
	})
}

func (c *networkDiagCollector) Name() string {
	return c.subsystem
}

func (c *networkDiagCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.netisrDispatched = buildPrometheusDesc(c.subsystem, "netisr_dispatched_total",
		"Total number of netisr dispatches by protocol",
		[]string{"protocol"},
	)
	c.netisrHybridDispatched = buildPrometheusDesc(c.subsystem, "netisr_hybrid_dispatched_total",
		"Total number of netisr hybrid dispatches by protocol",
		[]string{"protocol"},
	)
	c.netisrQueued = buildPrometheusDesc(c.subsystem, "netisr_queued_total",
		"Total number of netisr packets queued by protocol",
		[]string{"protocol"},
	)
	c.netisrHandled = buildPrometheusDesc(c.subsystem, "netisr_handled_total",
		"Total number of netisr packets handled by protocol",
		[]string{"protocol"},
	)
	c.netisrQueueDrops = buildPrometheusDesc(c.subsystem, "netisr_queue_drops_total",
		"Total number of netisr queue drops by protocol",
		[]string{"protocol"},
	)
	c.netisrQueueLength = buildPrometheusDesc(c.subsystem, "netisr_queue_length",
		"Current maximum netisr queue length across workstreams by protocol",
		[]string{"protocol"},
	)
	c.netisrQueueWatermark = buildPrometheusDesc(c.subsystem, "netisr_queue_watermark",
		"High watermark of netisr queue length across workstreams by protocol",
		[]string{"protocol"},
	)
	c.netisrQueueLimit = buildPrometheusDesc(c.subsystem, "netisr_queue_limit",
		"Configured netisr queue limit by protocol",
		[]string{"protocol"},
	)

	c.socketsActive = buildPrometheusDesc(c.subsystem, "sockets_active",
		"Number of active sockets by type",
		[]string{"type"},
	)
	c.socketsUnixTotal = buildPrometheusDesc(c.subsystem, "sockets_unix_total",
		"Total number of active Unix domain sockets",
		nil,
	)

	c.routesTotal = buildPrometheusDesc(c.subsystem, "routes_total",
		"Number of routing table entries by protocol",
		[]string{"proto"},
	)
}

func (c *networkDiagCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.netisrDispatched
	ch <- c.netisrHybridDispatched
	ch <- c.netisrQueued
	ch <- c.netisrHandled
	ch <- c.netisrQueueDrops
	ch <- c.netisrQueueLength
	ch <- c.netisrQueueWatermark
	ch <- c.netisrQueueLimit
	ch <- c.socketsActive
	ch <- c.socketsUnixTotal
	ch <- c.routesTotal
}

func (c *networkDiagCollector) Update(client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	// Fetch netisr statistics
	netisrData, err := client.FetchNetisrStatistics()
	if err != nil {
		return err
	}

	for proto, stats := range netisrData {
		ch <- prometheus.MustNewConstMetric(
			c.netisrDispatched,
			prometheus.CounterValue,
			float64(stats.Dispatched),
			proto,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.netisrHybridDispatched,
			prometheus.CounterValue,
			float64(stats.HybridDispatched),
			proto,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.netisrQueued,
			prometheus.CounterValue,
			float64(stats.Queued),
			proto,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.netisrHandled,
			prometheus.CounterValue,
			float64(stats.Handled),
			proto,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.netisrQueueDrops,
			prometheus.CounterValue,
			float64(stats.QueueDrops),
			proto,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.netisrQueueLength,
			prometheus.GaugeValue,
			float64(stats.Length),
			proto,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.netisrQueueWatermark,
			prometheus.GaugeValue,
			float64(stats.Watermark),
			proto,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.netisrQueueLimit,
			prometheus.GaugeValue,
			float64(stats.QueueLimit),
			proto,
			c.instance,
		)
	}

	// Fetch socket statistics
	socketData, err := client.FetchSocketStatistics()
	if err != nil {
		return err
	}

	for sockType, count := range socketData.ByType {
		ch <- prometheus.MustNewConstMetric(
			c.socketsActive,
			prometheus.GaugeValue,
			float64(count),
			sockType,
			c.instance,
		)
	}

	ch <- prometheus.MustNewConstMetric(
		c.socketsUnixTotal,
		prometheus.GaugeValue,
		float64(socketData.UnixTotal),
		c.instance,
	)

	// Fetch route statistics
	routeData, err := client.FetchRouteStatistics()
	if err != nil {
		return err
	}

	for proto, count := range routeData.ByProto {
		ch <- prometheus.MustNewConstMetric(
			c.routesTotal,
			prometheus.GaugeValue,
			float64(count),
			proto,
			c.instance,
		)
	}

	return nil
}
