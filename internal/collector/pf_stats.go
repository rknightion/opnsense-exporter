package collector

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type pfStatsCollector struct {
	log *slog.Logger

	stateTableEntries     *prometheus.Desc
	stateTableSearches    *prometheus.Desc
	stateTableInserts     *prometheus.Desc
	stateTableRemovals    *prometheus.Desc
	sourceTrackingEntries *prometheus.Desc
	counterTotal          *prometheus.Desc
	limitCounterTotal     *prometheus.Desc
	memoryLimit           *prometheus.Desc
	timeoutSeconds        *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &pfStatsCollector{
		subsystem: PFStatsSubsystem,
	})
}

func (c *pfStatsCollector) Name() string {
	return c.subsystem
}

func (c *pfStatsCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.stateTableEntries = buildPrometheusDesc(c.subsystem, "state_table_entries",
		"Current number of entries in the PF state table",
		nil,
	)
	c.stateTableSearches = buildPrometheusDesc(c.subsystem, "state_table_searches_total",
		"Total number of state table searches",
		nil,
	)
	c.stateTableInserts = buildPrometheusDesc(c.subsystem, "state_table_inserts_total",
		"Total number of state table inserts",
		nil,
	)
	c.stateTableRemovals = buildPrometheusDesc(c.subsystem, "state_table_removals_total",
		"Total number of state table removals",
		nil,
	)
	c.sourceTrackingEntries = buildPrometheusDesc(c.subsystem, "source_tracking_entries",
		"Current number of entries in the source tracking table",
		nil,
	)
	c.counterTotal = buildPrometheusDesc(c.subsystem, "counter_total",
		"Total count of PF counter by name",
		[]string{"counter"},
	)
	c.limitCounterTotal = buildPrometheusDesc(c.subsystem, "limit_counter_total",
		"Total count of PF limit counter by name",
		[]string{"counter"},
	)
	c.memoryLimit = buildPrometheusDesc(c.subsystem, "memory_limit",
		"PF memory pool limit by pool name",
		[]string{"pool"},
	)
	c.timeoutSeconds = buildPrometheusDesc(c.subsystem, "timeout_seconds",
		"PF timeout value in seconds by name",
		[]string{"name"},
	)
}

func (c *pfStatsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.stateTableEntries
	ch <- c.stateTableSearches
	ch <- c.stateTableInserts
	ch <- c.stateTableRemovals
	ch <- c.sourceTrackingEntries
	ch <- c.counterTotal
	ch <- c.limitCounterTotal
	ch <- c.memoryLimit
	ch <- c.timeoutSeconds
}

func (c *pfStatsCollector) Update(client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchPFStatistics()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(
		c.stateTableEntries,
		prometheus.GaugeValue,
		float64(data.StateTableEntries),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.stateTableSearches,
		prometheus.CounterValue,
		data.StateTableSearches,
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.stateTableInserts,
		prometheus.CounterValue,
		data.StateTableInserts,
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.stateTableRemovals,
		prometheus.CounterValue,
		data.StateTableRemovals,
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.sourceTrackingEntries,
		prometheus.GaugeValue,
		float64(data.SourceTrackingEntries),
		c.instance,
	)

	for name, total := range data.Counters {
		ch <- prometheus.MustNewConstMetric(
			c.counterTotal,
			prometheus.CounterValue,
			total,
			name,
			c.instance,
		)
	}

	for name, total := range data.LimitCounters {
		ch <- prometheus.MustNewConstMetric(
			c.limitCounterTotal,
			prometheus.CounterValue,
			total,
			name,
			c.instance,
		)
	}

	for pool, limit := range data.MemoryLimits {
		ch <- prometheus.MustNewConstMetric(
			c.memoryLimit,
			prometheus.GaugeValue,
			float64(limit),
			pool,
			c.instance,
		)
	}

	for name, seconds := range data.Timeouts {
		ch <- prometheus.MustNewConstMetric(
			c.timeoutSeconds,
			prometheus.GaugeValue,
			seconds,
			name,
			c.instance,
		)
	}

	return nil
}
