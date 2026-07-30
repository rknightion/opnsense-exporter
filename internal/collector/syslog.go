package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type syslogCollector struct {
	log *slog.Logger

	processedTotal         *prometheus.Desc
	droppedTotal           *prometheus.Desc
	writtenTotal           *prometheus.Desc
	queued                 *prometheus.Desc
	truncatedMessagesTotal *prometheus.Desc
	truncatedBytesTotal    *prometheus.Desc
	memoryUsageBytes       *prometheus.Desc
	eventsPerSecond        *prometheus.Desc
	messageSizeBytes       *prometheus.Desc
	targetState            *prometheus.Desc
	serviceRunning         *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &syslogCollector{
		subsystem: SyslogSubsystem,
	})
}

func (c *syslogCollector) Name() string {
	return c.subsystem
}

func (c *syslogCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	srcLabels := []string{"source_name", "source_id", "source_instance"}

	c.processedTotal = buildPrometheusDesc(c.subsystem, "processed_total",
		"Messages processed by this syslog-ng object since stats reset",
		srcLabels)
	c.droppedTotal = buildPrometheusDesc(c.subsystem, "dropped_total",
		"Messages dropped by this syslog-ng object since stats reset",
		srcLabels)
	c.writtenTotal = buildPrometheusDesc(c.subsystem, "written_total",
		"Messages written by this syslog-ng object since stats reset",
		srcLabels)
	c.queued = buildPrometheusDesc(c.subsystem, "queued",
		"Messages currently queued in this syslog-ng object",
		srcLabels)
	c.truncatedMessagesTotal = buildPrometheusDesc(c.subsystem, "truncated_messages_total",
		"Messages truncated by this syslog-ng object since stats reset",
		srcLabels)
	c.truncatedBytesTotal = buildPrometheusDesc(c.subsystem, "truncated_bytes_total",
		"Bytes truncated by this syslog-ng object since stats reset",
		srcLabels)
	c.memoryUsageBytes = buildPrometheusDesc(c.subsystem, "memory_usage_bytes",
		"Current memory usage of this syslog-ng object in bytes",
		srcLabels)
	c.eventsPerSecond = buildPrometheusDesc(c.subsystem, "events_per_second",
		"syslog-ng events per second over the labelled window (1h, 24h, since_start)",
		append(append([]string{}, srcLabels...), "window"))
	c.messageSizeBytes = buildPrometheusDesc(c.subsystem, "message_size_bytes",
		"syslog-ng message size in bytes (stat = avg or max)",
		append(append([]string{}, srcLabels...), "stat"))
	c.targetState = buildPrometheusDesc(c.subsystem, "target_state",
		"Current lifecycle state of a syslog-ng source/target object (always 1; one series per "+
			"SourceName/SourceId/SourceInstance). state is drawn from syslog-ng's closed state "+
			"vocabulary -- active (currently alive and receiving stat updates), dynamic (a "+
			"runtime-created object that may cease to exist), orphaned (the underlying config "+
			"element was removed but its last-known counters are retained) -- and anything "+
			"unrecognized collapses to unknown. A target's byte/message counters going flat while "+
			"this reads orphaned (rather than active) is exactly the stall this metric exists to "+
			"distinguish from an idle-but-fine target.",
		append(append([]string{}, srcLabels...), "state"))
	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the syslog-ng service is running (1 = running, 0 = stopped/disabled)",
		nil)
}

func (c *syslogCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.processedTotal
	ch <- c.droppedTotal
	ch <- c.writtenTotal
	ch <- c.queued
	ch <- c.truncatedMessagesTotal
	ch <- c.truncatedBytesTotal
	ch <- c.memoryUsageBytes
	ch <- c.eventsPerSecond
	ch <- c.messageSizeBytes
	ch <- c.targetState
	ch <- c.serviceRunning
}

func (c *syslogCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchSyslogStats()
	if err != nil {
		return err
	}

	for _, s := range data.Stats {
		src := []string{s.SourceName, s.SourceID, s.SourceInstance}
		switch s.Type {
		case "processed":
			ch <- prometheus.MustNewConstMetric(c.processedTotal, prometheus.CounterValue,
				s.Value, append(src, c.instance)...)
		case "dropped":
			ch <- prometheus.MustNewConstMetric(c.droppedTotal, prometheus.CounterValue,
				s.Value, append(src, c.instance)...)
		case "written":
			ch <- prometheus.MustNewConstMetric(c.writtenTotal, prometheus.CounterValue,
				s.Value, append(src, c.instance)...)
		case "queued":
			ch <- prometheus.MustNewConstMetric(c.queued, prometheus.GaugeValue,
				s.Value, append(src, c.instance)...)
		case "truncated_count":
			ch <- prometheus.MustNewConstMetric(c.truncatedMessagesTotal, prometheus.CounterValue,
				s.Value, append(src, c.instance)...)
		case "truncated_bytes":
			ch <- prometheus.MustNewConstMetric(c.truncatedBytesTotal, prometheus.CounterValue,
				s.Value, append(src, c.instance)...)
		case "memory_usage":
			ch <- prometheus.MustNewConstMetric(c.memoryUsageBytes, prometheus.GaugeValue,
				s.Value, append(src, c.instance)...)
		case "eps_last_1h":
			ch <- prometheus.MustNewConstMetric(c.eventsPerSecond, prometheus.GaugeValue,
				s.Value, append(src, "1h", c.instance)...)
		case "eps_last_24h":
			ch <- prometheus.MustNewConstMetric(c.eventsPerSecond, prometheus.GaugeValue,
				s.Value, append(src, "24h", c.instance)...)
		case "eps_since_start":
			ch <- prometheus.MustNewConstMetric(c.eventsPerSecond, prometheus.GaugeValue,
				s.Value, append(src, "since_start", c.instance)...)
		case "msg_size_avg":
			ch <- prometheus.MustNewConstMetric(c.messageSizeBytes, prometheus.GaugeValue,
				s.Value, append(src, "avg", c.instance)...)
		case "msg_size_max":
			ch <- prometheus.MustNewConstMetric(c.messageSizeBytes, prometheus.GaugeValue,
				s.Value, append(src, "max", c.instance)...)
		default:
			c.log.Debug("syslog: skipping unknown stat type", "type", s.Type)
		}
	}

	for _, ts := range data.TargetStates {
		ch <- prometheus.MustNewConstMetric(c.targetState, prometheus.GaugeValue,
			1, ts.SourceName, ts.SourceID, ts.SourceInstance, ts.State, c.instance)
	}

	status, sErr := client.FetchServiceStatus("syslogServiceStatus")
	if sErr != nil {
		c.log.Warn("failed to fetch syslog service status", "err", sErr)
	} else {
		val := 0.0
		if status == "running" {
			val = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.serviceRunning, prometheus.GaugeValue,
			val, c.instance)
	}

	return nil
}
