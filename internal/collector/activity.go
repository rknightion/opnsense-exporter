package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

// activityCollector exports thread-state counts from api/diagnostics/activity.
//
// CPU utilisation used to live here too and no longer does (#559): it comes from the
// cpu_usage SSE stream as cumulative counters instead. What remains is the only thing
// this endpoint uniquely provides — and it is expensive, at a measured 2.15 s of
// firewall work per call, because OPNsense's activity.py runs `top -aHSTn -d2` and
// waits out top's inter-display delay. Thread counts are instantaneous gauges with no
// sub-minute alerting story, so the collector sits on the medium tier: that alone
// takes this endpoint from a 14% firewall duty cycle to 3.6%.
type activityCollector struct {
	log *slog.Logger

	threadsTotal    *prometheus.Desc
	threadsRunning  *prometheus.Desc
	threadsSleeping *prometheus.Desc
	threadsWaiting  *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &activityCollector{
		subsystem: ActivitySubsystem,
	})
}

func (c *activityCollector) Name() string {
	return c.subsystem
}

func (c *activityCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.threadsTotal = buildPrometheusDesc(c.subsystem, "threads_total",
		"Total number of threads on the system",
		nil,
	)
	c.threadsRunning = buildPrometheusDesc(c.subsystem, "threads_running",
		"Number of running threads on the system",
		nil,
	)
	c.threadsSleeping = buildPrometheusDesc(c.subsystem, "threads_sleeping",
		"Number of sleeping threads on the system",
		nil,
	)
	c.threadsWaiting = buildPrometheusDesc(c.subsystem, "threads_waiting",
		"Number of waiting threads on the system",
		nil,
	)
}

func (c *activityCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.threadsTotal
	ch <- c.threadsRunning
	ch <- c.threadsSleeping
	ch <- c.threadsWaiting
}

func (c *activityCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchActivity()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(
		c.threadsTotal,
		prometheus.GaugeValue,
		float64(data.ThreadsTotal),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.threadsRunning,
		prometheus.GaugeValue,
		float64(data.ThreadsRunning),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.threadsSleeping,
		prometheus.GaugeValue,
		float64(data.ThreadsSleeping),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.threadsWaiting,
		prometheus.GaugeValue,
		float64(data.ThreadsWaiting),
		c.instance,
	)
	return nil
}
