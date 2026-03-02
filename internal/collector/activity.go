package collector

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type activityCollector struct {
	log *slog.Logger

	threadsTotal    *prometheus.Desc
	threadsRunning  *prometheus.Desc
	threadsSleeping *prometheus.Desc
	threadsWaiting  *prometheus.Desc
	cpuUser         *prometheus.Desc
	cpuNice         *prometheus.Desc
	cpuSystem       *prometheus.Desc
	cpuInterrupt    *prometheus.Desc
	cpuIdle         *prometheus.Desc

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
	c.cpuUser = buildPrometheusDesc(c.subsystem, "cpu_user_percent",
		"CPU user usage percentage",
		nil,
	)
	c.cpuNice = buildPrometheusDesc(c.subsystem, "cpu_nice_percent",
		"CPU nice usage percentage",
		nil,
	)
	c.cpuSystem = buildPrometheusDesc(c.subsystem, "cpu_system_percent",
		"CPU system usage percentage",
		nil,
	)
	c.cpuInterrupt = buildPrometheusDesc(c.subsystem, "cpu_interrupt_percent",
		"CPU interrupt usage percentage",
		nil,
	)
	c.cpuIdle = buildPrometheusDesc(c.subsystem, "cpu_idle_percent",
		"CPU idle percentage",
		nil,
	)
}

func (c *activityCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.threadsTotal
	ch <- c.threadsRunning
	ch <- c.threadsSleeping
	ch <- c.threadsWaiting
	ch <- c.cpuUser
	ch <- c.cpuNice
	ch <- c.cpuSystem
	ch <- c.cpuInterrupt
	ch <- c.cpuIdle
}

func (c *activityCollector) Update(client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
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
	ch <- prometheus.MustNewConstMetric(
		c.cpuUser,
		prometheus.GaugeValue,
		data.CPUUser,
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.cpuNice,
		prometheus.GaugeValue,
		data.CPUNice,
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.cpuSystem,
		prometheus.GaugeValue,
		data.CPUSystem,
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.cpuInterrupt,
		prometheus.GaugeValue,
		data.CPUInterrupt,
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.cpuIdle,
		prometheus.GaugeValue,
		data.CPUIdle,
		c.instance,
	)

	return nil
}
