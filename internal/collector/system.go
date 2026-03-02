package collector

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type systemCollector struct {
	log *slog.Logger

	memoryTotalBytes *prometheus.Desc
	memoryUsedBytes  *prometheus.Desc
	memoryArcBytes   *prometheus.Desc
	uptimeSeconds    *prometheus.Desc
	loadAverage      *prometheus.Desc
	configLastChange *prometheus.Desc
	diskTotalBytes   *prometheus.Desc
	diskUsedBytes    *prometheus.Desc
	diskUsageRatio   *prometheus.Desc
	swapTotalBytes   *prometheus.Desc
	swapUsedBytes    *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &systemCollector{
		subsystem: SystemSubsystem,
	})
}

func (c *systemCollector) Name() string {
	return c.subsystem
}

func (c *systemCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.memoryTotalBytes = buildPrometheusDesc(c.subsystem, "memory_total_bytes",
		"Total physical memory in bytes",
		nil,
	)
	c.memoryUsedBytes = buildPrometheusDesc(c.subsystem, "memory_used_bytes",
		"Used physical memory in bytes",
		nil,
	)
	c.memoryArcBytes = buildPrometheusDesc(c.subsystem, "memory_arc_bytes",
		"ZFS ARC memory usage in bytes",
		nil,
	)
	c.uptimeSeconds = buildPrometheusDesc(c.subsystem, "uptime_seconds",
		"System uptime in seconds",
		nil,
	)
	c.loadAverage = buildPrometheusDesc(c.subsystem, "load_average",
		"System load average",
		[]string{"interval"},
	)
	c.configLastChange = buildPrometheusDesc(c.subsystem, "config_last_change",
		"Unix timestamp of last configuration change",
		nil,
	)
	c.diskTotalBytes = buildPrometheusDesc(c.subsystem, "disk_total_bytes",
		"Total disk space in bytes",
		[]string{"device", "type", "mountpoint"},
	)
	c.diskUsedBytes = buildPrometheusDesc(c.subsystem, "disk_used_bytes",
		"Used disk space in bytes",
		[]string{"device", "type", "mountpoint"},
	)
	c.diskUsageRatio = buildPrometheusDesc(c.subsystem, "disk_usage_ratio",
		"Disk usage as a ratio from 0.0 to 1.0",
		[]string{"device", "type", "mountpoint"},
	)
	c.swapTotalBytes = buildPrometheusDesc(c.subsystem, "swap_total_bytes",
		"Total swap space in bytes",
		[]string{"device"},
	)
	c.swapUsedBytes = buildPrometheusDesc(c.subsystem, "swap_used_bytes",
		"Used swap space in bytes",
		[]string{"device"},
	)
}

func (c *systemCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.memoryTotalBytes
	ch <- c.memoryUsedBytes
	ch <- c.memoryArcBytes
	ch <- c.uptimeSeconds
	ch <- c.loadAverage
	ch <- c.configLastChange
	ch <- c.diskTotalBytes
	ch <- c.diskUsedBytes
	ch <- c.diskUsageRatio
	ch <- c.swapTotalBytes
	ch <- c.swapUsedBytes
}

func (c *systemCollector) Update(client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchSystemResources()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(
		c.memoryTotalBytes,
		prometheus.GaugeValue,
		float64(data.Memory.Total),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.memoryUsedBytes,
		prometheus.GaugeValue,
		float64(data.Memory.Used),
		c.instance,
	)

	if data.Memory.HasArc {
		ch <- prometheus.MustNewConstMetric(
			c.memoryArcBytes,
			prometheus.GaugeValue,
			float64(data.Memory.Arc),
			c.instance,
		)
	}

	ch <- prometheus.MustNewConstMetric(
		c.uptimeSeconds,
		prometheus.GaugeValue,
		float64(data.Time.Uptime),
		c.instance,
	)

	ch <- prometheus.MustNewConstMetric(
		c.loadAverage,
		prometheus.GaugeValue,
		data.Time.LoadAverage[0],
		"1",
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.loadAverage,
		prometheus.GaugeValue,
		data.Time.LoadAverage[1],
		"5",
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.loadAverage,
		prometheus.GaugeValue,
		data.Time.LoadAverage[2],
		"15",
		c.instance,
	)

	if data.Time.ConfigLastChange > 0 {
		ch <- prometheus.MustNewConstMetric(
			c.configLastChange,
			prometheus.GaugeValue,
			float64(data.Time.ConfigLastChange),
			c.instance,
		)
	}

	for _, disk := range data.Disks {
		ch <- prometheus.MustNewConstMetric(
			c.diskTotalBytes,
			prometheus.GaugeValue,
			float64(disk.Total),
			disk.Device,
			disk.Type,
			disk.Mountpoint,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.diskUsedBytes,
			prometheus.GaugeValue,
			float64(disk.Used),
			disk.Device,
			disk.Type,
			disk.Mountpoint,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.diskUsageRatio,
			prometheus.GaugeValue,
			disk.UsageRatio,
			disk.Device,
			disk.Type,
			disk.Mountpoint,
			c.instance,
		)
	}

	for _, swap := range data.Swaps {
		ch <- prometheus.MustNewConstMetric(
			c.swapTotalBytes,
			prometheus.GaugeValue,
			float64(swap.Total),
			swap.Device,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.swapUsedBytes,
			prometheus.GaugeValue,
			float64(swap.Used),
			swap.Device,
			c.instance,
		)
	}

	return nil
}
