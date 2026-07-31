package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

type systemCollector struct {
	log *slog.Logger

	memoryTotalBytes *prometheus.Desc
	memoryUsedBytes  *prometheus.Desc
	memoryArcBytes   *prometheus.Desc
	uptimeSeconds    *prometheus.Desc
	bootTimestamp    *prometheus.Desc
	loadAverage      *prometheus.Desc
	configLastChange *prometheus.Desc
	diskTotalBytes   *prometheus.Desc
	diskUsedBytes    *prometheus.Desc
	diskUsageRatio   *prometheus.Desc
	swapTotalBytes   *prometheus.Desc
	swapUsedBytes    *prometheus.Desc
	systemInfo       *prometheus.Desc

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
	c.bootTimestamp = buildPrometheusDesc(c.subsystem, "boot_timestamp_seconds",
		"Unix timestamp at which the firewall booted, taken from the API's own boottime value rather than derived from uptime. Anchors the reboot dashboard annotation (#421): a query-time time()-uptime is recomputed on every evaluation and drifts between them, which moves the marker. Absent when the systemTime sub-call failed or boottime was unparseable.",
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
	c.systemInfo = buildPrometheusDesc(c.subsystem, "info",
		"System information with hostname, OS versions, and CPU details (value is always 1)",
		[]string{"hostname", "opnsense_version", "freebsd_version", "openssl_version", "cpu_model", "cpu_cores", "cpu_threads"},
	)
}

func (c *systemCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.memoryTotalBytes
	ch <- c.memoryUsedBytes
	ch <- c.memoryArcBytes
	ch <- c.uptimeSeconds
	ch <- c.bootTimestamp
	ch <- c.loadAverage
	ch <- c.configLastChange
	ch <- c.diskTotalBytes
	ch <- c.diskUsedBytes
	ch <- c.diskUsageRatio
	ch <- c.swapTotalBytes
	ch <- c.swapUsedBytes
	ch <- c.systemInfo
}

func (c *systemCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchSystemResources()
	if err != nil {
		return err
	}

	// Memory total/used come solely from the systemResources sub-call. Skip them
	// when it failed (partial fetch) rather than emitting 0, which breaks
	// used/total ratio panels (division by zero) (#91).
	if data.Memory.Available {
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
	}

	if data.Memory.HasArc {
		ch <- prometheus.MustNewConstMetric(
			c.memoryArcBytes,
			prometheus.GaugeValue,
			float64(data.Memory.Arc),
			c.instance,
		)
	}

	// Uptime and load average come solely from the systemTime sub-call. Skip them
	// when it failed rather than emitting uptime=0, which reads as a host reboot
	// and can fire false "host rebooted" alerts (#91).
	if data.Time.Available {
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
	}

	// Gated on a positive value, not on Time.Available, exactly like
	// config_last_change below: an unparseable boottime leaves it zero, and an
	// epoch-0 sample would place the reboot annotation at 1970 (#421).
	if data.Time.BootTimestamp > 0 {
		ch <- prometheus.MustNewConstMetric(
			c.bootTimestamp,
			prometheus.GaugeValue,
			data.Time.BootTimestamp,
			c.instance,
		)
	}

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

	if data.Info != nil {
		ch <- prometheus.MustNewConstMetric(
			c.systemInfo,
			prometheus.GaugeValue,
			1,
			data.Info.Hostname,
			data.Info.OPNsenseVersion,
			data.Info.FreeBSDVersion,
			data.Info.OpenSSLVersion,
			data.Info.CPUModel,
			data.Info.CPUCores,
			data.Info.CPUThreads,
			c.instance,
		)
	}

	return nil
}
