package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

// monitCollector collects monit service-check metrics from the OPNsense
// Monit API (api/monit/status/get/xml).
type monitCollector struct {
	log *slog.Logger

	serviceRunning *prometheus.Desc
	statusOK       *prometheus.Desc
	checksTotal    *prometheus.Desc
	checkStatus    *prometheus.Desc
	checkMonitored *prometheus.Desc

	// Per-check resource telemetry (#219). All gauges; a value is only
	// emitted when the underlying monit payload actually carried it — never
	// coerced to zero when absent.
	filesystemUsagePercent      *prometheus.Desc
	filesystemInodeUsagePercent *prometheus.Desc
	processCPUPercent           *prometheus.Desc
	processMemoryBytes          *prometheus.Desc
	processUptimeSeconds        *prometheus.Desc
	processThreads              *prometheus.Desc
	hostICMPResponseSeconds     *prometheus.Desc
	portResponseSeconds         *prometheus.Desc
	systemLoad                  *prometheus.Desc
	systemMemoryPercent         *prometheus.Desc
	systemSwapPercent           *prometheus.Desc
	systemCPUPercent            *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &monitCollector{
		subsystem: MonitSubsystem,
	})
}

func (c *monitCollector) Name() string { return c.subsystem }

func (c *monitCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the Monit service is running (1 = running, 0 = stopped/disabled)", nil)

	c.statusOK = buildPrometheusDesc(c.subsystem, "status_ok",
		"Whether the monit httpd was reachable and returned a valid status (1 = ok, 0 = failed/unreachable)", nil)

	c.checksTotal = buildPrometheusDesc(c.subsystem, "checks_total",
		"Total number of service checks configured in monit", nil)

	c.checkStatus = buildPrometheusDesc(c.subsystem, "check_status",
		"Whether a monit check reports no errors (1 = status field is 0, 0 = error)",
		[]string{"name", "type"})

	c.checkMonitored = buildPrometheusDesc(c.subsystem, "check_monitored",
		"Whether a monit check is actively monitored (1 = monitored, 0 = not monitored)",
		[]string{"name", "type"})

	c.filesystemUsagePercent = buildPrometheusDesc(c.subsystem, "filesystem_usage_percent",
		"Filesystem block (space) usage percent for a monit filesystem check",
		[]string{"name", "type"})

	c.filesystemInodeUsagePercent = buildPrometheusDesc(c.subsystem, "filesystem_inode_usage_percent",
		"Filesystem inode usage percent for a monit filesystem check",
		[]string{"name", "type"})

	c.processCPUPercent = buildPrometheusDesc(c.subsystem, "process_cpu_percent",
		"CPU usage percent for a monit process check (absent until monit's second poll cycle computes a rate)",
		[]string{"name", "type"})

	c.processMemoryBytes = buildPrometheusDesc(c.subsystem, "process_memory_bytes",
		"Resident memory usage in bytes for a monit process check",
		[]string{"name", "type"})

	c.processUptimeSeconds = buildPrometheusDesc(c.subsystem, "process_uptime_seconds",
		"Uptime in seconds for a monit process check",
		[]string{"name", "type"})

	c.processThreads = buildPrometheusDesc(c.subsystem, "process_threads",
		"Number of threads for a monit process check",
		[]string{"name", "type"})

	c.hostICMPResponseSeconds = buildPrometheusDesc(c.subsystem, "host_icmp_response_seconds",
		"ICMP ping response time in seconds for a monit host check",
		[]string{"name", "type"})

	c.portResponseSeconds = buildPrometheusDesc(c.subsystem, "port_response_seconds",
		"Port connection response time in seconds for a monit host check's port test",
		[]string{"name", "type", "port", "protocol"})

	c.systemLoad = buildPrometheusDesc(c.subsystem, "system_load",
		"System load average for a monit system check",
		[]string{"name", "type", "period"})

	c.systemMemoryPercent = buildPrometheusDesc(c.subsystem, "system_memory_percent",
		"System memory usage percent for a monit system check",
		[]string{"name", "type"})

	c.systemSwapPercent = buildPrometheusDesc(c.subsystem, "system_swap_percent",
		"System swap usage percent for a monit system check",
		[]string{"name", "type"})

	c.systemCPUPercent = buildPrometheusDesc(c.subsystem, "system_cpu_percent",
		"System CPU usage percent by mode for a monit system check",
		[]string{"name", "type", "mode"})
}

func (c *monitCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.serviceRunning
	ch <- c.statusOK
	ch <- c.checksTotal
	ch <- c.checkStatus
	ch <- c.checkMonitored
	ch <- c.filesystemUsagePercent
	ch <- c.filesystemInodeUsagePercent
	ch <- c.processCPUPercent
	ch <- c.processMemoryBytes
	ch <- c.processUptimeSeconds
	ch <- c.processThreads
	ch <- c.hostICMPResponseSeconds
	ch <- c.portResponseSeconds
	ch <- c.systemLoad
	ch <- c.systemMemoryPercent
	ch <- c.systemSwapPercent
	ch <- c.systemCPUPercent
}

func (c *monitCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	// Fetch the Monit service status (running/stopped/disabled) first. This
	// uses FetchServiceStatusOptional so a missing endpoint is silent — a 404
	// from the service endpoint means the plugin is absent and we emit nothing.
	svcStatus, svcPresent, sErr := client.FetchServiceStatusOptional("monitServiceStatus")
	if sErr != nil {
		c.log.Warn("failed to fetch monit service status", "err", sErr)
		// Do not return early — still attempt to fetch monit status data.
	} else if svcPresent {
		running := 0.0
		if svcStatus == "running" {
			running = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.serviceRunning, prometheus.GaugeValue,
			running, c.instance)
	}

	// Fetch the monit status (check data via monit's httpd).
	data, err := client.FetchMonitStatus()
	if err != nil {
		return err
	}

	// Emit status_ok regardless of StatusOK value so the absence of monit
	// connectivity is always visible in the metric.
	statusOKVal := 0.0
	if data.StatusOK {
		statusOKVal = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.statusOK, prometheus.GaugeValue,
		statusOKVal, c.instance)

	// Only emit per-check metrics when monit is reachable and returned data.
	if !data.StatusOK {
		return nil
	}

	ch <- prometheus.MustNewConstMetric(c.checksTotal, prometheus.GaugeValue,
		float64(len(data.Checks)), c.instance)

	for _, check := range data.Checks {
		ch <- prometheus.MustNewConstMetric(c.checkStatus, prometheus.GaugeValue,
			check.StatusOK, check.Name, check.Type, c.instance)
		ch <- prometheus.MustNewConstMetric(c.checkMonitored, prometheus.GaugeValue,
			check.Monitored, check.Name, check.Type, c.instance)

		if v := check.FilesystemUsagePercent; v != nil {
			ch <- prometheus.MustNewConstMetric(c.filesystemUsagePercent, prometheus.GaugeValue,
				*v, check.Name, check.Type, c.instance)
		}
		if v := check.FilesystemInodeUsagePercent; v != nil {
			ch <- prometheus.MustNewConstMetric(c.filesystemInodeUsagePercent, prometheus.GaugeValue,
				*v, check.Name, check.Type, c.instance)
		}

		if v := check.ProcessCPUPercent; v != nil {
			ch <- prometheus.MustNewConstMetric(c.processCPUPercent, prometheus.GaugeValue,
				*v, check.Name, check.Type, c.instance)
		}
		if v := check.ProcessMemoryBytes; v != nil {
			ch <- prometheus.MustNewConstMetric(c.processMemoryBytes, prometheus.GaugeValue,
				*v, check.Name, check.Type, c.instance)
		}
		if v := check.ProcessUptimeSeconds; v != nil {
			ch <- prometheus.MustNewConstMetric(c.processUptimeSeconds, prometheus.GaugeValue,
				*v, check.Name, check.Type, c.instance)
		}
		if v := check.ProcessThreads; v != nil {
			ch <- prometheus.MustNewConstMetric(c.processThreads, prometheus.GaugeValue,
				*v, check.Name, check.Type, c.instance)
		}

		if v := check.ICMPResponseSeconds; v != nil {
			ch <- prometheus.MustNewConstMetric(c.hostICMPResponseSeconds, prometheus.GaugeValue,
				*v, check.Name, check.Type, c.instance)
		}
		for _, port := range check.Ports {
			ch <- prometheus.MustNewConstMetric(c.portResponseSeconds, prometheus.GaugeValue,
				port.ResponseSeconds, check.Name, check.Type, port.Port, port.Protocol, c.instance)
		}

		if v := check.SystemLoad1; v != nil {
			ch <- prometheus.MustNewConstMetric(c.systemLoad, prometheus.GaugeValue,
				*v, check.Name, check.Type, "1m", c.instance)
		}
		if v := check.SystemLoad5; v != nil {
			ch <- prometheus.MustNewConstMetric(c.systemLoad, prometheus.GaugeValue,
				*v, check.Name, check.Type, "5m", c.instance)
		}
		if v := check.SystemLoad15; v != nil {
			ch <- prometheus.MustNewConstMetric(c.systemLoad, prometheus.GaugeValue,
				*v, check.Name, check.Type, "15m", c.instance)
		}
		if v := check.SystemMemoryPercent; v != nil {
			ch <- prometheus.MustNewConstMetric(c.systemMemoryPercent, prometheus.GaugeValue,
				*v, check.Name, check.Type, c.instance)
		}
		if v := check.SystemSwapPercent; v != nil {
			ch <- prometheus.MustNewConstMetric(c.systemSwapPercent, prometheus.GaugeValue,
				*v, check.Name, check.Type, c.instance)
		}
		for mode, v := range check.SystemCPU {
			ch <- prometheus.MustNewConstMetric(c.systemCPUPercent, prometheus.GaugeValue,
				v, check.Name, check.Type, mode, c.instance)
		}
	}

	return nil
}
