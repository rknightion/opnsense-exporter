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
}

func (c *monitCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.serviceRunning
	ch <- c.statusOK
	ch <- c.checksTotal
	ch <- c.checkStatus
	ch <- c.checkMonitored
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
	}

	return nil
}
