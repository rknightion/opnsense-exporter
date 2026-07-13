package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

// crowdsecCollector collects CrowdSec plugin metrics.
//
// All four search endpoints are bootgrid. Alerts and decisions are count-only
// (D3: rowCount=1, reading `total`). Bouncers and machines are fetched fully.
//
// Plugin absent (404 on the first endpoint) → silent return, no metrics.
// cscli unavailable (HTTP-200 {"message":"unable to retrieve data"}) → the
// corresponding metric is omitted for that scrape (HasAlertsTotal / HasDecisionsTotal /
// HasBouncers / HasMachines flags control this).
type crowdsecCollector struct {
	log *slog.Logger

	serviceRunning   *prometheus.Desc
	alertsTotal      *prometheus.Desc
	decisionsTotal   *prometheus.Desc
	bouncersTotal    *prometheus.Desc
	bouncerValid     *prometheus.Desc
	bouncerLastPull  *prometheus.Desc
	machinesTotal    *prometheus.Desc
	machineValidated *prometheus.Desc
	machineHeartbeat *prometheus.Desc
	hubItems         *prometheus.Desc
	versionInfo      *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &crowdsecCollector{
		subsystem: CrowdSecSubsystem,
	})
}

func (c *crowdsecCollector) Name() string { return c.subsystem }

func (c *crowdsecCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	bouncerLabels := []string{"name", "type"}
	machineLabels := []string{"name"}

	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the CrowdSec service is running (1 = running, 0 = stopped/disabled)", nil)
	c.alertsTotal = buildPrometheusDesc(c.subsystem, "alerts_total",
		"Total number of CrowdSec alerts (count-only, no per-type breakdown)", nil)
	c.decisionsTotal = buildPrometheusDesc(c.subsystem, "decisions_total",
		"Total number of active CrowdSec decisions (count-only, no per-type breakdown)", nil)
	c.bouncersTotal = buildPrometheusDesc(c.subsystem, "bouncers_total",
		"Total number of registered CrowdSec bouncers", nil)
	c.bouncerValid = buildPrometheusDesc(c.subsystem, "bouncer_valid",
		"Whether the bouncer API key is valid (1 = valid, 0 = invalid)", bouncerLabels)
	c.bouncerLastPull = buildPrometheusDesc(c.subsystem, "bouncer_last_pull_timestamp_seconds",
		"Unix timestamp of the last pull by this bouncer (omitted when never pulled)", bouncerLabels)
	c.machinesTotal = buildPrometheusDesc(c.subsystem, "machines_total",
		"Total number of registered CrowdSec machines (agents)", nil)
	c.machineValidated = buildPrometheusDesc(c.subsystem, "machine_validated",
		"Whether the machine registration has been validated (1 = validated, 0 = pending)", machineLabels)
	c.machineHeartbeat = buildPrometheusDesc(c.subsystem, "machine_last_heartbeat_timestamp_seconds",
		"Unix timestamp of the last heartbeat from this machine (omitted when absent)", machineLabels)
	c.hubItems = buildPrometheusDesc(c.subsystem, "hub_items",
		"Number of installed CrowdSec hub items per component and status (e.g. component=\"scenario\" status=\"enabled,tainted\")",
		[]string{"component", "status"})
	c.versionInfo = buildPrometheusDesc(c.subsystem, "version_info",
		"CrowdSec engine version (value always 1; version is a label)", []string{"version"})
}

func (c *crowdsecCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.serviceRunning,
		c.alertsTotal,
		c.decisionsTotal,
		c.bouncersTotal,
		c.bouncerValid,
		c.bouncerLastPull,
		c.machinesTotal,
		c.machineValidated,
		c.machineHeartbeat,
		c.hubItems,
		c.versionInfo,
	} {
		ch <- d
	}
}

func (c *crowdsecCollector) Update(_ context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchCrowdSecStatus()
	if err != nil {
		return err
	}

	// Plugin absent (first endpoint 404): stay completely silent — also skip
	// the service-status probe (skip-on-absent pattern, D1).
	if !data.Present {
		return nil
	}

	// Counts — only emitted when cscli succeeded for that endpoint.
	if data.HasAlertsTotal {
		ch <- prometheus.MustNewConstMetric(c.alertsTotal, prometheus.GaugeValue,
			data.AlertsTotal, c.instance)
	}
	if data.HasDecisionsTotal {
		ch <- prometheus.MustNewConstMetric(c.decisionsTotal, prometheus.GaugeValue,
			data.DecisionsTotal, c.instance)
	}

	// Bouncers.
	if data.HasBouncers {
		ch <- prometheus.MustNewConstMetric(c.bouncersTotal, prometheus.GaugeValue,
			float64(len(data.Bouncers)), c.instance)
		for _, b := range data.Bouncers {
			valid := 0.0
			if b.Valid {
				valid = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.bouncerValid, prometheus.GaugeValue,
				valid, b.Name, b.Type, c.instance)
			if b.HasLastPull {
				ch <- prometheus.MustNewConstMetric(c.bouncerLastPull, prometheus.GaugeValue,
					b.LastPullSeconds, b.Name, b.Type, c.instance)
			}
		}
	}

	// Machines.
	if data.HasMachines {
		ch <- prometheus.MustNewConstMetric(c.machinesTotal, prometheus.GaugeValue,
			float64(len(data.Machines)), c.instance)
		for _, m := range data.Machines {
			validated := 0.0
			if m.Validated {
				validated = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.machineValidated, prometheus.GaugeValue,
				validated, m.Name, c.instance)
			if m.HasLastHeartbeat {
				ch <- prometheus.MustNewConstMetric(c.machineHeartbeat, prometheus.GaugeValue,
					m.LastHeartbeatSeconds, m.Name, c.instance)
			}
		}
	}

	// Hub component health (#205): aggregated counts per component + normalised
	// status. Never per-item name labels — a collection pulls in 50-200
	// scenarios/parsers.
	if data.HasHubItems {
		for _, item := range data.HubItems {
			ch <- prometheus.MustNewConstMetric(c.hubItems, prometheus.GaugeValue,
				float64(item.Count), item.Component, item.Status, c.instance)
		}
	}

	// Engine version (#205).
	if data.HasVersion {
		ch <- prometheus.MustNewConstMetric(c.versionInfo, prometheus.GaugeValue,
			1, data.Version, c.instance)
	}

	// Service status — always fetched when plugin is present.
	status, present, sErr := client.FetchServiceStatusOptional("crowdsecServiceStatus")
	if sErr != nil {
		c.log.Warn("failed to fetch crowdsec service status", "err", sErr)
	} else if present {
		running := 0.0
		if status == "running" {
			running = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.serviceRunning, prometheus.GaugeValue,
			running, c.instance)
	}

	return nil
}
