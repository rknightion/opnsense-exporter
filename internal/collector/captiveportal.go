package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type captivePortalCollector struct {
	log *slog.Logger

	serviceRunning *prometheus.Desc
	zonesTotal     *prometheus.Desc
	sessionsTotal  *prometheus.Desc
	zoneSessions   *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &captivePortalCollector{
		subsystem: CaptivePortalSubsystem,
	})
}

func (c *captivePortalCollector) Name() string { return c.subsystem }

func (c *captivePortalCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the captive portal service is running (1 = running, 0 = stopped/disabled)", nil)
	c.zonesTotal = buildPrometheusDesc(c.subsystem, "zones_total",
		"Number of configured captive portal zones (including disabled zones)", nil)
	c.sessionsTotal = buildPrometheusDesc(c.subsystem, "sessions_total",
		"Total number of active captive portal sessions across all zones", nil)
	c.zoneSessions = buildPrometheusDesc(c.subsystem, "zone_sessions",
		"Number of active captive portal sessions in this zone",
		[]string{"zone_id", "zone_description"})
}

func (c *captivePortalCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.serviceRunning, c.zonesTotal, c.sessionsTotal, c.zoneSessions,
	} {
		ch <- d
	}
}

func (c *captivePortalCollector) Update(_ context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchCaptivePortalSessions()
	if err != nil {
		return err
	}

	// Feature absent (zones endpoint 404): stay completely silent and skip the
	// service-status probe — the service endpoint would just 404 too.
	if !data.Present {
		return nil
	}

	// Count configured zones only (excluding the synthetic "unknown" entry).
	configuredZones := 0.0
	for _, z := range data.Zones {
		if z.ZoneID != "unknown" {
			configuredZones++
		}
	}

	ch <- prometheus.MustNewConstMetric(c.zonesTotal, prometheus.GaugeValue,
		configuredZones, c.instance)
	ch <- prometheus.MustNewConstMetric(c.sessionsTotal, prometheus.GaugeValue,
		data.SessionsTotal, c.instance)

	for _, zone := range data.Zones {
		ch <- prometheus.MustNewConstMetric(c.zoneSessions, prometheus.GaugeValue,
			zone.Sessions, zone.ZoneID, zone.Description, c.instance)
	}

	status, present, sErr := client.FetchServiceStatusOptional("captivePortalServiceStatus")
	if sErr != nil {
		c.log.Warn("failed to fetch captive portal service status", "err", sErr)
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
