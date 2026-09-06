package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// captivePortalVoucherStates is the fixed, known set of states OPNsense's
// core Voucher auth connector emits (see opnsense.captivePortalVoucherRow).
// Every configured (provider, group) always gets one series per state here
// (0-filled when absent), so rate()/alerting queries never see a gap; any
// unrecognised future state the box reports is still emitted, just without
// the zero-fill guarantee.
var captivePortalVoucherStates = []string{"valid", "unused", "expired"}

type captivePortalCollector struct {
	log *slog.Logger

	serviceRunning    *prometheus.Desc
	zonesTotal        *prometheus.Desc
	sessionsTotal     *prometheus.Desc
	zoneSessions      *prometheus.Desc
	vouchers          *prometheus.Desc
	voucherNextExpiry *prometheus.Desc

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
	c.zonesTotal = buildPrometheusDesc(c.subsystem, "zones",
		"Current number of configured captive portal zones (including disabled zones)", nil)
	c.sessionsTotal = buildPrometheusDesc(c.subsystem, "sessions",
		"Current number of active captive portal sessions across all zones", nil)
	c.zoneSessions = buildPrometheusDesc(c.subsystem, "zone_sessions",
		"Number of active captive portal sessions in this zone",
		[]string{"zone_id", "zone_description"})
	c.vouchers = buildPrometheusDesc(c.subsystem, "vouchers",
		"Number of captive portal vouchers in this group by state (valid, unused, expired)",
		[]string{"provider", "group", "state"})
	c.voucherNextExpiry = buildPrometheusDesc(c.subsystem, "voucher_group_next_expiry_timestamp_seconds",
		"Unix timestamp of the earliest hard expiry deadline among this group's unused/valid vouchers (absent when no voucher in the group has one set)",
		[]string{"provider", "group"})
}

func (c *captivePortalCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.serviceRunning, c.zonesTotal, c.sessionsTotal, c.zoneSessions,
		c.vouchers, c.voucherNextExpiry,
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

	vouchers, vErr := client.FetchCaptivePortalVouchers()
	if vErr != nil {
		c.log.Warn("failed to fetch captive portal vouchers", "err", vErr)
	} else if vouchers.Present {
		for _, g := range vouchers.Groups {
			// Emit every known state (0-filled when absent) plus any
			// unrecognised state the box reported, so alerting/rate() queries
			// never see a gap for a configured group.
			seen := make(map[string]bool, len(captivePortalVoucherStates))
			for _, state := range captivePortalVoucherStates {
				seen[state] = true
				ch <- prometheus.MustNewConstMetric(c.vouchers, prometheus.GaugeValue,
					g.Counts[state], g.Provider, g.Group, state, c.instance)
			}
			for state, count := range g.Counts {
				if seen[state] {
					continue
				}
				ch <- prometheus.MustNewConstMetric(c.vouchers, prometheus.GaugeValue,
					count, g.Provider, g.Group, state, c.instance)
			}

			if g.HasNextExpiryTimestamp {
				ch <- prometheus.MustNewConstMetric(c.voucherNextExpiry, prometheus.GaugeValue,
					g.NextExpiryTimestamp, g.Provider, g.Group, c.instance)
			}
		}
	}

	return nil
}
