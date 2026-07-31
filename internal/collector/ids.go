package collector

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// idsCollector collects Suricata IDS/IPS metrics (opnsense_ids_*).
//
// IDS is a CORE subsystem, not a plugin — its endpoints do not 404 when
// Suricata is unconfigured (status returns "disabled", data endpoints return
// empty structures), so nothing here is treated as "feature absent".
//
// The default-on part (service status, IPS/promiscuous mode, eve log inventory,
// ruleset inventory, installed-rule count) is cheap. The alert-activity part
// (recent_alerts) is opt-in via --exporter.enable-ids-alerts because it triggers
// a reverse read of eve.json on the box each scheduled poll; when enabled, alertLookback
// bounds the window counted.
//
// All alert-derived series are GAUGES by design: query_alerts reads a windowed,
// saturating backend, so a monotonic counter is impossible without unbounded
// reads. No per-SID / per-signature / per-IP labels are ever emitted — only
// bounded labels (action, filename, ruleset).
type idsCollector struct {
	log *slog.Logger

	status         *prometheus.Desc
	ipsMode        *prometheus.Desc
	promiscuous    *prometheus.Desc
	alertLogFiles  *prometheus.Desc
	alertLogSize   *prometheus.Desc
	recentAlerts   *prometheus.Desc
	rulesetEnabled *prometheus.Desc
	rulesetUpdated *prometheus.Desc
	installedRules *prometheus.Desc

	subsystem     string
	instance      string
	alertsEnabled bool
	alertLookback time.Duration
}

func init() {
	collectorInstances = append(collectorInstances, &idsCollector{
		subsystem: IDSSubsystem,
	})
}

func (c *idsCollector) Name() string { return c.subsystem }

// SetAlertsEnabled turns on the opt-in recent-alerts series and sets the
// lookback window counted from query_alerts.
func (c *idsCollector) SetAlertsEnabled(enabled bool, lookback time.Duration) {
	c.alertsEnabled = enabled
	c.alertLookback = lookback
}

func (c *idsCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.status = buildPrometheusDesc(c.subsystem, "status",
		"Suricata IDS/IPS service status (1 = running, 0 = stopped, -1 = disabled/unconfigured)", nil)
	c.ipsMode = buildPrometheusDesc(c.subsystem, "ips_mode_enabled",
		"Whether Suricata runs inline as an IPS that drops traffic (1) rather than a passive IDS (0)", nil)
	c.promiscuous = buildPrometheusDesc(c.subsystem, "promiscuous_mode_enabled",
		"Whether the IDS monitoring interface is in promiscuous mode (1 = yes, 0 = no)", nil)
	c.alertLogFiles = buildPrometheusDesc(c.subsystem, "alert_log_files",
		"Number of Suricata eve log files on disk (the live eve.json plus rotated copies)", nil)
	c.alertLogSize = buildPrometheusDesc(c.subsystem, "alert_log_size_bytes",
		"Size in bytes of each Suricata eve log file", []string{"filename"})
	c.recentAlerts = buildPrometheusDesc(c.subsystem, "recent_alerts",
		"Suricata alerts observed within the lookback window (--exporter.ids-alert-lookback), by action. "+
			"A GAUGE, not a counter (query_alerts reads a windowed, saturating backend); a floor when more "+
			"than 500 alerts fall inside the window. Requires --exporter.enable-ids-alerts.", []string{"action"})
	c.rulesetEnabled = buildPrometheusDesc(c.subsystem, "ruleset_enabled",
		"Whether an installable Suricata ruleset is enabled (1) or disabled (0), by ruleset filename", []string{"ruleset"})
	c.rulesetUpdated = buildPrometheusDesc(c.subsystem, "ruleset_last_updated_timestamp_seconds",
		"Unix timestamp of the last download of a ruleset (best-effort from the box-local modified time; omitted when never downloaded)", []string{"ruleset"})
	c.installedRules = buildPrometheusDesc(c.subsystem, "installed_rules_total",
		"Total number of installed Suricata rules in the rule cache (a current count; treat as RAW, not rate)", nil)
}

func (c *idsCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.status, c.ipsMode, c.promiscuous, c.alertLogFiles, c.alertLogSize,
		c.recentAlerts, c.rulesetEnabled, c.rulesetUpdated, c.installedRules,
	} {
		ch <- d
	}
}

// idsStatusValue maps the Suricata service status string to a tri-state gauge.
func idsStatusValue(s string) float64 {
	switch s {
	case "running":
		return 1
	case "disabled":
		return -1
	default:
		// "stopped" and any unexpected value.
		return 0
	}
}

func (c *idsCollector) Update(_ context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	info, err := client.FetchIDS()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(c.status, prometheus.GaugeValue,
		idsStatusValue(info.Status), c.instance)
	ch <- prometheus.MustNewConstMetric(c.ipsMode, prometheus.GaugeValue,
		boolToGauge(info.IPSMode), c.instance)
	ch <- prometheus.MustNewConstMetric(c.promiscuous, prometheus.GaugeValue,
		boolToGauge(info.PromiscuousMode), c.instance)

	ch <- prometheus.MustNewConstMetric(c.alertLogFiles, prometheus.GaugeValue,
		float64(len(info.AlertLogs)), c.instance)
	for _, l := range info.AlertLogs {
		ch <- prometheus.MustNewConstMetric(c.alertLogSize, prometheus.GaugeValue,
			l.SizeBytes, l.Filename, c.instance)
	}

	for _, r := range info.Rulesets {
		ch <- prometheus.MustNewConstMetric(c.rulesetEnabled, prometheus.GaugeValue,
			boolToGauge(r.Enabled), r.Filename, c.instance)
		if r.HasLastUpdated {
			ch <- prometheus.MustNewConstMetric(c.rulesetUpdated, prometheus.GaugeValue,
				r.LastUpdated, r.Filename, c.instance)
		}
	}

	ch <- prometheus.MustNewConstMetric(c.installedRules, prometheus.GaugeValue,
		info.InstalledRulesTotal, c.instance)

	// Opt-in alert activity: a separate reverse read of eve.json. A failure here
	// must not drop the default-on series already emitted above, so it is logged
	// rather than returned.
	if c.alertsEnabled {
		act, aErr := client.FetchIDSRecentAlerts(c.alertLookback)
		if aErr != nil {
			c.log.Warn("failed to fetch IDS recent alerts", "err", aErr)
		} else {
			for action, count := range act.ByAction {
				ch <- prometheus.MustNewConstMetric(c.recentAlerts, prometheus.GaugeValue,
					count, action, c.instance)
			}
		}
	}

	return nil
}
