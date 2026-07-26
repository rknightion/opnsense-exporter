package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type dyndnsCollector struct {
	log *slog.Logger

	accountsTotal  *prometheus.Desc
	accountEnabled *prometheus.Desc
	lastUpdate     *prometheus.Desc
	accountInfo    *prometheus.Desc
	serviceRunning *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &dyndnsCollector{
		subsystem: DynDNSSubsystem,
	})
}

func (c *dyndnsCollector) Name() string {
	return c.subsystem
}

func (c *dyndnsCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.accountsTotal = buildPrometheusDesc(c.subsystem, "accounts_total",
		"Total number of configured DynDNS accounts",
		nil,
	)
	c.accountEnabled = buildPrometheusDesc(c.subsystem, "account_enabled",
		"Whether this DynDNS account is enabled (1 = enabled, 0 = disabled)",
		[]string{"description", "service", "hostnames", "interface"},
	)
	// interface is included (matching the account_enabled/account_info sibling
	// metrics) so two dyndns accounts sharing description/service/hostnames but
	// bound to different interfaces — a normal dual-WAN failover setup — don't
	// collapse to the same label tuple and fail the whole scrape (#81).
	c.lastUpdate = buildPrometheusDesc(c.subsystem, "account_last_update_timestamp_seconds",
		"Unix timestamp of the last successful DynDNS IP update for this account",
		[]string{"description", "service", "hostnames", "interface"},
	)
	c.accountInfo = buildPrometheusDesc(c.subsystem, "account_info",
		"DynDNS account information (value is always 1; use labels)",
		[]string{"description", "service", "hostnames", "zone", "interface", "current_ip"},
	)
	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the DynDNS service is running (1 = running, 0 = stopped/disabled)",
		nil,
	)
}

func (c *dyndnsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.accountsTotal
	ch <- c.accountEnabled
	ch <- c.lastUpdate
	ch <- c.accountInfo
	ch <- c.serviceRunning
}

func (c *dyndnsCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchDynDNSAccounts()
	if err != nil {
		return err
	}

	// os-ddclient absent → Present=false; stay silent so accounts_total=0 (plugin
	// absent) is not confused with a present-but-unconfigured ddclient, and we do
	// not probe the service-status endpoint (which would 404-warn every scheduled poll) (#87).
	if !data.Present {
		return nil
	}

	ch <- prometheus.MustNewConstMetric(
		c.accountsTotal,
		prometheus.GaugeValue,
		float64(data.Total),
		c.instance,
	)

	for _, acct := range data.Accounts {
		enabledVal := 0.0
		if acct.Enabled {
			enabledVal = 1.0
		}

		ch <- prometheus.MustNewConstMetric(
			c.accountEnabled,
			prometheus.GaugeValue,
			enabledVal,
			acct.Description,
			acct.Service,
			acct.Hostnames,
			acct.Interface,
			c.instance,
		)

		ch <- prometheus.MustNewConstMetric(
			c.accountInfo,
			prometheus.GaugeValue,
			1,
			acct.Description,
			acct.Service,
			acct.Hostnames,
			acct.Zone,
			acct.Interface,
			acct.CurrentIP,
			c.instance,
		)

		// Only emit the timestamp metric when current_mtime was non-empty and
		// successfully parsed as RFC3339; skipped for never-updated accounts.
		if acct.HasLastUpdate {
			ch <- prometheus.MustNewConstMetric(
				c.lastUpdate,
				prometheus.GaugeValue,
				acct.LastUpdateSeconds,
				acct.Description,
				acct.Service,
				acct.Hostnames,
				acct.Interface,
				c.instance,
			)
		}
	}

	status, present, sErr := client.FetchServiceStatusOptional("dyndnsServiceStatus")
	if sErr != nil {
		c.log.Warn("failed to fetch dyndns service status", "err", sErr)
	} else if present {
		val := 0.0
		if status == "running" {
			val = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			c.serviceRunning, prometheus.GaugeValue,
			val, c.instance,
		)
	}

	return nil
}
