package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type qfeedsCollector struct {
	log *slog.Logger

	feedsTotal            *prometheus.Desc
	feedEntries           *prometheus.Desc
	feedPacketsBlocked    *prometheus.Desc
	feedBytesBlocked      *prometheus.Desc
	feedAddressesBlocked  *prometheus.Desc
	feedLastUpdate        *prometheus.Desc
	feedNextUpdate        *prometheus.Desc
	totalEntries          *prometheus.Desc
	totalPacketsBlocked   *prometheus.Desc
	totalBytesBlocked     *prometheus.Desc
	totalAddressesBlocked *prometheus.Desc
	licenseInfo           *prometheus.Desc
	licenseExpiry         *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &qfeedsCollector{
		subsystem: QFeedsSubsystem,
	})
}

func (c *qfeedsCollector) Name() string { return c.subsystem }

func (c *qfeedsCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	feedLabels := []string{"feed"}

	c.feedsTotal = buildPrometheusDesc(c.subsystem, "feeds_total",
		"Total number of configured Q-Feeds threat intelligence feeds", nil)
	c.feedEntries = buildPrometheusDesc(c.subsystem, "feed_entries",
		"Current number of entries in this Q-Feeds feed", feedLabels)
	c.feedPacketsBlocked = buildPrometheusDesc(c.subsystem, "feed_packets_blocked_total",
		"Packets blocked by this Q-Feeds feed since last reset", feedLabels)
	c.feedBytesBlocked = buildPrometheusDesc(c.subsystem, "feed_bytes_blocked_total",
		"Bytes blocked by this Q-Feeds feed since last reset", feedLabels)
	c.feedAddressesBlocked = buildPrometheusDesc(c.subsystem, "feed_addresses_blocked",
		"Current number of addresses blocked by this Q-Feeds feed", feedLabels)
	c.feedLastUpdate = buildPrometheusDesc(c.subsystem, "feed_last_update_timestamp_seconds",
		"Unix timestamp of the last update for this Q-Feeds feed", feedLabels)
	c.feedNextUpdate = buildPrometheusDesc(c.subsystem, "feed_next_update_timestamp_seconds",
		"Unix timestamp of the next scheduled update for this Q-Feeds feed", feedLabels)
	c.totalEntries = buildPrometheusDesc(c.subsystem, "entries",
		"Total current entries across all Q-Feeds feeds", nil)
	c.totalPacketsBlocked = buildPrometheusDesc(c.subsystem, "packets_blocked_total",
		"Total packets blocked across all Q-Feeds feeds since last reset", nil)
	c.totalBytesBlocked = buildPrometheusDesc(c.subsystem, "bytes_blocked_total",
		"Total bytes blocked across all Q-Feeds feeds since last reset", nil)
	c.totalAddressesBlocked = buildPrometheusDesc(c.subsystem, "addresses_blocked",
		"Total current addresses blocked across all Q-Feeds feeds", nil)
	c.licenseInfo = buildPrometheusDesc(c.subsystem, "license_info",
		"Q-Feeds license information (value is always 1; see labels)", []string{"license"})
	c.licenseExpiry = buildPrometheusDesc(c.subsystem, "license_expiry_timestamp_seconds",
		"Unix timestamp of the Q-Feeds license expiry", nil)
}

func (c *qfeedsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.feedsTotal
	ch <- c.feedEntries
	ch <- c.feedPacketsBlocked
	ch <- c.feedBytesBlocked
	ch <- c.feedAddressesBlocked
	ch <- c.feedLastUpdate
	ch <- c.feedNextUpdate
	ch <- c.totalEntries
	ch <- c.totalPacketsBlocked
	ch <- c.totalBytesBlocked
	ch <- c.totalAddressesBlocked
	ch <- c.licenseInfo
	ch <- c.licenseExpiry
}

func (c *qfeedsCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchQFeedsStats()
	if err != nil {
		return err
	}
	if !data.Present {
		return nil
	}

	ch <- prometheus.MustNewConstMetric(c.feedsTotal, prometheus.GaugeValue,
		float64(len(data.Feeds)), c.instance)

	for _, f := range data.Feeds {
		ch <- prometheus.MustNewConstMetric(c.feedEntries, prometheus.GaugeValue,
			f.Entries, f.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.feedPacketsBlocked, prometheus.CounterValue,
			f.PacketsBlocked, f.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.feedBytesBlocked, prometheus.CounterValue,
			f.BytesBlocked, f.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.feedAddressesBlocked, prometheus.GaugeValue,
			f.AddressesBlocked, f.Name, c.instance)
		if f.HasLastUpdate {
			ch <- prometheus.MustNewConstMetric(c.feedLastUpdate, prometheus.GaugeValue,
				f.LastUpdateSeconds, f.Name, c.instance)
		}
		if f.HasNextUpdate {
			ch <- prometheus.MustNewConstMetric(c.feedNextUpdate, prometheus.GaugeValue,
				f.NextUpdateSeconds, f.Name, c.instance)
		}
	}

	ch <- prometheus.MustNewConstMetric(c.totalEntries, prometheus.GaugeValue,
		data.TotalEntries, c.instance)
	ch <- prometheus.MustNewConstMetric(c.totalPacketsBlocked, prometheus.CounterValue,
		data.TotalPacketsBlocked, c.instance)
	ch <- prometheus.MustNewConstMetric(c.totalBytesBlocked, prometheus.CounterValue,
		data.TotalBytesBlocked, c.instance)
	ch <- prometheus.MustNewConstMetric(c.totalAddressesBlocked, prometheus.GaugeValue,
		data.TotalAddressesBlocked, c.instance)

	if data.LicenseName != "" {
		ch <- prometheus.MustNewConstMetric(c.licenseInfo, prometheus.GaugeValue,
			1, data.LicenseName, c.instance)
	}
	if data.HasLicenseExpiry {
		ch <- prometheus.MustNewConstMetric(c.licenseExpiry, prometheus.GaugeValue,
			data.LicenseExpirySeconds, c.instance)
	}

	return nil
}
