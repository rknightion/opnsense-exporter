package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

// backupCollector surfaces config-backup freshness (#220): is the firewall's
// own configuration actually being backed up, and how stale is the newest
// copy. Silent backup failure is otherwise invisible — OPNsense keeps
// retrying/rotating quietly. No per-backup labels are emitted: descriptions
// and usernames can carry hostnames/admin identity, so only the aggregate
// count/timestamp/size are surfaced.
type backupCollector struct {
	log *slog.Logger

	lastTimestamp *prometheus.Desc
	count         *prometheus.Desc
	lastSizeBytes *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &backupCollector{
		subsystem: BackupSubsystem,
	})
}

func (c *backupCollector) Name() string {
	return c.subsystem
}

func (c *backupCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.lastTimestamp = buildPrometheusDesc(c.subsystem, "last_timestamp_seconds",
		"Unix timestamp of the newest retained config backup. Compare against time() to alert on stale/silent backup failure.",
		nil,
	)
	c.count = buildPrometheusDesc(c.subsystem, "count",
		"Number of config backups OPNsense currently retains.",
		nil,
	)
	c.lastSizeBytes = buildPrometheusDesc(c.subsystem, "last_size_bytes",
		"Size in bytes of the newest retained config backup.",
		nil,
	)
}

func (c *backupCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.lastTimestamp
	ch <- c.count
	ch <- c.lastSizeBytes
}

func (c *backupCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchConfigBackupHistory()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(c.lastTimestamp, prometheus.GaugeValue, data.LastTimestamp, c.instance)
	ch <- prometheus.MustNewConstMetric(c.count, prometheus.GaugeValue, float64(data.Count), c.instance)
	ch <- prometheus.MustNewConstMetric(c.lastSizeBytes, prometheus.GaugeValue, data.LastSizeBytes, c.instance)

	return nil
}
