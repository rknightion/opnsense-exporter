package collector

import (
	"context"
	"log/slog"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// snapshotsCollector surfaces ZFS boot-environment inventory (#220): are
// pre-upgrade snapshots actually being made, the rollback safety net. A UFS
// box (or any box where bectl is unavailable) reports supported=0 with total=0
// — a normal, healthy shape, not an error. size is a human-formatted string on
// the wire and is deliberately not modelled as a metric.
type snapshotsCollector struct {
	log *slog.Logger

	supported              *prometheus.Desc
	total                  *prometheus.Desc
	activeCreatedTimestamp *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &snapshotsCollector{
		subsystem: SnapshotsSubsystem,
	})
}

func (c *snapshotsCollector) Name() string {
	return c.subsystem
}

func (c *snapshotsCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.supported = buildPrometheusDesc(c.subsystem, "supported",
		"Whether the root filesystem supports ZFS boot environments (1 = ZFS/bectl, 0 = e.g. UFS).",
		nil,
	)
	c.total = buildPrometheusDesc(c.subsystem, "total",
		"Number of ZFS boot environments currently present.",
		nil,
	)
	c.activeCreatedTimestamp = buildPrometheusDesc(c.subsystem, "active_created_timestamp_seconds",
		"Unix timestamp when the currently active boot environment (active flag containing \"N\") was created. Absent when no boot environment is marked active (e.g. unsupported filesystem).",
		nil,
	)
}

func (c *snapshotsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.supported
	ch <- c.total
	ch <- c.activeCreatedTimestamp
}

func (c *snapshotsCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	// The two endpoints are independent, so fetch them concurrently (mirrors
	// the netflow collector's #129 pattern) — wall time is bounded by the
	// slower of the two rather than their sum.
	var (
		supported    bool
		beData       opnsense.BootEnvironments
		supportedErr *opnsense.APICallError
		beErr        *opnsense.APICallError
	)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); supported, supportedErr = client.FetchSnapshotsSupported() }()
	go func() { defer wg.Done(); beData, beErr = client.FetchBootEnvironments() }()
	wg.Wait()

	if supportedErr != nil {
		return supportedErr
	}

	var supportedVal float64
	if supported {
		supportedVal = 1
	}
	ch <- prometheus.MustNewConstMetric(c.supported, prometheus.GaugeValue, supportedVal, c.instance)

	if beErr != nil {
		return beErr
	}

	ch <- prometheus.MustNewConstMetric(c.total, prometheus.GaugeValue, float64(beData.Total), c.instance)

	if beData.HasActive {
		ch <- prometheus.MustNewConstMetric(c.activeCreatedTimestamp, prometheus.GaugeValue, beData.ActiveCreatedTimestamp, c.instance)
	}

	return nil
}
