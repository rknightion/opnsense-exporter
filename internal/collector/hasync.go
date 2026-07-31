package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// hasyncCollector collects HA sync status metrics by querying the two
// api/core/hasync_status/* endpoints on every scheduled poll. This involves a live
// XML-RPC call to the configured HA peer — real per-poll network cost — so
// the collector is opt-in (exporter.enable-hasync, default off, decision D6).
//
// When HA is unconfigured or the peer is unreachable the version endpoint
// returns an error envelope; the collector is completely silent in that case
// so single-node boxes are not polluted with 0-valued HA metrics.
type hasyncCollector struct {
	log *slog.Logger

	remoteReachable      *prometheus.Desc
	remoteVersionMatch   *prometheus.Desc
	remoteVersionInfo    *prometheus.Desc
	remoteServicesTotal  *prometheus.Desc
	remoteServiceRunning *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &hasyncCollector{
		subsystem: HasyncSubsystem,
	})
}

func (c *hasyncCollector) Name() string { return c.subsystem }

func (c *hasyncCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.remoteReachable = buildPrometheusDesc(c.subsystem, "remote_reachable",
		"Whether the HA sync remote peer is reachable (1 = reachable, 0 = unreachable/unconfigured)", nil)
	c.remoteVersionMatch = buildPrometheusDesc(c.subsystem, "remote_version_match",
		"Whether the remote peer firmware version matches the local version (1 = match, 0 = mismatch)", nil)
	c.remoteVersionInfo = buildPrometheusDesc(c.subsystem, "remote_version_info",
		"HA sync firmware version information (value is always 1; see labels)",
		[]string{"remote_version", "local_version"})
	c.remoteServicesTotal = buildPrometheusDesc(c.subsystem, "remote_services_total",
		"Total number of services in the cached remote HA peer service list", nil)
	c.remoteServiceRunning = buildPrometheusDesc(c.subsystem, "remote_service_running",
		"Whether a service is running on the remote HA peer (1 = running, 0 = stopped)",
		[]string{"service", "id"})
}

func (c *hasyncCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.remoteReachable,
		c.remoteVersionMatch,
		c.remoteVersionInfo,
		c.remoteServicesTotal,
		c.remoteServiceRunning,
	} {
		ch <- d
	}
}

func (c *hasyncCollector) Update(_ context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchHasyncStatus()
	if err != nil {
		return err
	}

	// Unconfigured peer or unreachable: stay completely silent.
	// The collector is opt-in (D6) precisely to avoid polluting single-node
	// dashboards with 0-valued HA metrics on every scrape.
	if !data.Reachable {
		return nil
	}

	versionMatch := 0.0
	if data.VersionMatch {
		versionMatch = 1.0
	}

	ch <- prometheus.MustNewConstMetric(c.remoteReachable, prometheus.GaugeValue,
		1, c.instance)
	ch <- prometheus.MustNewConstMetric(c.remoteVersionMatch, prometheus.GaugeValue,
		versionMatch, c.instance)
	ch <- prometheus.MustNewConstMetric(c.remoteVersionInfo, prometheus.GaugeValue,
		1, data.RemoteVersion, data.LocalVersion, c.instance)
	ch <- prometheus.MustNewConstMetric(c.remoteServicesTotal, prometheus.GaugeValue,
		float64(len(data.Services)), c.instance)

	for _, svc := range data.Services {
		ch <- prometheus.MustNewConstMetric(c.remoteServiceRunning, prometheus.GaugeValue,
			svc.Running, svc.Name, svc.ID, c.instance)
	}

	return nil
}
