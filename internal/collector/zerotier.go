package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

type zeroTierCollector struct {
	log *slog.Logger

	networksTotal        *prometheus.Desc
	networkEnabled       *prometheus.Desc
	networkStatus        *prometheus.Desc
	networkAssignedAddrs *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &zeroTierCollector{
		subsystem: ZeroTierSubsystem,
	})
}

func (c *zeroTierCollector) Name() string {
	return c.subsystem
}

func (c *zeroTierCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.networksTotal = buildPrometheusDesc(c.subsystem, "networks_configured",
		"Total number of configured ZeroTier networks returned by the plugin network search endpoint", nil)
	c.networkEnabled = buildPrometheusDesc(c.subsystem, "network_enabled",
		"Whether a configured ZeroTier network is enabled (1 = enabled, 0 = disabled)", []string{"network_id"})
	c.networkStatus = buildPrometheusDesc(c.subsystem, "network_status",
		"Current ZeroTier status for a configured network (value is always 1; status is the closed ZeroTier status vocabulary or unknown)", []string{"network_id", "status"})
	c.networkAssignedAddrs = buildPrometheusDesc(c.subsystem, "network_assigned_addresses",
		"Number of ZeroTier addresses assigned to this node on the network", []string{"network_id"})
}

func (c *zeroTierCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.networksTotal
	ch <- c.networkEnabled
	ch <- c.networkStatus
	ch <- c.networkAssignedAddrs
}

func (c *zeroTierCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchZeroTierNetworks()
	if err != nil {
		return err
	}
	if !data.Present {
		// os-zerotier is absent. The client treats search's 404 as a
		// feature-absence result, and the registry wires its negative TTL;
		// keep the collector silent rather than exporting zero as if the
		// plugin were installed but unconfigured.
		return nil
	}

	ch <- prometheus.MustNewConstMetric(c.networksTotal, prometheus.GaugeValue,
		float64(data.Total), c.instance)

	for _, network := range data.Networks {
		enabled := 0.0
		if network.Enabled {
			enabled = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.networkEnabled, prometheus.GaugeValue,
			enabled, network.NetworkID, c.instance)

		// A successful info call with a malformed/unavailable message has no
		// trustworthy runtime state. Do not turn that into a fabricated
		// status or zero address count.
		if network.HasStatus {
			ch <- prometheus.MustNewConstMetric(c.networkStatus, prometheus.GaugeValue,
				1, network.NetworkID, network.Status, c.instance)
		}
		if network.HasAssignedAddresses {
			ch <- prometheus.MustNewConstMetric(c.networkAssignedAddrs, prometheus.GaugeValue,
				float64(network.AssignedAddresses), network.NetworkID, c.instance)
		}
	}

	return nil
}
