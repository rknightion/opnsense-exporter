package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type dhcpv4Collector struct {
	log *slog.Logger

	leasesTotal   *prometheus.Desc
	leasesByIface *prometheus.Desc
	reservedTotal *prometheus.Desc
	dynamicTotal  *prometheus.Desc
	leaseInfo     *prometheus.Desc

	subsystem      string
	instance       string
	detailsEnabled bool
}

func init() {
	collectorInstances = append(collectorInstances, &dhcpv4Collector{
		subsystem: Dhcpv4Subsystem,
	})
}

func (c *dhcpv4Collector) Name() string {
	return c.subsystem
}

func (c *dhcpv4Collector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.leasesTotal = buildPrometheusDesc(c.subsystem, "leases_total",
		"Total number of ISC DHCPv4 leases",
		nil,
	)
	c.leasesByIface = buildPrometheusDesc(c.subsystem, "leases_by_interface",
		"Number of ISC DHCPv4 leases per interface",
		[]string{"interface"},
	)
	c.reservedTotal = buildPrometheusDesc(c.subsystem, "leases_reserved_total",
		"Total number of reserved (static) ISC DHCPv4 leases",
		nil,
	)
	c.dynamicTotal = buildPrometheusDesc(c.subsystem, "leases_dynamic_total",
		"Total number of dynamic ISC DHCPv4 leases",
		nil,
	)
	c.leaseInfo = buildPrometheusDesc(c.subsystem, "lease_info",
		"Per-lease ISC DHCPv4 information (value is always 1; use labels). Only emitted when --exporter.enable-dhcpv4-details is set.",
		[]string{"address", "hostname", "mac", "interface", "type", "state", "status"},
	)
}

func (c *dhcpv4Collector) SetDetailsEnabled(enabled bool) {
	c.detailsEnabled = enabled
}

func (c *dhcpv4Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.leasesTotal
	ch <- c.leasesByIface
	ch <- c.reservedTotal
	ch <- c.dynamicTotal
	ch <- c.leaseInfo
}

func (c *dhcpv4Collector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchDHCPv4Leases()
	if err != nil {
		return err
	}

	// The legacy ISC DHCPv4 plugin is deprecated and absent on modern boxes; a 404
	// yields Present=false. Stay completely silent then, so leases_total=0 (plugin
	// absent) is never confused with a present-but-empty server (#87).
	if !data.Present {
		return nil
	}

	ch <- prometheus.MustNewConstMetric(
		c.leasesTotal,
		prometheus.GaugeValue,
		float64(data.TotalLeases),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.reservedTotal,
		prometheus.GaugeValue,
		float64(data.ReservedCount),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.dynamicTotal,
		prometheus.GaugeValue,
		float64(data.DynamicCount),
		c.instance,
	)

	for iface, count := range data.LeasesByInterface {
		ch <- prometheus.MustNewConstMetric(
			c.leasesByIface,
			prometheus.GaugeValue,
			float64(count),
			iface,
			c.instance,
		)
	}

	if c.detailsEnabled {
		for _, lease := range data.Leases {
			ch <- prometheus.MustNewConstMetric(
				c.leaseInfo,
				prometheus.GaugeValue,
				1,
				lease.Address,
				lease.Hostname,
				lease.MAC,
				lease.IfDescr,
				lease.Type,
				lease.State,
				lease.Status,
				c.instance,
			)
		}
	}

	return nil
}
