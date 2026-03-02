package collector

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type keaCollector struct {
	log *slog.Logger

	dhcp4LeasesTotal   *prometheus.Desc
	dhcp4LeasesByIface *prometheus.Desc
	dhcp4ReservedTotal *prometheus.Desc
	dhcp4DynamicTotal  *prometheus.Desc
	dhcp4LeaseInfo     *prometheus.Desc

	dhcp6LeasesTotal   *prometheus.Desc
	dhcp6LeasesByIface *prometheus.Desc
	dhcp6ReservedTotal *prometheus.Desc
	dhcp6DynamicTotal  *prometheus.Desc
	dhcp6LeaseInfo     *prometheus.Desc

	subsystem      string
	instance       string
	detailsEnabled bool
}

func init() {
	collectorInstances = append(collectorInstances, &keaCollector{
		subsystem: KeaSubsystem,
	})
}

func (c *keaCollector) Name() string {
	return c.subsystem
}

func (c *keaCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	// DHCPv4 metrics
	c.dhcp4LeasesTotal = buildPrometheusDesc(c.subsystem, "dhcp4_leases_total",
		"Total number of Kea DHCPv4 leases",
		nil,
	)
	c.dhcp4LeasesByIface = buildPrometheusDesc(c.subsystem, "dhcp4_leases_by_interface",
		"Number of Kea DHCPv4 leases per interface",
		[]string{"interface"},
	)
	c.dhcp4ReservedTotal = buildPrometheusDesc(c.subsystem, "dhcp4_leases_reserved_total",
		"Total number of reserved (static) Kea DHCPv4 leases",
		nil,
	)
	c.dhcp4DynamicTotal = buildPrometheusDesc(c.subsystem, "dhcp4_leases_dynamic_total",
		"Total number of dynamic Kea DHCPv4 leases",
		nil,
	)
	c.dhcp4LeaseInfo = buildPrometheusDesc(c.subsystem, "dhcp4_lease_info",
		"Per-lease DHCPv4 information (value is expire timestamp). Only emitted when --exporter.enable-kea-details is set.",
		[]string{"address", "hostname", "hwaddr", "interface"},
	)

	// DHCPv6 metrics
	c.dhcp6LeasesTotal = buildPrometheusDesc(c.subsystem, "dhcp6_leases_total",
		"Total number of Kea DHCPv6 leases",
		nil,
	)
	c.dhcp6LeasesByIface = buildPrometheusDesc(c.subsystem, "dhcp6_leases_by_interface",
		"Number of Kea DHCPv6 leases per interface",
		[]string{"interface"},
	)
	c.dhcp6ReservedTotal = buildPrometheusDesc(c.subsystem, "dhcp6_leases_reserved_total",
		"Total number of reserved (static) Kea DHCPv6 leases",
		nil,
	)
	c.dhcp6DynamicTotal = buildPrometheusDesc(c.subsystem, "dhcp6_leases_dynamic_total",
		"Total number of dynamic Kea DHCPv6 leases",
		nil,
	)
	c.dhcp6LeaseInfo = buildPrometheusDesc(c.subsystem, "dhcp6_lease_info",
		"Per-lease DHCPv6 information (value is expire timestamp). Only emitted when --exporter.enable-kea-details is set.",
		[]string{"address", "hostname", "hwaddr", "interface"},
	)
}

func (c *keaCollector) SetDetailsEnabled(enabled bool) {
	c.detailsEnabled = enabled
}

func (c *keaCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.dhcp4LeasesTotal
	ch <- c.dhcp4LeasesByIface
	ch <- c.dhcp4ReservedTotal
	ch <- c.dhcp4DynamicTotal
	ch <- c.dhcp4LeaseInfo

	ch <- c.dhcp6LeasesTotal
	ch <- c.dhcp6LeasesByIface
	ch <- c.dhcp6ReservedTotal
	ch <- c.dhcp6DynamicTotal
	ch <- c.dhcp6LeaseInfo
}

func (c *keaCollector) Update(client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	var firstErr *opnsense.APICallError

	// Fetch and emit DHCPv4 metrics
	v4Data, err := client.FetchKeaLeases4()
	if err != nil {
		firstErr = err
		c.log.Error("failed to fetch Kea DHCPv4 leases", "err", err)
	} else {
		c.emitLeaseMetrics(ch, v4Data,
			c.dhcp4LeasesTotal,
			c.dhcp4ReservedTotal,
			c.dhcp4DynamicTotal,
			c.dhcp4LeasesByIface,
			c.dhcp4LeaseInfo,
		)
	}

	// Fetch and emit DHCPv6 metrics
	v6Data, err := client.FetchKeaLeases6()
	if err != nil {
		if firstErr == nil {
			firstErr = err
		}
		c.log.Error("failed to fetch Kea DHCPv6 leases", "err", err)
	} else {
		c.emitLeaseMetrics(ch, v6Data,
			c.dhcp6LeasesTotal,
			c.dhcp6ReservedTotal,
			c.dhcp6DynamicTotal,
			c.dhcp6LeasesByIface,
			c.dhcp6LeaseInfo,
		)
	}

	return firstErr
}

func (c *keaCollector) emitLeaseMetrics(
	ch chan<- prometheus.Metric,
	data opnsense.KeaLeases,
	leasesTotal, reservedTotal, dynamicTotal, leasesByIface, leaseInfo *prometheus.Desc,
) {
	ch <- prometheus.MustNewConstMetric(
		leasesTotal,
		prometheus.GaugeValue,
		float64(data.TotalLeases),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		reservedTotal,
		prometheus.GaugeValue,
		float64(data.ReservedCount),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		dynamicTotal,
		prometheus.GaugeValue,
		float64(data.DynamicCount),
		c.instance,
	)

	for iface, count := range data.LeasesByInterface {
		ch <- prometheus.MustNewConstMetric(
			leasesByIface,
			prometheus.GaugeValue,
			float64(count),
			iface,
			c.instance,
		)
	}

	if c.detailsEnabled {
		for _, lease := range data.Leases {
			ch <- prometheus.MustNewConstMetric(
				leaseInfo,
				prometheus.GaugeValue,
				float64(lease.Expire),
				lease.Address,
				lease.Hostname,
				lease.HWAddr,
				lease.IfDescr,
				c.instance,
			)
		}
	}
}
