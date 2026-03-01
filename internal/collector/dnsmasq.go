package collector

import (
	"log/slog"

	"github.com/rknightion/opnsense-exporter/opnsense"
	"github.com/prometheus/client_golang/prometheus"
)

type dnsmasqCollector struct {
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
	collectorInstances = append(collectorInstances, &dnsmasqCollector{
		subsystem: DnsmasqSubsystem,
	})
}

func (c *dnsmasqCollector) Name() string {
	return c.subsystem
}

func (c *dnsmasqCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.leasesTotal = buildPrometheusDesc(c.subsystem, "leases_total",
		"Total number of DHCP leases",
		nil,
	)
	c.leasesByIface = buildPrometheusDesc(c.subsystem, "leases_by_interface",
		"Number of DHCP leases per interface",
		[]string{"interface"},
	)
	c.reservedTotal = buildPrometheusDesc(c.subsystem, "leases_reserved_total",
		"Total number of reserved (static) DHCP leases",
		nil,
	)
	c.dynamicTotal = buildPrometheusDesc(c.subsystem, "leases_dynamic_total",
		"Total number of dynamic DHCP leases",
		nil,
	)
	c.leaseInfo = buildPrometheusDesc(c.subsystem, "lease_info",
		"Per-lease information (value is expire timestamp). Only emitted when --exporter.enable-dnsmasq-details is set.",
		[]string{"address", "hostname", "hwaddr", "interface"},
	)
}

func (c *dnsmasqCollector) SetDetailsEnabled(enabled bool) {
	c.detailsEnabled = enabled
}

func (c *dnsmasqCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.leasesTotal
	ch <- c.leasesByIface
	ch <- c.reservedTotal
	ch <- c.dynamicTotal
	ch <- c.leaseInfo
}

func (c *dnsmasqCollector) Update(client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchDnsmasqLeases()
	if err != nil {
		return err
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
				float64(lease.Expire),
				lease.Address,
				lease.Hostname,
				lease.HWAddr,
				lease.IfDescr,
				c.instance,
			)
		}
	}

	return nil
}
