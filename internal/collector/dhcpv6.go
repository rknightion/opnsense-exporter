package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

type dhcpv6Collector struct {
	log *slog.Logger

	leasesTotal   *prometheus.Desc
	leasesByIface *prometheus.Desc
	reservedTotal *prometheus.Desc
	dynamicTotal  *prometheus.Desc
	leaseInfo     *prometheus.Desc
	pdTotal       *prometheus.Desc
	pdActive      *prometheus.Desc

	subsystem      string
	instance       string
	detailsEnabled bool
}

func init() {
	collectorInstances = append(collectorInstances, &dhcpv6Collector{
		subsystem: Dhcpv6Subsystem,
	})
}

func (c *dhcpv6Collector) Name() string {
	return c.subsystem
}

func (c *dhcpv6Collector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.leasesTotal = buildPrometheusDesc(c.subsystem, "leases",
		"Current number of ISC DHCPv6 leases",
		nil,
	)
	c.leasesByIface = buildPrometheusDesc(c.subsystem, "leases_by_interface",
		"Number of ISC DHCPv6 leases per interface",
		[]string{"interface"},
	)
	c.reservedTotal = buildPrometheusDesc(c.subsystem, "leases_reserved",
		"Current number of reserved (static) ISC DHCPv6 leases",
		nil,
	)
	c.dynamicTotal = buildPrometheusDesc(c.subsystem, "leases_dynamic",
		"Current number of dynamic ISC DHCPv6 leases",
		nil,
	)
	c.leaseInfo = buildPrometheusDesc(c.subsystem, "lease_info",
		"Per-lease ISC DHCPv6 information (value is always 1; use labels). Only emitted when "+
			"--exporter.enable-dhcpv6-details is set. `device` is the raw logical interface id and "+
			"`if_descr` the assigned description; they diverge on VLAN children and bridges, and "+
			"only `device` joins against the interfaces metrics (the #544 item-5 pattern).",
		[]string{"address", "mac", "duid", "if_descr", "state", "status", "type", "device"},
	)
	c.pdTotal = buildPrometheusDesc(c.subsystem, "pd_prefixes",
		"Current number of ISC DHCPv6 prefix delegation entries",
		nil,
	)
	c.pdActive = buildPrometheusDesc(c.subsystem, "pd_prefixes_active",
		"Number of active ISC DHCPv6 prefix delegation entries",
		nil,
	)
}

// SetDetailsEnabled controls whether per-lease lease_info metrics are emitted.
// Called by WithDhcpv6Details() at wiring time.
func (c *dhcpv6Collector) SetDetailsEnabled(enabled bool) {
	c.detailsEnabled = enabled
}

func (c *dhcpv6Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.leasesTotal
	ch <- c.leasesByIface
	ch <- c.reservedTotal
	ch <- c.dynamicTotal
	ch <- c.leaseInfo
	ch <- c.pdTotal
	ch <- c.pdActive
}

func (c *dhcpv6Collector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	leases, err := client.FetchDHCPv6Leases()
	if err != nil {
		return err
	}

	// FetchDHCPv6Leases initialises LeasesByInterface only when the endpoint
	// responds (404 leaves it nil), so a nil map is the plugin-absent signal here.
	// (The dhcpv4 sibling uses an explicit Present flag for the same purpose.)
	// When the plugin is absent, stay completely silent.
	if leases.LeasesByInterface == nil {
		return nil
	}

	ch <- prometheus.MustNewConstMetric(
		c.leasesTotal,
		prometheus.GaugeValue,
		float64(leases.TotalLeases),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.reservedTotal,
		prometheus.GaugeValue,
		float64(leases.ReservedCount),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.dynamicTotal,
		prometheus.GaugeValue,
		float64(leases.DynamicCount),
		c.instance,
	)

	for iface, count := range leases.LeasesByInterface {
		ch <- prometheus.MustNewConstMetric(
			c.leasesByIface,
			prometheus.GaugeValue,
			float64(count),
			iface,
			c.instance,
		)
	}

	if c.detailsEnabled {
		for _, lease := range leases.Leases {
			ch <- prometheus.MustNewConstMetric(
				c.leaseInfo,
				prometheus.GaugeValue,
				1,
				lease.Address,
				lease.MAC,
				lease.DUID,
				lease.IfDescr,
				lease.State,
				lease.Status,
				lease.Type,
				lease.Device,
				c.instance,
			)
		}
	}

	prefixes, perr := client.FetchDHCPv6Prefixes()
	if perr != nil {
		c.log.Warn("failed to fetch DHCPv6 prefix delegation data", "err", perr)
		// Still emit what we have from leases; skip prefix metrics.
		return nil
	}

	ch <- prometheus.MustNewConstMetric(
		c.pdTotal,
		prometheus.GaugeValue,
		float64(prefixes.Total),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.pdActive,
		prometheus.GaugeValue,
		float64(prefixes.Active),
		c.instance,
	)

	return nil
}
