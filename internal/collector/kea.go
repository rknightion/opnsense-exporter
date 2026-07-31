package collector

import (
	"context"
	"log/slog"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type keaCollector struct {
	log *slog.Logger

	dhcp4LeasesTotal   *prometheus.Desc
	dhcp4LeasesByIface *prometheus.Desc
	dhcp4ReservedTotal *prometheus.Desc
	dhcp4DynamicTotal  *prometheus.Desc
	dhcp4LeasesByState *prometheus.Desc
	dhcp4LeaseInfo     *prometheus.Desc
	dhcp4PoolStats     *prometheus.Desc

	dhcp6LeasesTotal   *prometheus.Desc
	dhcp6LeasesByIface *prometheus.Desc
	dhcp6ReservedTotal *prometheus.Desc
	dhcp6DynamicTotal  *prometheus.Desc
	dhcp6LeasesByState *prometheus.Desc
	dhcp6LeasesByType  *prometheus.Desc
	dhcp6LeaseInfo     *prometheus.Desc
	dhcp6PoolStats     *prometheus.Desc

	serviceRunning *prometheus.Desc
	dhcp4PoolSize  *prometheus.Desc
	dhcp6PoolSize  *prometheus.Desc
	dhcp4PoolUsed  *prometheus.Desc
	dhcp6PoolUsed  *prometheus.Desc
	dhcp6PdPoolCap *prometheus.Desc

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
	c.dhcp4LeasesByState = buildPrometheusDesc(c.subsystem, "dhcp4_leases_by_state",
		"Number of Kea DHCPv4 leases per lease state (active, declined, expired-reclaimed)",
		[]string{"state"},
	)
	c.dhcp4LeaseInfo = buildPrometheusDesc(c.subsystem, "dhcp4_lease_info",
		"Per-lease DHCPv4 information (value is expire timestamp). Only emitted when --exporter.enable-kea-details is set.",
		[]string{"address", "hostname", "hwaddr", "interface", "vendor", "valid_lifetime", "client_id"},
	)
	c.dhcp4PoolStats = buildPrometheusDesc(c.subsystem, "dhcp4_lease_pool_stats",
		"Kea's own DHCPv4 lease pool accounting (the response's top-level `stats` object, computed "+
			"over the FULL lease population), by pool_state (active/inactive/total). Authoritative and "+
			"never truncated by bootgrid pagination, unlike a row-derived count -- a complement to the "+
			"other DHCPv4 lease metrics in this collector, not a replacement for any of them.",
		[]string{"pool_state"},
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
	c.dhcp6LeasesByState = buildPrometheusDesc(c.subsystem, "dhcp6_leases_by_state",
		"Number of Kea DHCPv6 leases per lease state (active, declined, expired-reclaimed)",
		[]string{"state"},
	)
	c.dhcp6LeasesByType = buildPrometheusDesc(c.subsystem, "dhcp6_leases_by_type",
		"Number of Kea DHCPv6 leases per lease type (IA_NA address lease vs IA_PD prefix delegation)",
		[]string{"type"},
	)
	c.dhcp6LeaseInfo = buildPrometheusDesc(c.subsystem, "dhcp6_lease_info",
		"Per-lease DHCPv6 information (value is expire timestamp). Only emitted when --exporter.enable-kea-details is set. "+
			"prefix_len is the delegated prefix's block size (e.g. 56 for a /56) for an IA_PD "+
			"(prefix-delegation) lease; for an IA_NA (address) lease it carries Kea's fixed 128 "+
			"(a single address has no delegated block).",
		// No client_id label here: Kea's lease6-get-all response carries no
		// "client-id" key (DHCPv6 identifies clients by DUID, not option
		// 61), so on v6 it would always be an empty label — dropped rather
		// than modeled as dead weight.
		[]string{"address", "hostname", "hwaddr", "interface", "vendor", "valid_lifetime", "prefix_len"},
	)
	c.dhcp6PoolStats = buildPrometheusDesc(c.subsystem, "dhcp6_lease_pool_stats",
		"Kea's own DHCPv6 lease pool accounting (the response's top-level `stats` object, computed "+
			"over the FULL lease population), by pool_state (active/inactive/total). Authoritative and "+
			"never truncated by bootgrid pagination, unlike a row-derived count -- a complement to the "+
			"other DHCPv6 lease metrics in this collector, not a replacement for any of them.",
		[]string{"pool_state"},
	)

	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the Kea DHCP service is running (1 = running, 0 = stopped/disabled)",
		nil,
	)
	c.dhcp4PoolSize = buildPrometheusDesc(c.subsystem, "dhcp4_pool_size",
		"Number of addresses in the configured Kea DHCPv4 pools for this subnet",
		[]string{"subnet", "interface"},
	)
	c.dhcp6PoolSize = buildPrometheusDesc(c.subsystem, "dhcp6_pool_size",
		"Number of addresses in the configured Kea DHCPv6 pools for this subnet",
		[]string{"subnet", "interface"},
	)
	c.dhcp4PoolUsed = buildPrometheusDesc(c.subsystem, "dhcp4_pool_used",
		"Number of Kea DHCPv4 leases whose address falls within this subnet's configured pool",
		[]string{"subnet"},
	)
	c.dhcp6PoolUsed = buildPrometheusDesc(c.subsystem, "dhcp6_pool_used",
		"Number of Kea DHCPv6 address (non-PD) leases whose address falls within this subnet's configured pool",
		[]string{"subnet"},
	)
	c.dhcp6PdPoolCap = buildPrometheusDesc(c.subsystem, "dhcp6_pd_pool_size",
		"Delegable-prefix capacity of a configured Kea DHCPv6 prefix-delegation pool (2^(delegated_len-prefix_len))",
		[]string{"subnet", "prefix"},
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
	ch <- c.dhcp4LeasesByState
	ch <- c.dhcp4LeaseInfo
	ch <- c.dhcp4PoolStats

	ch <- c.dhcp6LeasesTotal
	ch <- c.dhcp6LeasesByIface
	ch <- c.dhcp6ReservedTotal
	ch <- c.dhcp6DynamicTotal
	ch <- c.dhcp6LeasesByState
	ch <- c.dhcp6LeasesByType
	ch <- c.dhcp6LeaseInfo
	ch <- c.dhcp6PoolStats

	ch <- c.serviceRunning
	ch <- c.dhcp4PoolSize
	ch <- c.dhcp6PoolSize
	ch <- c.dhcp4PoolUsed
	ch <- c.dhcp6PoolUsed
	ch <- c.dhcp6PdPoolCap
}

func (c *keaCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
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
			c.dhcp4LeasesByState,
			nil, // DHCPv4 leases have no lease-type concept
			c.dhcp4LeaseInfo,
			c.dhcp4PoolStats,
			true,  // includeClientID: genuine DHCPv4 option 61
			false, // includePrefixLen: meaningless on v4 (Kea has no v4 prefix-length concept; the shared row-builder papers over it with a hardcoded 128 -- #584)
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
			c.dhcp6LeasesByState,
			c.dhcp6LeasesByType,
			c.dhcp6LeaseInfo,
			c.dhcp6PoolStats,
			false, // includeClientID: always "" on v6, dropped rather than modeled
			true,  // includePrefixLen: real IA_PD delegated block size on v6 (#584)
		)
	}

	// Pool sizes (joinable with *_leases_by_interface on the interface label),
	// and subnet UUID->CIDR maps for the pool-usage / PD-pool joins below.
	var subnets4, subnets6 []opnsense.KeaSubnet
	if s4, sErr := client.FetchKeaSubnets4(); sErr != nil {
		if firstErr == nil {
			firstErr = sErr
		}
		c.log.Error("failed to fetch Kea DHCPv4 subnets", "err", sErr)
	} else {
		subnets4 = s4
		for _, s := range subnets4 {
			ch <- prometheus.MustNewConstMetric(c.dhcp4PoolSize, prometheus.GaugeValue,
				s.PoolSize, s.Subnet, s.Interface, c.instance)
		}
	}
	if s6, sErr := client.FetchKeaSubnets6(); sErr != nil {
		if firstErr == nil {
			firstErr = sErr
		}
		c.log.Error("failed to fetch Kea DHCPv6 subnets", "err", sErr)
	} else {
		subnets6 = s6
		for _, s := range subnets6 {
			ch <- prometheus.MustNewConstMetric(c.dhcp6PoolSize, prometheus.GaugeValue,
				s.PoolSize, s.Subnet, s.Interface, c.instance)
		}
	}

	// Per-subnet pool utilization: client-side CIDR match of lease addresses
	// into the configured subnets (Kea lease records carry no subnet id).
	for subnet, used := range opnsense.KeaPoolUsedBySubnet(v4Data.Leases, subnets4) {
		ch <- prometheus.MustNewConstMetric(c.dhcp4PoolUsed, prometheus.GaugeValue,
			float64(used), subnet, c.instance)
	}
	for subnet, used := range opnsense.KeaPoolUsedBySubnet(v6Data.Leases, subnets6) {
		ch <- prometheus.MustNewConstMetric(c.dhcp6PoolUsed, prometheus.GaugeValue,
			float64(used), subnet, c.instance)
	}

	// DHCPv6 prefix-delegation pool capacity.
	if pdPools, pErr := client.FetchKeaPdPools(); pErr != nil {
		if firstErr == nil {
			firstErr = pErr
		}
		c.log.Error("failed to fetch Kea DHCPv6 PD pools", "err", pErr)
	} else {
		subnet6ByUUID := make(map[string]string, len(subnets6))
		for _, s := range subnets6 {
			if s.UUID != "" {
				subnet6ByUUID[s.UUID] = s.Subnet
			}
		}
		for _, p := range pdPools {
			ch <- prometheus.MustNewConstMetric(c.dhcp6PdPoolCap, prometheus.GaugeValue,
				p.Capacity, pdPoolSubnetLabel(p, subnet6ByUUID), p.Prefix, c.instance)
		}
	}

	status, sErr := client.FetchServiceStatus("keaServiceStatus")
	if sErr != nil {
		c.log.Warn("failed to fetch kea service status", "err", sErr)
	} else {
		val := 0.0
		if status == "running" {
			val = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.serviceRunning, prometheus.GaugeValue,
			val, c.instance)
	}

	return firstErr
}

// pdPoolSubnetLabel resolves a PD pool's "subnet" label: prefer the UUID join
// against the fetched DHCPv6 subnets (byUUID), falling back to the CIDR token
// of OPNsense's own "<if-key> <cidr>" %subnet display string (see the
// keaPdPoolRow doc comment) when the join misses, and finally the raw UUID as
// a last resort so the series is never silently dropped.
// of OPNsense's own "<interface-description> <cidr>" %subnet display string
// (see the keaPdPoolRow doc comment — confirmed real shape "TESTLAN
// fd09:172:16:9::/64") when the join misses, and finally the raw UUID as a
// last resort so the series is never silently dropped.
func pdPoolSubnetLabel(pool opnsense.KeaPdPool, byUUID map[string]string) string {
	if subnet, ok := byUUID[pool.SubnetUUID]; ok && subnet != "" {
		return subnet
	}
	if pool.SubnetDisplay != "" {
		if idx := strings.LastIndex(pool.SubnetDisplay, " "); idx >= 0 {
			return pool.SubnetDisplay[idx+1:]
		}
		return pool.SubnetDisplay
	}
	return pool.SubnetUUID
}

func (c *keaCollector) emitLeaseMetrics(
	ch chan<- prometheus.Metric,
	data opnsense.KeaLeases,
	leasesTotal, reservedTotal, dynamicTotal, leasesByIface, leasesByState, leasesByType, leaseInfo, poolStats *prometheus.Desc,
	includeClientID bool,
	includePrefixLen bool,
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

	ch <- prometheus.MustNewConstMetric(
		poolStats, prometheus.GaugeValue, float64(data.StatsActive), "active", c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		poolStats, prometheus.GaugeValue, float64(data.StatsInactive), "inactive", c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		poolStats, prometheus.GaugeValue, float64(data.StatsTotal), "total", c.instance,
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

	for state, count := range data.LeasesByState {
		ch <- prometheus.MustNewConstMetric(
			leasesByState,
			prometheus.GaugeValue,
			float64(count),
			state,
			c.instance,
		)
	}

	if leasesByType != nil {
		for typ, count := range data.LeasesByType {
			ch <- prometheus.MustNewConstMetric(
				leasesByType,
				prometheus.GaugeValue,
				float64(count),
				typ,
				c.instance,
			)
		}
	}

	if c.detailsEnabled {
		for _, lease := range data.Leases {
			labelValues := []string{
				lease.Address,
				lease.Hostname,
				lease.HWAddr,
				lease.IfDescr,
				lease.Vendor,
				strconv.Itoa(lease.ValidLifetime),
			}
			if includeClientID {
				labelValues = append(labelValues, lease.ClientID)
			}
			// Presence-gating doesn't apply here the way it does for e.g. the
			// interface queue-drop counters: prefix_len is always a fixed,
			// always-populated field on this shared row-builder response
			// (#584) -- the "meaningless" case (v4) is excluded by NOT adding
			// the label at all (includePrefixLen=false), rather than by
			// checking a per-lease presence flag.
			if includePrefixLen {
				labelValues = append(labelValues, strconv.Itoa(lease.PrefixLen))
			}
			labelValues = append(labelValues, c.instance)

			ch <- prometheus.MustNewConstMetric(
				leaseInfo,
				prometheus.GaugeValue,
				float64(lease.Expire),
				labelValues...,
			)
		}
	}
}
