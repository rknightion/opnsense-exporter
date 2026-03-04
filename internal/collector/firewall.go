package collector

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type firewallCollector struct {
	log                 *slog.Logger
	inIPv4PassPackets   *prometheus.Desc
	outIPv4PassPackets  *prometheus.Desc
	inIPv4BlockPackets  *prometheus.Desc
	outIPv4BlockPackets *prometheus.Desc

	inIPv6PassPackets   *prometheus.Desc
	outIPv6PassPackets  *prometheus.Desc
	inIPv6BlockPackets  *prometheus.Desc
	outIPv6BlockPackets *prometheus.Desc

	inIPv4PassBytes   *prometheus.Desc
	outIPv4PassBytes  *prometheus.Desc
	inIPv4BlockBytes  *prometheus.Desc
	outIPv4BlockBytes *prometheus.Desc

	inIPv6PassBytes   *prometheus.Desc
	outIPv6PassBytes  *prometheus.Desc
	inIPv6BlockBytes  *prometheus.Desc
	outIPv6BlockBytes *prometheus.Desc

	pfStatesCurrent *prometheus.Desc
	pfStatesLimit   *prometheus.Desc

	interfaceHitsTotal *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &firewallCollector{
		subsystem: FirewallSubsystem,
	})
}

func (c *firewallCollector) Name() string {
	return c.subsystem
}

func (c *firewallCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.inIPv4PassPackets = buildPrometheusDesc(c.subsystem, "in_ipv4_pass_packets",
		"The number of IPv4 incoming packets that were allowed to pass through the firewall by interface",
		[]string{"interface"},
	)

	c.outIPv4PassPackets = buildPrometheusDesc(c.subsystem, "out_ipv4_pass_packets",
		"The number of IPv4 outgoing packets that were allowed to pass through the firewall by interface",
		[]string{"interface"},
	)

	c.inIPv4BlockPackets = buildPrometheusDesc(c.subsystem, "in_ipv4_block_packets",
		"The number of IPv4 incoming packets that were blocked by the firewall by interface",
		[]string{"interface"},
	)

	c.outIPv4BlockPackets = buildPrometheusDesc(c.subsystem, "out_ipv4_block_packets",
		"The number of IPv4 outgoing packets that were blocked by the firewall by interface",
		[]string{"interface"},
	)

	c.inIPv6PassPackets = buildPrometheusDesc(c.subsystem, "in_ipv6_pass_packets",
		"The number of IPv6 incoming packets that were allowed to pass through the firewall by interface",
		[]string{"interface"},
	)

	c.outIPv6PassPackets = buildPrometheusDesc(c.subsystem, "out_ipv6_pass_packets",
		"The number of IPv6 outgoing packets that were allowed to pass through the firewall by interface",
		[]string{"interface"},
	)

	c.inIPv6BlockPackets = buildPrometheusDesc(c.subsystem, "in_ipv6_block_packets",
		"The number of IPv6 incoming packets that were blocked by the firewall by interface",
		[]string{"interface"},
	)

	c.outIPv6BlockPackets = buildPrometheusDesc(c.subsystem, "out_ipv6_block_packets",
		"The number of IPv6 outgoing packets that were blocked by the firewall by interface",
		[]string{"interface"},
	)

	c.inIPv4PassBytes = buildPrometheusDesc(c.subsystem, "in_ipv4_pass_bytes_total",
		"The number of IPv4 incoming bytes that were allowed to pass through the firewall by interface",
		[]string{"interface"},
	)

	c.outIPv4PassBytes = buildPrometheusDesc(c.subsystem, "out_ipv4_pass_bytes_total",
		"The number of IPv4 outgoing bytes that were allowed to pass through the firewall by interface",
		[]string{"interface"},
	)

	c.inIPv4BlockBytes = buildPrometheusDesc(c.subsystem, "in_ipv4_block_bytes_total",
		"The number of IPv4 incoming bytes that were blocked by the firewall by interface",
		[]string{"interface"},
	)

	c.outIPv4BlockBytes = buildPrometheusDesc(c.subsystem, "out_ipv4_block_bytes_total",
		"The number of IPv4 outgoing bytes that were blocked by the firewall by interface",
		[]string{"interface"},
	)

	c.inIPv6PassBytes = buildPrometheusDesc(c.subsystem, "in_ipv6_pass_bytes_total",
		"The number of IPv6 incoming bytes that were allowed to pass through the firewall by interface",
		[]string{"interface"},
	)

	c.outIPv6PassBytes = buildPrometheusDesc(c.subsystem, "out_ipv6_pass_bytes_total",
		"The number of IPv6 outgoing bytes that were allowed to pass through the firewall by interface",
		[]string{"interface"},
	)

	c.inIPv6BlockBytes = buildPrometheusDesc(c.subsystem, "in_ipv6_block_bytes_total",
		"The number of IPv6 incoming bytes that were blocked by the firewall by interface",
		[]string{"interface"},
	)

	c.outIPv6BlockBytes = buildPrometheusDesc(c.subsystem, "out_ipv6_block_bytes_total",
		"The number of IPv6 outgoing bytes that were blocked by the firewall by interface",
		[]string{"interface"},
	)

	c.pfStatesCurrent = buildPrometheusDesc(c.subsystem, "pf_states_current",
		"Current number of active PF states",
		nil,
	)

	c.pfStatesLimit = buildPrometheusDesc(c.subsystem, "pf_states_limit",
		"Maximum number of PF states allowed",
		nil,
	)

	c.interfaceHitsTotal = buildPrometheusDesc(c.subsystem, "interface_hits_total",
		"Total number of firewall rule matches per interface",
		[]string{"interface"},
	)
}

func (c *firewallCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.inIPv4PassPackets
	ch <- c.outIPv4PassPackets
	ch <- c.inIPv4BlockPackets
	ch <- c.outIPv4BlockPackets

	ch <- c.inIPv6PassPackets
	ch <- c.outIPv6PassPackets
	ch <- c.inIPv6BlockPackets
	ch <- c.outIPv6BlockPackets

	ch <- c.inIPv4PassBytes
	ch <- c.outIPv4PassBytes
	ch <- c.inIPv4BlockBytes
	ch <- c.outIPv4BlockBytes

	ch <- c.inIPv6PassBytes
	ch <- c.outIPv6PassBytes
	ch <- c.inIPv6BlockBytes
	ch <- c.outIPv6BlockBytes

	ch <- c.pfStatesCurrent
	ch <- c.pfStatesLimit

	ch <- c.interfaceHitsTotal
}

func (c *firewallCollector) Update(client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchPFStatsByInterface()
	if err != nil {
		return err
	}

	for _, v := range data.Interfaces {
		metricsValueMapping := map[*prometheus.Desc]int{
			c.inIPv4PassPackets:   v.In4PassPackets,
			c.outIPv4PassPackets:  v.Out4PassPackets,
			c.inIPv4BlockPackets:  v.In4BlockPackets,
			c.outIPv4BlockPackets: v.Out4BlockPackets,
			c.inIPv6PassPackets:   v.In6PassPackets,
			c.outIPv6PassPackets:  v.Out6PassPackets,
			c.inIPv6BlockPackets:  v.In6BlockPackets,
			c.outIPv6BlockPackets: v.Out6BlockPackets,
			c.inIPv4PassBytes:     v.In4PassBytes,
			c.outIPv4PassBytes:    v.Out4PassBytes,
			c.inIPv4BlockBytes:    v.In4BlockBytes,
			c.outIPv4BlockBytes:   v.Out4BlockBytes,
			c.inIPv6PassBytes:     v.In6PassBytes,
			c.outIPv6PassBytes:    v.Out6PassBytes,
			c.inIPv6BlockBytes:    v.In6BlockBytes,
			c.outIPv6BlockBytes:   v.Out6BlockBytes,
		}
		for metric, value := range metricsValueMapping {
			ch <- prometheus.MustNewConstMetric(
				metric,
				prometheus.GaugeValue,
				float64(value),
				v.InterfaceName,
				c.instance,
			)
		}
	}

	pfStates, pfErr := client.FetchPFStates()
	if pfErr != nil {
		return pfErr
	}
	ch <- prometheus.MustNewConstMetric(
		c.pfStatesCurrent,
		prometheus.GaugeValue,
		float64(pfStates.Current),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.pfStatesLimit,
		prometheus.GaugeValue,
		float64(pfStates.Limit),
		c.instance,
	)

	fwStats, fwErr := client.FetchFirewallStats()
	if fwErr != nil {
		c.log.Warn("failed to fetch firewall aggregate stats", "error", fwErr.Error())
	} else {
		for _, hit := range fwStats {
			ch <- prometheus.MustNewConstMetric(
				c.interfaceHitsTotal,
				prometheus.CounterValue,
				float64(hit.Value),
				hit.Label,
				c.instance,
			)
		}
	}

	return nil
}
