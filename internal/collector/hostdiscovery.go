package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

// hostDiscoveryCollector exposes the core hostwatch discovered-host inventory
// (Interfaces > Host discovery) as bounded interface+source aggregate counts.
//
// Deliberately no per-host series: MAC/IP/hostname labels would be unbounded
// cardinality (#223), unlike the arp_table/ndp collectors' opt-in per-entry
// detail mode, which this collector has no equivalent of by design.
type hostDiscoveryCollector struct {
	hosts       *prometheus.Desc
	hostsRecent *prometheus.Desc
	log         *slog.Logger
	subsystem   string
	instance    string
}

func init() {
	collectorInstances = append(collectorInstances, &hostDiscoveryCollector{
		subsystem: HostDiscoverySubsystem,
	})
}

func (c *hostDiscoveryCollector) Name() string {
	return c.subsystem
}

func (c *hostDiscoveryCollector) Register(namespace, instance string, log *slog.Logger) {
	c.log = log
	c.instance = instance

	c.log.Debug("Registering collector", "collector", c.Name())

	c.hosts = buildPrometheusDesc(c.subsystem, "hosts",
		"Number of hosts in the discovered-host inventory, by interface, source and manufacturer. "+
			"source is \"discovery\" when the hostwatch daemon is enabled (persistent inventory, "+
			"survives reboots and cache expiry) or \"arp-ndp\" when it is disabled (a live fallback "+
			"that duplicates the arp_table/ndp collectors). manufacturer is the OUI vendor lookup of "+
			"the MAC (organization_name), same label name/convention as arp_table/ndp's manufacturer "+
			"label; \"unknown\" when the box could not resolve an OUI (e.g. a randomized-MAC device). "+
			"Aggregate only: never a per-host series.",
		[]string{"interface", "source", "manufacturer"},
	)
	c.hostsRecent = buildPrometheusDesc(c.subsystem, "hosts_recent",
		"Number of hosts in the discovered-host inventory whose last_seen falls within a 15 minute "+
			"window, by interface, source and manufacturer. Always 0 for source=\"arp-ndp\" rows, "+
			"which carry no last_seen timestamp to judge recency from.",
		[]string{"interface", "source", "manufacturer"},
	)
}

func (c *hostDiscoveryCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.hosts
	ch <- c.hostsRecent
}

func (c *hostDiscoveryCollector) Update(_ context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchHostDiscovery()
	if err != nil {
		return err
	}

	for _, g := range data.Groups {
		ch <- prometheus.MustNewConstMetric(
			c.hosts, prometheus.GaugeValue, float64(g.Hosts), g.Interface, g.Source, g.Manufacturer, c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.hostsRecent, prometheus.GaugeValue, float64(g.RecentHosts), g.Interface, g.Source, g.Manufacturer, c.instance,
		)
	}

	return nil
}
