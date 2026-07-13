package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type lldpCollector struct {
	log *slog.Logger

	neighbors *prometheus.Desc
	info      *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &lldpCollector{
		subsystem: LLDPSubsystem,
	})
}

func (c *lldpCollector) Name() string {
	return c.subsystem
}

func (c *lldpCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.neighbors = buildPrometheusDesc(c.subsystem, "neighbors",
		"Number of LLDP neighbors currently seen on this local interface",
		[]string{"interface"},
	)
	c.info = buildPrometheusDesc(c.subsystem, "neighbor_info",
		"LLDP neighbor information (value is always 1; use labels). SysDescr and MgmtIP are "+
			"deliberately excluded from labels (free-text/unbounded)",
		[]string{"interface", "chassis_name", "port_id", "port_descr"},
	)
}

func (c *lldpCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.neighbors
	ch <- c.info
}

func (c *lldpCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchLLDPNeighbors()
	if err != nil {
		return err
	}

	// os-lldpd absent → Present=false; stay silent so a plugin-absent box isn't
	// confused with a present-but-quiet one (mirrors the ACME #87 handling).
	if !data.Present {
		return nil
	}

	counts := make(map[string]int, len(data.Neighbors))
	for _, n := range data.Neighbors {
		counts[n.Interface]++
	}
	for iface, count := range counts {
		ch <- prometheus.MustNewConstMetric(
			c.neighbors,
			prometheus.GaugeValue,
			float64(count),
			iface,
			c.instance,
		)
	}

	// Neighbor rows are keyed on (interface, chassis_name, port_id, port_descr);
	// a duplicate tuple would panic MustNewConstMetric, so skip and warn instead
	// — mirrors the ACME certificate dedup pattern (#81).
	seen := make(map[[4]string]bool, len(data.Neighbors))
	for _, n := range data.Neighbors {
		key := [4]string{n.Interface, n.ChassisName, n.PortID, n.PortDescr}
		if seen[key] {
			c.log.Warn("skipping LLDP neighbor with duplicate label tuple",
				"interface", n.Interface, "chassis_name", n.ChassisName, "port_id", n.PortID)
			continue
		}
		seen[key] = true

		ch <- prometheus.MustNewConstMetric(
			c.info,
			prometheus.GaugeValue,
			1,
			n.Interface,
			n.ChassisName,
			n.PortID,
			n.PortDescr,
			c.instance,
		)
	}

	return nil
}
