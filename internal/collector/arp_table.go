package collector

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

type arpTableCollector struct {
	entriesTotal   *prometheus.Desc
	entries        *prometheus.Desc
	detailsEnabled bool
	log            *slog.Logger
	subsystem      string
	instance       string
}

func init() {
	collectorInstances = append(collectorInstances, &arpTableCollector{
		subsystem: ArpTableSubsystem,
	})
}

func (c *arpTableCollector) Name() string {
	return c.subsystem
}

func (c *arpTableCollector) Register(namespace, instance string, log *slog.Logger) {
	c.log = log
	c.instance = instance

	c.log.Debug("Registering collector", "collector", c.Name())

	c.entriesTotal = buildPrometheusDesc(c.subsystem, "entries_total",
		"Total number of ARP table entries (low-cardinality aggregate, always emitted)",
		nil,
	)
	c.entries = buildPrometheusDesc(c.subsystem, "entries",
		"One series per ARP table entry (value is always 1). Only emitted when "+
			"--exporter.enable-arp-details is set (high, churning cardinality). "+
			"`manufacturer` is the OUI lookup for the MAC and is the label that actually identifies "+
			"a device: `hostname` is empty on every entry on the reference box and is frequently "+
			"empty upstream in general, so do not build a panel that depends on it. "+
			"`device` is the raw kernel device and `interface_description` the assigned name; they "+
			"diverge on VLAN children and bridges, and only `device` joins against the interfaces "+
			"metrics.",
		[]string{"ip", "mac", "hostname", "interface_description", "type", "expired", "permanent", "manufacturer", "device"},
	)
}

// SetDetailsEnabled controls whether the per-entry `entries` series are emitted.
// Called by WithArpDetails() at wiring time (#125).
func (c *arpTableCollector) SetDetailsEnabled(enabled bool) {
	c.detailsEnabled = enabled
}

func (c *arpTableCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.entriesTotal
	ch <- c.entries
}

func (c *arpTableCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchArpTable()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(
		c.entriesTotal, prometheus.GaugeValue, float64(data.TotalEntries), c.instance,
	)

	if !c.detailsEnabled {
		return nil
	}

	for _, arp := range data.Arp {
		ch <- prometheus.MustNewConstMetric(
			c.entries,
			prometheus.GaugeValue,
			1,
			arp.IP,
			arp.Mac,
			arp.Hostname,
			arp.IntfDescription,
			arp.Type,
			fmt.Sprintf("%t", arp.Expired),
			fmt.Sprintf("%t", arp.Permanent),
			arp.Manufacturer,
			arp.Device,
			c.instance,
		)
	}

	return nil
}
