package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

type ndpCollector struct {
	entriesTotal   *prometheus.Desc
	entries        *prometheus.Desc
	detailsEnabled bool
	log            *slog.Logger
	subsystem      string
	instance       string
}

func init() {
	collectorInstances = append(collectorInstances, &ndpCollector{
		subsystem: NDPSubsystem,
	})
}

func (c *ndpCollector) Name() string {
	return c.subsystem
}

func (c *ndpCollector) Register(namespace, instance string, log *slog.Logger) {
	c.log = log
	c.instance = instance

	c.log.Debug("Registering collector", "collector", c.Name())

	c.entriesTotal = buildPrometheusDesc(c.subsystem, "table_entries",
		"Current number of NDP table entries (low-cardinality aggregate, always emitted)",
		nil,
	)
	c.entries = buildPrometheusDesc(c.subsystem, "entries",
		"One series per NDP neighbour entry (value is always 1). Only emitted when "+
			"--exporter.enable-ndp-details is set (high, churning cardinality from IPv6 privacy "+
			"addresses). `manufacturer` is the OUI lookup for the MAC and is the label that "+
			"identifies a device. `device` is the raw kernel device and `interface_description` the "+
			"assigned name; they diverge on VLAN children and bridges, and only `device` joins "+
			"against the interfaces metrics. `type` reads empty on OPNsense 26.1, which sends no "+
			"type key on this endpoint.",
		[]string{"ip", "mac", "interface_description", "type", "manufacturer", "device"},
	)
}

// SetDetailsEnabled controls whether the per-entry `entries` series are emitted.
// Called by WithNdpDetails() at wiring time (#125).
func (c *ndpCollector) SetDetailsEnabled(enabled bool) {
	c.detailsEnabled = enabled
}

func (c *ndpCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.entriesTotal
	ch <- c.entries
}

func (c *ndpCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchNDPTable()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(
		c.entriesTotal, prometheus.GaugeValue, float64(len(data.Entries)), c.instance,
	)

	if !c.detailsEnabled {
		return nil
	}

	for _, entry := range data.Entries {
		ch <- prometheus.MustNewConstMetric(
			c.entries,
			prometheus.GaugeValue,
			1,
			entry.IP,
			entry.Mac,
			entry.IntfDescription,
			entry.Type,
			entry.Manufacturer,
			entry.Device,
			c.instance,
		)
	}

	return nil
}
