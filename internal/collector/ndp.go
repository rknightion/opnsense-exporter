package collector

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type ndpCollector struct {
	entries   *prometheus.Desc
	log       *slog.Logger
	subsystem string
	instance  string
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

	c.entries = buildPrometheusDesc(c.subsystem, "entries",
		"NDP entries by ip, mac, interface description, and type",
		[]string{"ip", "mac", "interface_description", "type"},
	)
}

func (c *ndpCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.entries
}

func (c *ndpCollector) Update(client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchNDPTable()
	if err != nil {
		return err
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
			c.instance,
		)
	}

	return nil
}
