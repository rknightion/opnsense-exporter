package collector

import (
	"log/slog"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type temperatureCollector struct {
	log *slog.Logger

	celsius *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &temperatureCollector{
		subsystem: TemperatureSubsystem,
	})
}

func (c *temperatureCollector) Name() string {
	return c.subsystem
}

func (c *temperatureCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.celsius = buildPrometheusDesc(c.subsystem, "celsius",
		"Temperature reading in Celsius",
		[]string{"device", "type", "device_seq"},
	)
}

func (c *temperatureCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.celsius
}

func (c *temperatureCollector) Update(client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	readings, err := client.FetchTemperatures()
	if err != nil {
		return err
	}

	for _, r := range readings {
		ch <- prometheus.MustNewConstMetric(
			c.celsius,
			prometheus.GaugeValue,
			r.Celsius,
			r.Device,
			r.Type,
			strconv.Itoa(r.DeviceSeq),
			c.instance,
		)
	}

	return nil
}
