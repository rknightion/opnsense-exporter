package collector

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type smartCollector struct {
	log *slog.Logger

	devicesTotal *prometheus.Desc
	deviceHealth *prometheus.Desc
	temperature  *prometheus.Desc
	powerOnHours *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &smartCollector{
		subsystem: SMARTSubsystem,
	})
}

func (c *smartCollector) Name() string {
	return c.subsystem
}

func (c *smartCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.devicesTotal = buildPrometheusDesc(c.subsystem, "devices_total",
		"Number of SMART-monitored devices enumerated by the os-smart plugin",
		nil,
	)
	c.deviceHealth = buildPrometheusDesc(c.subsystem, "device_health",
		"SMART overall health assessment (1 = passed, 0 = failed)",
		[]string{"device", "model", "serial"},
	)
	c.temperature = buildPrometheusDesc(c.subsystem, "device_temperature_celsius",
		"Current drive temperature in degrees Celsius",
		[]string{"device"},
	)
	c.powerOnHours = buildPrometheusDesc(c.subsystem, "device_power_on_hours",
		"Total power-on hours reported by the drive",
		[]string{"device"},
	)
}

func (c *smartCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.devicesTotal
	ch <- c.deviceHealth
	ch <- c.temperature
	ch <- c.powerOnHours
}

func (c *smartCollector) Update(client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchSMARTDevices()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(
		c.devicesTotal,
		prometheus.GaugeValue,
		float64(data.DeviceCount),
		c.instance,
	)

	for _, dev := range data.Devices {
		if dev.Health != nil {
			healthVal := 0.0
			if *dev.Health {
				healthVal = 1.0
			}
			ch <- prometheus.MustNewConstMetric(
				c.deviceHealth,
				prometheus.GaugeValue,
				healthVal,
				dev.Device,
				dev.Model,
				dev.Serial,
				c.instance,
			)
		}

		if dev.Temperature != nil {
			ch <- prometheus.MustNewConstMetric(
				c.temperature,
				prometheus.GaugeValue,
				*dev.Temperature,
				dev.Device,
				c.instance,
			)
		}

		if dev.PowerOnHours != nil {
			ch <- prometheus.MustNewConstMetric(
				c.powerOnHours,
				prometheus.GaugeValue,
				*dev.PowerOnHours,
				dev.Device,
				c.instance,
			)
		}
	}

	return nil
}
