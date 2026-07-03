package collector

import (
	"context"
	"log/slog"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type smartCollector struct {
	log *slog.Logger

	devicesTotal *prometheus.Desc
	deviceHealth *prometheus.Desc
	temperature  *prometheus.Desc
	powerOnHours *prometheus.Desc

	attributeValue     *prometheus.Desc
	attributeWorst     *prometheus.Desc
	attributeThreshold *prometheus.Desc
	attributeRaw       *prometheus.Desc

	nvmeAvailableSpare   *prometheus.Desc
	nvmePercentageUsed   *prometheus.Desc
	nvmeMediaErrors      *prometheus.Desc
	nvmeUnsafeShutdowns  *prometheus.Desc
	nvmeDataUnitsRead    *prometheus.Desc
	nvmeDataUnitsWritten *prometheus.Desc

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

	attrLabels := []string{"device", "attribute_name", "attribute_id"}
	c.attributeValue = buildPrometheusDesc(c.subsystem, "attribute_value",
		"Normalised current value of a SATA SMART attribute",
		attrLabels,
	)
	c.attributeWorst = buildPrometheusDesc(c.subsystem, "attribute_worst",
		"Worst recorded normalised value of a SATA SMART attribute",
		attrLabels,
	)
	c.attributeThreshold = buildPrometheusDesc(c.subsystem, "attribute_threshold",
		"Failure threshold of a SATA SMART attribute (normalised value at/below this indicates failure)",
		attrLabels,
	)
	c.attributeRaw = buildPrometheusDesc(c.subsystem, "attribute_raw",
		"Raw value of a SATA SMART attribute (e.g. reallocated sector count, total LBAs written)",
		attrLabels,
	)
	c.nvmeAvailableSpare = buildPrometheusDesc(c.subsystem, "nvme_available_spare_percent",
		"NVMe remaining spare capacity as a percentage",
		[]string{"device"},
	)
	c.nvmePercentageUsed = buildPrometheusDesc(c.subsystem, "nvme_percentage_used",
		"NVMe vendor estimate of device life used as a percentage (may exceed 100)",
		[]string{"device"},
	)
	c.nvmeMediaErrors = buildPrometheusDesc(c.subsystem, "nvme_media_errors_total",
		"NVMe count of unrecovered data-integrity errors",
		[]string{"device"},
	)
	c.nvmeUnsafeShutdowns = buildPrometheusDesc(c.subsystem, "nvme_unsafe_shutdowns_total",
		"NVMe count of unsafe shutdowns",
		[]string{"device"},
	)
	c.nvmeDataUnitsRead = buildPrometheusDesc(c.subsystem, "nvme_data_units_read_total",
		"NVMe data units read (1 unit = 1000 × 512 bytes)",
		[]string{"device"},
	)
	c.nvmeDataUnitsWritten = buildPrometheusDesc(c.subsystem, "nvme_data_units_written_total",
		"NVMe data units written (1 unit = 1000 × 512 bytes)",
		[]string{"device"},
	)
}

func (c *smartCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.devicesTotal
	ch <- c.deviceHealth
	ch <- c.temperature
	ch <- c.powerOnHours
	ch <- c.attributeValue
	ch <- c.attributeWorst
	ch <- c.attributeThreshold
	ch <- c.attributeRaw
	ch <- c.nvmeAvailableSpare
	ch <- c.nvmePercentageUsed
	ch <- c.nvmeMediaErrors
	ch <- c.nvmeUnsafeShutdowns
	ch <- c.nvmeDataUnitsRead
	ch <- c.nvmeDataUnitsWritten
}

func (c *smartCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchSMARTDevices()
	if err != nil {
		return err
	}

	// os-smart absent → Present=false; stay silent so devices_total=0 (plugin
	// absent) is not confused with a box that genuinely has no disks (#87).
	if !data.Present {
		return nil
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

		for _, attr := range dev.Attributes {
			id := strconv.FormatInt(attr.ID, 10)
			ch <- prometheus.MustNewConstMetric(c.attributeValue, prometheus.GaugeValue,
				float64(attr.Value), dev.Device, attr.Name, id, c.instance)
			ch <- prometheus.MustNewConstMetric(c.attributeWorst, prometheus.GaugeValue,
				float64(attr.Worst), dev.Device, attr.Name, id, c.instance)
			ch <- prometheus.MustNewConstMetric(c.attributeThreshold, prometheus.GaugeValue,
				float64(attr.Threshold), dev.Device, attr.Name, id, c.instance)
			ch <- prometheus.MustNewConstMetric(c.attributeRaw, prometheus.GaugeValue,
				attr.Raw, dev.Device, attr.Name, id, c.instance)
		}

		if n := dev.NVMe; n != nil {
			emit := func(desc *prometheus.Desc, vt prometheus.ValueType, v *float64) {
				if v != nil {
					ch <- prometheus.MustNewConstMetric(desc, vt, *v, dev.Device, c.instance)
				}
			}
			emit(c.nvmeAvailableSpare, prometheus.GaugeValue, n.AvailableSpare)
			emit(c.nvmePercentageUsed, prometheus.GaugeValue, n.PercentageUsed)
			emit(c.nvmeMediaErrors, prometheus.CounterValue, n.MediaErrors)
			emit(c.nvmeUnsafeShutdowns, prometheus.CounterValue, n.UnsafeShutdowns)
			emit(c.nvmeDataUnitsRead, prometheus.CounterValue, n.DataUnitsRead)
			emit(c.nvmeDataUnitsWritten, prometheus.CounterValue, n.DataUnitsWritten)
		}
	}

	return nil
}
