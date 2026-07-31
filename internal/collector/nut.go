package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

type nutCollector struct {
	log *slog.Logger

	serviceRunning     *prometheus.Desc
	upsInfo            *prometheus.Desc
	batteryCharge      *prometheus.Desc
	batteryRuntime     *prometheus.Desc
	batteryVoltage     *prometheus.Desc
	inputVoltage       *prometheus.Desc
	outputVoltage      *prometheus.Desc
	loadPercent        *prometheus.Desc
	temperatureCelsius *prometheus.Desc
	inputFrequency     *prometheus.Desc
	statusOnline       *prometheus.Desc
	statusOnBattery    *prometheus.Desc
	statusLowBattery   *prometheus.Desc
	statusCharging     *prometheus.Desc
	statusReplaceBatt  *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &nutCollector{
		subsystem: NUTSubsystem,
	})
}

func (c *nutCollector) Name() string { return c.subsystem }

func (c *nutCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the NUT service is running (1 = running, 0 = stopped/disabled)", nil)
	c.upsInfo = buildPrometheusDesc(c.subsystem, "ups_info",
		"UPS device information (always 1)", []string{"model", "status"})
	c.batteryCharge = buildPrometheusDesc(c.subsystem, "battery_charge_percent",
		"Battery charge percentage (battery.charge)", nil)
	c.batteryRuntime = buildPrometheusDesc(c.subsystem, "battery_runtime_seconds",
		"Estimated battery runtime in seconds (battery.runtime)", nil)
	c.batteryVoltage = buildPrometheusDesc(c.subsystem, "battery_voltage_volts",
		"Battery voltage in volts (battery.voltage)", nil)
	c.inputVoltage = buildPrometheusDesc(c.subsystem, "input_voltage_volts",
		"Input (mains) voltage in volts (input.voltage)", nil)
	c.outputVoltage = buildPrometheusDesc(c.subsystem, "output_voltage_volts",
		"Output voltage in volts (output.voltage)", nil)
	c.loadPercent = buildPrometheusDesc(c.subsystem, "load_percent",
		"UPS load percentage (ups.load)", nil)
	c.temperatureCelsius = buildPrometheusDesc(c.subsystem, "temperature_celsius",
		"UPS temperature in degrees Celsius (ups.temperature)", nil)
	c.inputFrequency = buildPrometheusDesc(c.subsystem, "input_frequency_hertz",
		"Input frequency in Hertz (input.frequency)", nil)
	c.statusOnline = buildPrometheusDesc(c.subsystem, "status_online",
		"1 when UPS is online (OL flag in ups.status)", nil)
	c.statusOnBattery = buildPrometheusDesc(c.subsystem, "status_on_battery",
		"1 when UPS is running on battery (OB flag in ups.status)", nil)
	c.statusLowBattery = buildPrometheusDesc(c.subsystem, "status_low_battery",
		"1 when battery is low (LB flag in ups.status)", nil)
	c.statusCharging = buildPrometheusDesc(c.subsystem, "status_charging",
		"1 when battery is charging (CHRG flag in ups.status)", nil)
	c.statusReplaceBatt = buildPrometheusDesc(c.subsystem, "status_replace_battery",
		"1 when battery replacement is recommended (RB flag in ups.status)", nil)
}

func (c *nutCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.serviceRunning, c.upsInfo,
		c.batteryCharge, c.batteryRuntime, c.batteryVoltage,
		c.inputVoltage, c.outputVoltage, c.loadPercent,
		c.temperatureCelsius, c.inputFrequency,
		c.statusOnline, c.statusOnBattery, c.statusLowBattery,
		c.statusCharging, c.statusReplaceBatt,
	} {
		ch <- d
	}
}

func (c *nutCollector) Update(_ context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchNUTStatus()
	if err != nil {
		return err
	}

	// Plugin absent (404): stay completely silent, skip service-status probe too.
	if !data.Present {
		return nil
	}

	if data.HasData {
		// ups_info (always 1, carries model and status labels).
		ch <- prometheus.MustNewConstMetric(c.upsInfo, prometheus.GaugeValue, 1,
			data.Model, data.Status, c.instance)

		// Numeric metrics — only emit keys present in Metrics map.
		descs := map[string]*prometheus.Desc{
			"battery.charge":  c.batteryCharge,
			"battery.runtime": c.batteryRuntime,
			"battery.voltage": c.batteryVoltage,
			"input.voltage":   c.inputVoltage,
			"output.voltage":  c.outputVoltage,
			"ups.load":        c.loadPercent,
			"ups.temperature": c.temperatureCelsius,
			"input.frequency": c.inputFrequency,
		}
		for varName, desc := range descs {
			if v, ok := data.Metrics[varName]; ok {
				ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, v, c.instance)
			}
		}

		// Status flags — only emitted when ups.status was present (StatusFlags non-nil).
		if data.StatusFlags != nil {
			ch <- prometheus.MustNewConstMetric(c.statusOnline, prometheus.GaugeValue,
				data.StatusFlags["online"], c.instance)
			ch <- prometheus.MustNewConstMetric(c.statusOnBattery, prometheus.GaugeValue,
				data.StatusFlags["on_battery"], c.instance)
			ch <- prometheus.MustNewConstMetric(c.statusLowBattery, prometheus.GaugeValue,
				data.StatusFlags["low_battery"], c.instance)
			ch <- prometheus.MustNewConstMetric(c.statusCharging, prometheus.GaugeValue,
				data.StatusFlags["charging"], c.instance)
			ch <- prometheus.MustNewConstMetric(c.statusReplaceBatt, prometheus.GaugeValue,
				data.StatusFlags["replace_battery"], c.instance)
		}
	}

	// Always (when plugin present) emit service_running.
	status, present, sErr := client.FetchServiceStatusOptional("nutServiceStatus")
	if sErr != nil {
		c.log.Warn("failed to fetch NUT service status", "err", sErr)
	} else if present {
		running := 0.0
		if status == "running" {
			running = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.serviceRunning, prometheus.GaugeValue,
			running, c.instance)
	}

	return nil
}
