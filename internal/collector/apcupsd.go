package collector

import (
	"context"
	"log/slog"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// apcupsdCollector collects UPS metrics from the apcupsd plugin
// (sysutils/apcupsd on OPNsense). Plugin absent (404) → silent return,
// no metrics. Daemon down (status map null) → Present=true, HasData=false →
// only service_running is emitted.
type apcupsdCollector struct {
	log *slog.Logger

	serviceRunning   *prometheus.Desc
	upsInfo          *prometheus.Desc
	batteryCharge    *prometheus.Desc
	batteryRuntime   *prometheus.Desc
	batteryVoltage   *prometheus.Desc
	inputVoltage     *prometheus.Desc
	outputVoltage    *prometheus.Desc
	loadPercent      *prometheus.Desc
	timeOnBattery    *prometheus.Desc
	transfersTotal   *prometheus.Desc
	nominalPower     *prometheus.Desc
	statusOnline     *prometheus.Desc
	statusOnBattery  *prometheus.Desc
	statusLowBattery *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &apcupsdCollector{
		subsystem: ApcupsdSubsystem,
	})
}

func (c *apcupsdCollector) Name() string { return c.subsystem }

func (c *apcupsdCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the apcupsd service is running (1 = running, 0 = stopped/disabled)", nil)
	c.upsInfo = buildPrometheusDesc(c.subsystem, "ups_info",
		"UPS information (value is always 1; see model and status labels)",
		[]string{"model", "status"})
	c.batteryCharge = buildPrometheusDesc(c.subsystem, "battery_charge_percent",
		"UPS battery charge percentage (BCHARGE)", nil)
	c.batteryRuntime = buildPrometheusDesc(c.subsystem, "battery_runtime_seconds",
		"Estimated UPS battery runtime in seconds (TIMELEFT minutes × 60)", nil)
	c.batteryVoltage = buildPrometheusDesc(c.subsystem, "battery_voltage_volts",
		"UPS battery voltage in volts (BATTV)", nil)
	c.inputVoltage = buildPrometheusDesc(c.subsystem, "input_voltage_volts",
		"UPS input line voltage in volts (LINEV)", nil)
	c.outputVoltage = buildPrometheusDesc(c.subsystem, "output_voltage_volts",
		"UPS output voltage in volts (OUTPUTV)", nil)
	c.loadPercent = buildPrometheusDesc(c.subsystem, "load_percent",
		"UPS load percentage (LOADPCT)", nil)
	c.timeOnBattery = buildPrometheusDesc(c.subsystem, "time_on_battery_seconds",
		"Elapsed time on battery power in seconds (TONBATT)", nil)
	c.transfersTotal = buildPrometheusDesc(c.subsystem, "transfers_total",
		"Cumulative number of transfers to battery (NUMXFERS)", nil)
	c.nominalPower = buildPrometheusDesc(c.subsystem, "nominal_power_watts",
		"UPS nominal output power in watts (NOMPOWER)", nil)
	c.statusOnline = buildPrometheusDesc(c.subsystem, "status_online",
		"1 when UPS status contains ONLINE", nil)
	c.statusOnBattery = buildPrometheusDesc(c.subsystem, "status_on_battery",
		"1 when UPS status contains ONBATT", nil)
	c.statusLowBattery = buildPrometheusDesc(c.subsystem, "status_low_battery",
		"1 when UPS status contains LOWBATT", nil)
}

func (c *apcupsdCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.serviceRunning, c.upsInfo,
		c.batteryCharge, c.batteryRuntime, c.batteryVoltage,
		c.inputVoltage, c.outputVoltage, c.loadPercent,
		c.timeOnBattery, c.transfersTotal, c.nominalPower,
		c.statusOnline, c.statusOnBattery, c.statusLowBattery,
	} {
		ch <- d
	}
}

func (c *apcupsdCollector) Update(_ context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchApcupsdStatus()
	if err != nil {
		return err
	}

	// Plugin absent (404): stay completely silent — skip service-status probe too
	// (skip-on-absent pattern: the service endpoint would also 404).
	if !data.Present {
		return nil
	}

	// Plugin present but daemon down (status map null/empty): emit only
	// service_running so the outage is visible.
	if !data.HasData {
		status, present, sErr := client.FetchServiceStatusOptional("apcupsdServiceStatus")
		if sErr != nil {
			c.log.Warn("failed to fetch apcupsd service status", "err", sErr)
			return nil
		}
		if present {
			running := 0.0
			if status == "running" {
				running = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.serviceRunning, prometheus.GaugeValue, running, c.instance)
		}
		return nil
	}

	// UPS info (always 1 when HasData).
	ch <- prometheus.MustNewConstMetric(c.upsInfo, prometheus.GaugeValue, 1,
		data.Model, data.Status, c.instance)

	// Numeric metrics — emitted only when the apcaccess field was present and numeric.
	metricMapping := []struct {
		key  string
		desc *prometheus.Desc
		vt   prometheus.ValueType
		mult float64 // multiplier (1 normally, 60 for TIMELEFT minutes→seconds)
	}{
		{"BCHARGE", c.batteryCharge, prometheus.GaugeValue, 1},
		{"TIMELEFT", c.batteryRuntime, prometheus.GaugeValue, 60}, // minutes → seconds
		{"BATTV", c.batteryVoltage, prometheus.GaugeValue, 1},
		{"LINEV", c.inputVoltage, prometheus.GaugeValue, 1},
		{"OUTPUTV", c.outputVoltage, prometheus.GaugeValue, 1},
		{"LOADPCT", c.loadPercent, prometheus.GaugeValue, 1},
		{"TONBATT", c.timeOnBattery, prometheus.GaugeValue, 1},
		{"NUMXFERS", c.transfersTotal, prometheus.CounterValue, 1},
		{"NOMPOWER", c.nominalPower, prometheus.GaugeValue, 1},
	}
	for _, m := range metricMapping {
		if v, ok := data.Metrics[m.key]; ok {
			ch <- prometheus.MustNewConstMetric(m.desc, m.vt, v*m.mult, c.instance)
		}
	}

	// Status flags derived from the STATUS string (space-separated tokens).
	statusOnline := 0.0
	if strings.Contains(data.Status, "ONLINE") {
		statusOnline = 1.0
	}
	statusOnBattery := 0.0
	if strings.Contains(data.Status, "ONBATT") {
		statusOnBattery = 1.0
	}
	statusLowBattery := 0.0
	if strings.Contains(data.Status, "LOWBATT") {
		statusLowBattery = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.statusOnline, prometheus.GaugeValue, statusOnline, c.instance)
	ch <- prometheus.MustNewConstMetric(c.statusOnBattery, prometheus.GaugeValue, statusOnBattery, c.instance)
	ch <- prometheus.MustNewConstMetric(c.statusLowBattery, prometheus.GaugeValue, statusLowBattery, c.instance)

	// Service status.
	status, present, sErr := client.FetchServiceStatusOptional("apcupsdServiceStatus")
	if sErr != nil {
		c.log.Warn("failed to fetch apcupsd service status", "err", sErr)
	} else if present {
		running := 0.0
		if status == "running" {
			running = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.serviceRunning, prometheus.GaugeValue, running, c.instance)
	}

	return nil
}
