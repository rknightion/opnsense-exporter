package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

// hardwareCollector exposes two independent, plugin-gated hardware facts:
//   - DMI/BIOS system identity from the os-dmidecode plugin (one bounded-label
//     info gauge; wholly slow-moving, changes only when the hardware itself
//     changes).
//   - Deciso DEC-series dual-PSU GPIO status from the os-dec-hw plugin (a 0/1
//     gauge per PSU, only emitted on real Deciso hardware).
//
// The two plugins are unrelated and independently installable, so both
// Fetch* calls run every Update regardless of whether the other's data was
// present (#217).
type hardwareCollector struct {
	log *slog.Logger

	dmiInfo   *prometheus.Desc
	psuStatus *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &hardwareCollector{
		subsystem: HardwareSubsystem,
	})
}

func (c *hardwareCollector) Name() string {
	return c.subsystem
}

func (c *hardwareCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.dmiInfo = buildPrometheusDesc(c.subsystem, "dmi_info",
		"DMI system and BIOS identity as reported by dmidecode (value is always 1; use labels). Silent when the os-dmidecode plugin is absent.",
		[]string{"manufacturer", "product", "version", "serial", "family", "bios_vendor", "bios_version", "bios_release"},
	)
	c.psuStatus = buildPrometheusDesc(c.subsystem, "psu_status",
		"Deciso DEC-series power supply status (1 = powered, 0 = not powered). Only emitted on hardware with a GPIO power-status device; silent when the os-dec-hw plugin is absent or no such hardware is detected.",
		[]string{"psu"},
	)
}

func (c *hardwareCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.dmiInfo
	ch <- c.psuStatus
}

func (c *hardwareCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	dmi, err := client.FetchDMIInfo()
	if err != nil {
		return err
	}

	if dmi.Present {
		ch <- prometheus.MustNewConstMetric(
			c.dmiInfo,
			prometheus.GaugeValue,
			1,
			dmi.Manufacturer,
			dmi.Product,
			dmi.Version,
			dmi.Serial,
			dmi.Family,
			dmi.BIOSVendor,
			dmi.BIOSVersion,
			dmi.BIOSRelease,
			c.instance,
		)
	}

	// os-dec-hw is an entirely separate plugin from os-dmidecode; a fetch error here
	// must not suppress the DMI info metric already queued above (mirrors the
	// leases/prefix-delegation split in dhcpv6.go).
	psu, perr := client.FetchDechwPowerStatus()
	if perr != nil {
		c.log.Warn("failed to fetch DEC-HW power status", "err", perr)
		return nil
	}

	if psu.Present {
		if psu.PSU1 != nil {
			ch <- prometheus.MustNewConstMetric(
				c.psuStatus,
				prometheus.GaugeValue,
				boolToFloat64(*psu.PSU1),
				"1",
				c.instance,
			)
		}
		if psu.PSU2 != nil {
			ch <- prometheus.MustNewConstMetric(
				c.psuStatus,
				prometheus.GaugeValue,
				boolToFloat64(*psu.PSU2),
				"2",
				c.instance,
			)
		}
	}

	return nil
}

func boolToFloat64(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
