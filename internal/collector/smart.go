package collector

import (
	"context"
	"log/slog"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
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
	attributeFailed    *prometheus.Desc

	nvmeAvailableSpare   *prometheus.Desc
	nvmePercentageUsed   *prometheus.Desc
	nvmeMediaErrors      *prometheus.Desc
	nvmeUnsafeShutdowns  *prometheus.Desc
	nvmeDataUnitsRead    *prometheus.Desc
	nvmeDataUnitsWritten *prometheus.Desc

	rotationRate   *prometheus.Desc
	spareAvailable *prometheus.Desc
	enduranceUsed  *prometheus.Desc

	infoErrors *prometheus.Desc

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

	c.devicesTotal = buildPrometheusDesc(c.subsystem, "devices",
		"Current number of SMART-monitored devices enumerated by the os-smart plugin",
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

	c.rotationRate = buildPrometheusDesc(c.subsystem, "device_rotation_rate_rpm",
		"Drive rotation speed in RPM as reported by the drive itself. 0 explicitly means "+
			"solid-state (no spinning platter); any other value is the platter's actual RPM. "+
			"Use this to pick which wear/temperature thresholds apply — an ABSENT series means "+
			"the drive didn't report this field at all, which is not the same as a genuine 0 (#577).",
		[]string{"device"},
	)
	c.spareAvailable = buildPrometheusDesc(c.subsystem, "device_spare_available_percent",
		"SSD spare/reserve blocks remaining, as a percentage of the original spare pool. "+
			"smartctl derives this by matching vendor-specific reallocated-sector/spare-block "+
			"attributes, so it is only reported for drives it can normalize — falling toward the "+
			"drive's own threshold means the wear-leveling reserve is running out (#577).",
		[]string{"device"},
	)
	c.enduranceUsed = buildPrometheusDesc(c.subsystem, "device_endurance_used_percent",
		"SSD endurance used, normalized by smartctl from vendor-specific wear-leveling "+
			"attributes (0-100+; values above 100 mean the drive has exceeded its rated write "+
			"endurance and failure risk keeps rising). Only reported for drives smartctl can "+
			"normalize this from (#577).",
		[]string{"device"},
	)
	// attribute_failed is a SEPARATE metric rather than a new "when_failed"
	// label on attribute_value/worst/threshold/raw above (#577). Labels are
	// part of a series' identity: appending one to an already-shipped series
	// starts a brand-new series under the same name, breaking continuity of
	// every existing panel/rule that reads it (e.g. the SMART Attributes
	// table and Critical Attribute Raw Values panel in grafana/tabs/system.py
	// both query attribute_raw/value/worst/threshold today). A dedicated
	// gauge, emitted only when an attribute has actually failed, costs zero
	// extra cardinality on a healthy fleet and leaves the existing series
	// untouched.
	// Spelled out rather than built with append(attrLabels..., "when_failed"): docgen
	// extracts a metric's label set from the AST, and it can follow a plain []string
	// variable but not an append() expression — the latter documents the metric with an
	// EMPTY label set and fails TestVerifyAgainstRegistryPasses. Keep this literal.
	failedLabels := []string{"device", "attribute_name", "attribute_id", "when_failed"}
	c.attributeFailed = buildPrometheusDesc(c.subsystem, "attribute_failed",
		"Emitted with value 1 ONLY for a SATA SMART attribute whose own when_failed marker is "+
			"non-empty — i.e. that specific attribute, not just the drive's overall smart_status, "+
			"has failed its threshold now or in the past. when_failed carries the raw smartctl "+
			"value (\"now\" or \"past\"). A healthy attribute emits no series at all (absence means "+
			"\"never failed\", not \"unknown\"), so a clean fleet adds ~0 cardinality. This is "+
			"deliberately a separate metric rather than a new label on attribute_value/worst/"+
			"threshold/raw: adding a label to those would change their series identity and break "+
			"continuity of every existing panel/rule reading them (#577).",
		failedLabels,
	)

	// #615: the per-device info path used to fail at Debug level and nothing
	// else, so a decode bug that cost EVERY per-device SMART metric on the one
	// box with a real disk read as perfectly healthy — collector_success=1,
	// devices=1, and not another series in the family. This gauge is the
	// thing that would have caught it on day one.
	//
	// reason="failed" = the device is reported by name only, nothing decoded.
	// reason="partial" = the payload disagreed with our schema on some field;
	// the device is kept, but at least one value is missing or degraded to a
	// zero, which is not distinguishable at the metric it feeds.
	c.infoErrors = buildPrometheusDesc(c.subsystem, "device_info_errors",
		"Devices whose smartInfo payload could not be fully read in the last poll, by reason (failed = nothing decoded, partial = schema disagreement)",
		[]string{"reason"},
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
	ch <- c.rotationRate
	ch <- c.spareAvailable
	ch <- c.enduranceUsed
	ch <- c.attributeFailed
	ch <- c.infoErrors
}

func (c *smartCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchSMARTDevices()
	if err != nil {
		return err
	}

	// os-smart absent → Present=false; stay silent so devices=0 (plugin
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

	// Always emitted, both reasons, zero included: a series that only appears
	// when something is wrong cannot be alerted on, and "absent" is exactly
	// how #615 hid.
	ch <- prometheus.MustNewConstMetric(
		c.infoErrors,
		prometheus.GaugeValue,
		float64(data.InfoFailures),
		"failed",
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.infoErrors,
		prometheus.GaugeValue,
		float64(data.InfoPartialDecodes),
		"partial",
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

		// RotationRate is presence-gated on the pointer, NOT on truthiness of
		// the dereferenced value: 0 is a genuine SSD reading and must still
		// emit a series (#577), unlike a nil pointer which means the drive
		// never reported this field at all.
		if dev.RotationRate != nil {
			ch <- prometheus.MustNewConstMetric(
				c.rotationRate,
				prometheus.GaugeValue,
				*dev.RotationRate,
				dev.Device,
				c.instance,
			)
		}

		if dev.SpareAvailable != nil {
			ch <- prometheus.MustNewConstMetric(
				c.spareAvailable,
				prometheus.GaugeValue,
				*dev.SpareAvailable,
				dev.Device,
				c.instance,
			)
		}

		if dev.EnduranceUsed != nil {
			ch <- prometheus.MustNewConstMetric(
				c.enduranceUsed,
				prometheus.GaugeValue,
				*dev.EnduranceUsed,
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

			// attribute_failed is gated on when_failed being non-empty, not
			// merely present: every attribute row carries this field, so
			// "" (never failed) must emit NOTHING, or a clean fleet would
			// carry one series per attribute per device for no reason (#577).
			if attr.WhenFailed != "" {
				ch <- prometheus.MustNewConstMetric(c.attributeFailed, prometheus.GaugeValue,
					1, dev.Device, attr.Name, id, attr.WhenFailed, c.instance)
			}
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
