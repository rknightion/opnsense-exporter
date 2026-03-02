package collector

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type firmwareCollector struct {
	log *slog.Logger

	info                 *prometheus.Desc
	needsReboot          *prometheus.Desc
	upgradeNeedsReboot   *prometheus.Desc
	lastCheckTimestamp   *prometheus.Desc
	newPackagesCount     *prometheus.Desc
	upgradePackagesCount *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &firmwareCollector{
		subsystem: FirmwareSubsystem,
	})
}

func (c *firmwareCollector) Name() string {
	return c.subsystem
}

func (c *firmwareCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel

	c.log.Debug("Registering collector", "collector", c.Name())

	c.info = buildPrometheusDesc(c.subsystem, "info",
		"OPNsense firmware information", []string{"os_version", "product_version", "product_id", "product_abi"})

	c.needsReboot = buildPrometheusDesc(c.subsystem, "needs_reboot",
		"Whether OPNsense needs a reboot (1 = yes, 0 = no)", nil)

	c.upgradeNeedsReboot = buildPrometheusDesc(c.subsystem, "upgrade_needs_reboot",
		"Whether the upgrade requires a reboot (1 = yes, 0 = no)", nil)

	c.lastCheckTimestamp = buildPrometheusDesc(c.subsystem, "last_check_timestamp_seconds",
		"Unix timestamp of the last firmware update check", nil)

	c.newPackagesCount = buildPrometheusDesc(c.subsystem, "new_packages_count",
		"Number of new packages available", nil)

	c.upgradePackagesCount = buildPrometheusDesc(c.subsystem, "upgrade_packages_count",
		"Number of packages with available upgrades", nil)
}

func (c *firmwareCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.info
	ch <- c.needsReboot
	ch <- c.upgradeNeedsReboot
	ch <- c.lastCheckTimestamp
	ch <- c.newPackagesCount
	ch <- c.upgradePackagesCount
}

func (c *firmwareCollector) Update(client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchFirmwareStatus()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(c.info, prometheus.GaugeValue, 1,
		data.OsVersion, data.ProductVersion, data.ProductId, data.ProductABI, c.instance)

	var needsRebootVal float64
	if data.NeedsReboot {
		needsRebootVal = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.needsReboot, prometheus.GaugeValue, needsRebootVal, c.instance)

	var upgradeNeedsRebootVal float64
	if data.UpgradeNeedsReboot {
		upgradeNeedsRebootVal = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.upgradeNeedsReboot, prometheus.GaugeValue, upgradeNeedsRebootVal, c.instance)

	ch <- prometheus.MustNewConstMetric(c.lastCheckTimestamp, prometheus.GaugeValue, data.LastCheckTimestamp, c.instance)

	ch <- prometheus.MustNewConstMetric(c.newPackagesCount, prometheus.GaugeValue, float64(data.NewPackages), c.instance)

	ch <- prometheus.MustNewConstMetric(c.upgradePackagesCount, prometheus.GaugeValue, float64(data.UpgradePackages), c.instance)

	return nil
}
