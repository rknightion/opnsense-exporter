package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type firmwareCollector struct {
	log *slog.Logger

	info                   *prometheus.Desc
	needsReboot            *prometheus.Desc
	upgradeNeedsReboot     *prometheus.Desc
	lastCheckTimestamp     *prometheus.Desc
	newPackagesCount       *prometheus.Desc
	upgradePackagesCount   *prometheus.Desc
	downgradePackagesCount *prometheus.Desc
	reinstallPackagesCount *prometheus.Desc
	packageUpdateAvailable *prometheus.Desc
	pluginInstalled        *prometheus.Desc

	subsystem      string
	instance       string
	detailsEnabled bool
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
		"Whether applying the currently AVAILABLE update would require a reboot, or a plugin has set the reboot-required hook (1 = yes, 0 = no). This tracks update availability, NOT a completed-but-unapplied install - it can be 1 for days before anything is installed and is not cleared by rebooting. For the major-version-upgrade reboot signal see upgrade_needs_reboot.", nil)

	c.upgradeNeedsReboot = buildPrometheusDesc(c.subsystem, "upgrade_needs_reboot",
		"Whether a pending major-version upgrade (product.product_check) requires a reboot to apply (1 = yes, 0 = no). Distinct from needs_reboot, which tracks base/kernel/plugin update availability.", nil)

	c.lastCheckTimestamp = buildPrometheusDesc(c.subsystem, "last_check_timestamp_seconds",
		"Unix timestamp of the last firmware update check", nil)

	c.newPackagesCount = buildPrometheusDesc(c.subsystem, "new_packages_count",
		"Number of new packages available", nil)

	c.upgradePackagesCount = buildPrometheusDesc(c.subsystem, "upgrade_packages_count",
		"Number of packages with available upgrades", nil)

	c.downgradePackagesCount = buildPrometheusDesc(c.subsystem, "downgrade_packages_count",
		"Number of packages available to downgrade", nil)

	c.reinstallPackagesCount = buildPrometheusDesc(c.subsystem, "reinstall_packages_count",
		"Number of packages available to reinstall", nil)

	c.packageUpdateAvailable = buildPrometheusDesc(c.subsystem, "package_update_available",
		"Pending package update (1 = update available). Only emitted when --exporter.enable-firmware-package-details is set.",
		[]string{"name", "installed_version", "new_version"})

	c.pluginInstalled = buildPrometheusDesc(c.subsystem, "plugin_installed",
		"Installed OPNsense plugin (1 = installed). Only emitted when --exporter.enable-firmware-package-details is set.",
		[]string{"name", "version"})
}

// SetDetailsEnabled toggles the per-package detail metrics
// (package_update_available, plugin_installed).
func (c *firmwareCollector) SetDetailsEnabled(enabled bool) {
	c.detailsEnabled = enabled
}

func (c *firmwareCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.info
	ch <- c.needsReboot
	ch <- c.upgradeNeedsReboot
	ch <- c.lastCheckTimestamp
	ch <- c.newPackagesCount
	ch <- c.upgradePackagesCount
	ch <- c.downgradePackagesCount
	ch <- c.reinstallPackagesCount
	ch <- c.packageUpdateAvailable
	ch <- c.pluginInstalled
}

func (c *firmwareCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
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

	ch <- prometheus.MustNewConstMetric(c.downgradePackagesCount, prometheus.GaugeValue, float64(data.DowngradePackages), c.instance)

	ch <- prometheus.MustNewConstMetric(c.reinstallPackagesCount, prometheus.GaugeValue, float64(data.ReinstallPackages), c.instance)

	if c.detailsEnabled {
		for _, p := range data.UpgradePackageDetails {
			ch <- prometheus.MustNewConstMetric(c.packageUpdateAvailable, prometheus.GaugeValue, 1,
				p.Name, p.CurrentVersion, p.NewVersion, c.instance)
		}

		info, infoErr := client.FetchFirmwareInfo()
		if infoErr != nil {
			return infoErr
		}
		for _, p := range info.InstalledPlugins {
			ch <- prometheus.MustNewConstMetric(c.pluginInstalled, prometheus.GaugeValue, 1,
				p.Name, p.Version, c.instance)
		}
	}

	return nil
}
