package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
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
	removePackagesCount    *prometheus.Desc
	upgradeSetsCount       *prometheus.Desc
	updateCheckSuccess     *prometheus.Desc
	updateCheckState       *prometheus.Desc
	pendingDownloadBytes   *prometheus.Desc
	packageUpdateAvailable *prometheus.Desc
	pluginInstalled        *prometheus.Desc
	majorUpgradeAvailable  *prometheus.Desc
	majorUpgradeInfo       *prometheus.Desc
	pluginSizeBytes        *prometheus.Desc
	pluginLocked           *prometheus.Desc
	pluginAutomatic        *prometheus.Desc

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

	c.removePackagesCount = buildPrometheusDesc(c.subsystem, "remove_packages_count",
		"Number of packages the pending update would remove", nil)

	c.upgradeSetsCount = buildPrometheusDesc(c.subsystem, "upgrade_sets_count",
		"Number of pending upgrade sets (the synthetic base/kernel entries of a major or point upgrade, not ordinary packages)", nil)

	c.updateCheckSuccess = buildPrometheusDesc(c.subsystem, "update_check_success",
		"Whether the firewall's stored update check actually succeeded (1 = the repository was reachable, authenticated and verified; 0 = it was not). Only emitted once a check has been stored. This is NOT the same as \"no updates pending\": before this metric existed, a DNS failure, expired subscription, revoked fingerprint or unavailable release train looked exactly like a healthy check with zero updates. Reflects the STORED result of the box's own check (refreshed roughly daily) as seen through the exporter's firmware response cache, so a state change can take up to --exporter.firmware-cache-ttl (default 12h) to appear.", nil)

	c.updateCheckState = buildPrometheusDesc(c.subsystem, "update_check_state",
		"Current state of one component of the firewall's stored update check (always 1; exactly one series per component). component is connection or repository. state is drawn from OPNsense's closed vocabularies - connection: error/unauthenticated/misconfigured/unresolved/ok, repository: error/untrusted/unsigned/revoked/incomplete/forbidden/ok - and anything else, including a future upstream state, collapses to unknown. Only emitted once a check has been stored.", []string{"component", "state"})

	c.pendingDownloadBytes = buildPrometheusDesc(c.subsystem, "pending_download_bytes",
		"Total size in bytes the pending update would download, parsed from the stored check's mixed-unit download_size list (base-2 units). Only emitted once a check has been stored AND the field parsed unambiguously - a value that cannot be parsed emits no series rather than a fabricated 0. Unlike the OPNsense GUI, which truncates a fractional size, fractions are kept, so this can read slightly higher than the number the GUI displays.", nil)

	c.packageUpdateAvailable = buildPrometheusDesc(c.subsystem, "package_update_available",
		"Pending package update (1 = update available). Only emitted when --exporter.enable-firmware-package-details is set.",
		[]string{"name", "installed_version", "new_version"})

	c.pluginInstalled = buildPrometheusDesc(c.subsystem, "plugin_installed",
		"Installed OPNsense plugin (1 = installed). Only emitted when --exporter.enable-firmware-package-details is set.",
		[]string{"name", "version"})

	// #583. Spelled out as a literal []string, NOT built with append(): docgen's
	// AST label extractor follows a plain slice literal or variable but silently
	// records an EMPTY label set for an append(...) expression, which then fails
	// the docs-vs-registry cross-check with a message that points nowhere near
	// here. Keep it a literal.
	pluginLabels := []string{"name", "version"}

	c.majorUpgradeAvailable = buildPrometheusDesc(c.subsystem, "major_upgrade_available",
		"Whether a MAJOR release upgrade is on offer (1 = yes), e.g. 26.1 to 26.7. This is a different maintenance decision from the package updates upgrade_packages_count tracks - a scheduled-window job, not something to apply mid-afternoon - and upgrade_needs_reboot describes THIS upgrade, not the package ones. Only emitted once the box has a stored update check; before that there is nothing to report and a 0 would claim 'no major upgrade pending' on a firewall that has never looked.",
		nil)
	c.majorUpgradeInfo = buildPrometheusDesc(c.subsystem, "major_upgrade_info",
		"The release a pending major upgrade would move this firewall to (always 1; read the version label). Emitted ONLY while such an upgrade is on offer, so the series appearing is itself the signal and there is never a stale version=\"\" series hanging around. Cardinality is one series, changing at most once or twice a year.",
		[]string{"version"})

	c.pluginSizeBytes = buildPrometheusDesc(c.subsystem, "plugin_size_bytes",
		"Installed size of this OPNsense plugin, in bytes. Only emitted when --exporter.enable-firmware-package-details is set. APPROXIMATE: OPNsense reports the size as an already-humanised string with one decimal place (pkg's %sh, then formatBytes), so this is that display value converted to base-2 bytes, not the exact on-disk size - good for attributing disk pressure between plugins, not for accounting. A plugin whose size upstream could not report emits no series rather than 0.",
		pluginLabels)
	c.pluginLocked = buildPrometheusDesc(c.subsystem, "plugin_locked",
		"Whether this plugin is pkg-locked against updates (1 = locked). Only emitted when --exporter.enable-firmware-package-details is set. This is the explanation for a plugin that sits at an old version while everything else moves - a locked plugin is skipped by an upgrade rather than failing it.",
		pluginLabels)
	c.pluginAutomatic = buildPrometheusDesc(c.subsystem, "plugin_automatic",
		"Whether this plugin was installed automatically as a dependency rather than chosen deliberately (1 = automatic). Only emitted when --exporter.enable-firmware-package-details is set.",
		pluginLabels)
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
	ch <- c.removePackagesCount
	ch <- c.upgradeSetsCount
	ch <- c.updateCheckSuccess
	ch <- c.updateCheckState
	ch <- c.pendingDownloadBytes
	ch <- c.packageUpdateAvailable
	ch <- c.pluginInstalled
	ch <- c.majorUpgradeAvailable
	ch <- c.majorUpgradeInfo
	ch <- c.pluginSizeBytes
	ch <- c.pluginLocked
	ch <- c.pluginAutomatic
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

	ch <- prometheus.MustNewConstMetric(c.removePackagesCount, prometheus.GaugeValue, float64(data.RemovePackages), c.instance)

	ch <- prometheus.MustNewConstMetric(c.upgradeSetsCount, prometheus.GaugeValue, float64(data.UpgradeSets), c.instance)

	// #373: the check-health family is gated on a stored check existing. Before
	// the box's first check there is no verdict, and emitting one would
	// fabricate health data — success=1 on a firewall whose update path has
	// never been exercised is exactly the false-safe signal this fixes.
	if data.CheckPresent {
		var successVal float64
		if data.Connection == "ok" && data.Repository == "ok" {
			successVal = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.updateCheckSuccess, prometheus.GaugeValue, successVal, c.instance)

		// Exactly one series per component: the CURRENT state only, so the
		// label set stays bounded and a state change does not leave a stale
		// series behind.
		ch <- prometheus.MustNewConstMetric(c.updateCheckState, prometheus.GaugeValue, 1,
			"connection", data.Connection, c.instance)
		ch <- prometheus.MustNewConstMetric(c.updateCheckState, prometheus.GaugeValue, 1,
			"repository", data.Repository, c.instance)

		// #583: gated on the same stored check for the same reason — before the
		// first check upstream sends the minimal envelope and there is no
		// upgrade_major_version to read at all.
		var majorVal float64
		if data.MajorUpgradeAvailable {
			majorVal = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.majorUpgradeAvailable, prometheus.GaugeValue, majorVal, c.instance)
		// The info series exists only while there is a version to name. A
		// version="" series would be permanent noise on every box that is
		// already current.
		if data.MajorUpgradeAvailable {
			ch <- prometheus.MustNewConstMetric(c.majorUpgradeInfo, prometheus.GaugeValue, 1,
				data.MajorUpgradeVersion, c.instance)
		}
	}

	// #380: absent unless a stored check exists AND download_size parsed.
	if data.PendingDownloadBytesValid {
		ch <- prometheus.MustNewConstMetric(c.pendingDownloadBytes, prometheus.GaugeValue, data.PendingDownloadBytes, c.instance)
	}

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
			// #583. HasSize is false when upstream reported "N/A" — no size
			// series then, since 0 would show the plugin as costing nothing.
			if p.HasSize {
				ch <- prometheus.MustNewConstMetric(c.pluginSizeBytes, prometheus.GaugeValue,
					p.SizeBytes, p.Name, p.Version, c.instance)
			}
			// locked/automatic are always emitted: upstream's wire vocabulary is
			// {"1","N/A"} (PHP's empty("0") is true, so a false flag is rewritten
			// to "N/A"), and "N/A" is a decoded false, not an unknown.
			lockedVal := 0.0
			if p.Locked {
				lockedVal = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.pluginLocked, prometheus.GaugeValue,
				lockedVal, p.Name, p.Version, c.instance)
			automaticVal := 0.0
			if p.Automatic {
				automaticVal = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.pluginAutomatic, prometheus.GaugeValue,
				automaticVal, p.Name, p.Version, c.instance)
		}
	}

	return nil
}
