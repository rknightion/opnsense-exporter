package opnsense

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

type firmwareStatusResponse struct {
	LastCheck      string `json:"last_check"`
	NeedsReboot    string `json:"needs_reboot"`
	OsVersion      string `json:"os_version"`
	ProductID      string `json:"product_id"`
	ProductVersion string `json:"product_version"`
	ProductAbi     string `json:"product_abi"`
	NewPackages    []struct {
		Name       string `json:"name"`
		Repository string `json:"repository"`
		Version    string `json:"version"`
	} `json:"new_packages"`
	UpgradePackages []struct {
		Name           string `json:"name"`
		Repository     string `json:"repository"`
		CurrentVersion string `json:"current_version"`
		NewVersion     string `json:"new_version"`
		Size           string `json:"size,omitempty"`
	} `json:"upgrade_packages"`
	// DowngradePackages / ReinstallPackages are state-dependent supersets that
	// appear once a firmware check has run (#237): packages available to downgrade
	// (shape mirrors upgrade_packages: current_version/new_version) and packages
	// available to reinstall (shape mirrors new_packages: a single version field).
	// Only counts are exported — see FirmwareStatus.DowngradePackages/ReinstallPackages.
	DowngradePackages []struct {
		Name           string `json:"name"`
		Repository     string `json:"repository"`
		CurrentVersion string `json:"current_version"`
		NewVersion     string `json:"new_version"`
	} `json:"downgrade_packages"`
	ReinstallPackages []struct {
		Name       string `json:"name"`
		Repository string `json:"repository"`
		Version    string `json:"version"`
	} `json:"reinstall_packages"`
	// RemovePackages / UpgradeSets complete the five action arrays (#373).
	// Only counts are exported. Both were EMPTY on the 26.7.r_35 testbed, so
	// their inner shapes are derived from the installed
	// /usr/local/opnsense/scripts/firmware/check.sh (remove_packages at lines
	// 256/262, upgrade_sets at 374/385/397) rather than from a live capture.
	// They are modelled fully anyway: the contract canary reports unexpected
	// NESTED keys, and an under-modelled array would generate exactly the noise
	// that reporting exists to surface.
	RemovePackages []struct {
		Name       string `json:"name"`
		Repository string `json:"repository"`
		Version    string `json:"version"`
	} `json:"remove_packages"`
	UpgradeSets []struct {
		Name           string `json:"name"`
		Size           string `json:"size"`
		CurrentVersion string `json:"current_version"`
		NewVersion     string `json:"new_version"`
		Repository     string `json:"repository"`
	} `json:"upgrade_sets"`
	Product struct {
		ProductCheck struct {
			UpgradeNeedsReboot string `json:"upgrade_needs_reboot"`
		} `json:"product_check"`
	} `json:"product"`
	Status string `json:"status"`
	// Connection / Repository are the stored check's own verdict (#373).
	// Upstream persists them even when the check FAILED, which is what makes a
	// failed check distinguishable from a healthy check with no pending
	// updates. Both observed as "ok" on the 26.7.r_35 testbed.
	Connection string `json:"connection"`
	Repository string `json:"repository"`
	// DownloadSize is a comma-separated list of mixed-unit sizes (#380).
	// Observed as "37MiB" on the 26.7.r_35 testbed.
	DownloadSize string `json:"download_size"`
	// all_packages / all_sets are deliberately NOT decoded: upstream builds
	// them by recombining the five action arrays above, so decoding them would
	// duplicate every entry we already count.
}

type FirmwareStatus struct {
	LastCheck             string
	NeedsReboot           bool
	NewPackages           int
	OsVersion             string
	ProductABI            string
	ProductId             string
	ProductVersion        string
	UpgradePackages       int
	UpgradeNeedsReboot    bool
	LastCheckTimestamp    float64
	UpgradePackageDetails []FirmwarePackageUpgrade
	// DowngradePackages / ReinstallPackages (#237): counts only, siblings of
	// NewPackages/UpgradePackages. Populated only once a firmware check has run
	// since boot, same as the rest of this state-dependent envelope.
	DowngradePackages int
	ReinstallPackages int
	// CheckPresent reports that the box holds a stored update check
	// (last_check non-empty). It gates every #373/#380 series: before the first
	// check the envelope is minimal and there is no verdict to report, so
	// emitting one would fabricate health data.
	CheckPresent bool
	// Connection / Repository are the canonicalized stored-check verdict
	// (#373), or "" when no check is stored. Values come from a closed
	// vocabulary; anything unrecognized collapses to "unknown" so no free-form
	// upstream message can reach a label.
	Connection string
	Repository string
	// RemovePackages / UpgradeSets (#373): counts only, completing the package
	// action family.
	RemovePackages int
	UpgradeSets    int
	// PendingDownloadBytes is the parsed download_size (#380).
	// PendingDownloadBytesValid is false when there is no stored check or the
	// field could not be parsed unambiguously — the metric is then not emitted
	// at all, rather than reporting a fabricated zero.
	PendingDownloadBytes      float64
	PendingDownloadBytesValid bool
}

// The two CLOSED state vocabularies upstream's firmware check can persist,
// taken from the header comment of the installed 26.7
// /usr/local/opnsense/scripts/firmware/check.sh (lines 30-31). Note that both
// lists include "error", which #373's issue body omitted.
var (
	firmwareConnectionStates = map[string]struct{}{
		"error":           {},
		"unauthenticated": {},
		"misconfigured":   {},
		"unresolved":      {},
		"ok":              {},
	}
	firmwareRepositoryStates = map[string]struct{}{
		"error":      {},
		"untrusted":  {},
		"unsigned":   {},
		"revoked":    {},
		"incomplete": {},
		"forbidden":  {},
		"ok":         {},
	}
)

// canonicalizeFirmwareCheckState maps a raw upstream state onto its closed
// vocabulary. Anything else — a future upstream state, an empty field on an
// older release, or a free-form message that ended up in the wrong key —
// collapses to "unknown". This is what keeps the state label bounded: the raw
// string is NEVER passed through.
func canonicalizeFirmwareCheckState(raw string, vocabulary map[string]struct{}) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if _, ok := vocabulary[s]; ok {
		return s
	}
	return "unknown"
}

func canonicalizeConnectionState(raw string) string {
	return canonicalizeFirmwareCheckState(raw, firmwareConnectionStates)
}

func canonicalizeRepositoryState(raw string) string {
	return canonicalizeFirmwareCheckState(raw, firmwareRepositoryStates)
}

// firmwareSizeItem matches one download_size list item: a number, optional
// whitespace, and an optional unit suffix. Anchored at both ends so trailing
// prose ("quite big", "37MiB soon") is treated as malformed instead of being
// silently half-parsed.
var firmwareSizeItem = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]*)$`)

// parseFirmwareDownloadSize converts the firmware status "download_size" field
// into base-2 bytes (#380). The field is a comma-separated list of mixed-unit
// sizes, e.g. "37MiB" or "180MiB,40MiB"; every item is summed. The unit is the
// FIRST alphabetic character after the number, case-insensitive; no unit letter
// (or a bare "B") means bytes.
//
// Contract derived from the installed 26.7 FirmwareController.php lines
// 126-161. One deliberate difference: upstream's own regex is `(\d+)` and so
// TRUNCATES a fractional size, while we accept the decimal. Our value can
// therefore be slightly larger than the number the GUI displays.
//
// Returns ok=false when any item cannot be parsed. Callers must then emit
// nothing rather than a fabricated zero: an unparseable size is unknown, not
// "no download pending". An empty field IS unambiguously zero — upstream leaves
// it empty when there is nothing to download.
func parseFirmwareDownloadSize(raw string) (float64, bool) {
	var total float64
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			// Empty list item (empty field, or a leading/trailing separator
			// from upstream's string accumulation) contributes nothing.
			continue
		}
		m := firmwareSizeItem.FindStringSubmatch(item)
		if m == nil {
			return 0, false
		}
		value, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return 0, false
		}
		multiplier, ok := firmwareSizeMultiplier(m[2])
		if !ok {
			return 0, false
		}
		total += value * multiplier
	}
	return total, true
}

// firmwareSizeMultiplier resolves a unit suffix to its base-2 multiplier. Only
// the first letter is significant, so "K", "KiB" and "kB" are the same unit.
func firmwareSizeMultiplier(unit string) (float64, bool) {
	if unit == "" {
		return 1, true
	}
	switch strings.ToLower(unit[:1]) {
	case "b":
		return 1, true
	case "k":
		return 1024, true
	case "m":
		return 1024 * 1024, true
	case "g":
		return 1024 * 1024 * 1024, true
	case "t":
		return 1024 * 1024 * 1024 * 1024, true
	case "p":
		return 1024 * 1024 * 1024 * 1024 * 1024, true
	}
	// An unrecognized unit is a future/localized representation we must not
	// guess at — fail safe instead of under-reporting by 1024^n.
	return 0, false
}

func NewFirmwareStatus() FirmwareStatus {
	return FirmwareStatus{
		LastCheck:          "undefined",
		NeedsReboot:        false,
		NewPackages:        0,
		OsVersion:          "undefined",
		ProductABI:         "undefined",
		ProductId:          "undefined",
		ProductVersion:     "undefined",
		UpgradePackages:    0,
		UpgradeNeedsReboot: false,
		LastCheckTimestamp: 0,
	}
}

func parseLastCheckTimestamp(raw string) float64 {
	if raw == "" || raw == "undefined" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err == nil {
		return float64(t.Unix())
	}
	t, err = time.Parse("2006-01-02T15:04:05", raw)
	if err == nil {
		return float64(t.UTC().Unix())
	}
	// OPNsense 25.x+ emits e.g. "Tue Jun  9 10:13:17 BST 2026" (time.UnixDate).
	// ParseInLocation with UTC keeps the result deterministic regardless of
	// the host's timezone (plain time.Parse resolves abbreviations like "BST"
	// against the local zone). Zone abbreviations therefore parse with a zero
	// offset, so the value can be off by the box's zone offset — acceptable
	// for a last-check age.
	t, err = time.ParseInLocation(time.UnixDate, raw, time.UTC)
	if err == nil {
		return float64(t.Unix())
	}
	return 0
}

func (c *Client) FetchFirmwareStatus() (FirmwareStatus, *APICallError) {
	var resp firmwareStatusResponse
	data := NewFirmwareStatus()

	url, ok := c.endpoints["firmware"]

	if !ok {
		return data, &APICallError{
			Endpoint:   "firmware",
			Message:    "Missing endpoint 'firmwareStatus'",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	// OPNsense >= 25.x no longer flips the status field; a populated
	// last_check is the signal that an update check has run and the rest of
	// the payload is meaningful (upstream PR #101 / issue #100).
	if resp.LastCheck != "" {
		data.CheckPresent = true
		data.OsVersion = resp.OsVersion
		data.ProductABI = resp.ProductAbi
		data.ProductId = resp.ProductID
		data.ProductVersion = resp.ProductVersion
		data.LastCheck = resp.LastCheck
		data.NeedsReboot = resp.NeedsReboot == "1"
		data.UpgradeNeedsReboot = resp.Product.ProductCheck.UpgradeNeedsReboot == "1"
		data.LastCheckTimestamp = parseLastCheckTimestamp(resp.LastCheck)
		data.NewPackages = len(resp.NewPackages)
		data.UpgradePackages = len(resp.UpgradePackages)
		data.DowngradePackages = len(resp.DowngradePackages)
		data.ReinstallPackages = len(resp.ReinstallPackages)
		data.RemovePackages = len(resp.RemovePackages)
		data.UpgradeSets = len(resp.UpgradeSets)
		// #373: the stored check's own verdict. Upstream writes last_check
		// BEFORE it attempts the package operation and persists these two
		// fields even when the check failed, so a populated last_check alone
		// does not mean the repository was reachable, authenticated and
		// verified. An older release that omits them reads "unknown", which is
		// deliberately not treated as success.
		data.Connection = canonicalizeConnectionState(resp.Connection)
		data.Repository = canonicalizeRepositoryState(resp.Repository)
		// #380: pending download size, parsed only inside the stored-check
		// branch so nothing is reported before the first check.
		data.PendingDownloadBytes, data.PendingDownloadBytesValid = parseFirmwareDownloadSize(resp.DownloadSize)
		if !data.PendingDownloadBytesValid {
			data.PendingDownloadBytes = 0
		}
		for _, p := range resp.UpgradePackages {
			data.UpgradePackageDetails = append(data.UpgradePackageDetails, FirmwarePackageUpgrade{
				Name:           p.Name,
				CurrentVersion: p.CurrentVersion,
				NewVersion:     p.NewVersion,
			})
		}
	}
	return data, nil
}

// FirmwarePackageUpgrade describes one package with a pending upgrade, from
// the firmware status "upgrade_packages" list.
type FirmwarePackageUpgrade struct {
	Name           string
	CurrentVersion string
	NewVersion     string
}

type firmwareInfoResponse struct {
	ProductID      string `json:"product_id"`
	ProductVersion string `json:"product_version"`
	Plugin         []struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Installed string `json:"installed"`
	} `json:"plugin"`
}

// FirmwarePlugin is one installed OPNsense plugin (os-*) from core/firmware/info.
type FirmwarePlugin struct {
	Name    string
	Version string
}

// FirmwareInfo is the parsed subset of api/core/firmware/info the exporter
// uses: product identity plus installed plugins.
type FirmwareInfo struct {
	ProductID        string
	ProductVersion   string
	InstalledPlugins []FirmwarePlugin
}

// FetchFirmwareInfo fetches api/core/firmware/info and returns the product
// identity plus the list of installed plugins. The 900+ entry "package"
// catalogue in the response is deliberately not decoded — only the plugin
// list (~100 entries, ~15 installed on a typical box) is used, filtered to
// installed == "1", to keep metric cardinality bounded.
func (c *Client) FetchFirmwareInfo() (FirmwareInfo, *APICallError) {
	var resp firmwareInfoResponse
	var data FirmwareInfo

	url, ok := c.endpoints["firmwareInfo"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "firmwareInfo",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	data.ProductID = resp.ProductID
	data.ProductVersion = resp.ProductVersion
	for _, p := range resp.Plugin {
		if p.Installed != "1" {
			continue
		}
		data.InstalledPlugins = append(data.InstalledPlugins, FirmwarePlugin{
			Name:    p.Name,
			Version: p.Version,
		})
	}
	return data, nil
}
