package opnsense

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rknightion/opnsense2otel/v5/internal/fetchshare"
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
	// UpgradeMajorVersion is the release a pending MAJOR upgrade would move the
	// box to (#583) — "26.7", not a package version. check.sh assigns it as
	// `upgrade_major_version=$(opnsense-update -vR)` (line 368) only inside
	// `if [ -n "${packages_is_size}" ]` (line 366), then writes the key
	// unconditionally at line 422. So within a stored check the key is always
	// present and an EMPTY STRING is the "no major upgrade offered" signal;
	// emptiness is the availability test, there is no separate flag.
	UpgradeMajorVersion string `json:"upgrade_major_version"`
	// UpgradeNeedsReboot mirrors the SAME key check.sh writes at line 423
	// (initialised "0" at line 68, flipped to "1" when a major upgrade's
	// packages/kernel/base sets differ from the running ones).
	//
	// It is read from the top level here and from Product.ProductCheck below,
	// resolved new-wins-else-legacy by upgradeNeedsReboot(). Those two are not
	// really two sources: FirmwareController.php:126-127 builds the response as
	// `$response = $product['product_check']; $response['product'] = $product;`
	// — the top level IS product_check, served a second time under `product`.
	// The exporter historically read only the nested copy; the pointer keeps
	// that path working on any generation that omits the top-level key while
	// letting the canonical location win.
	UpgradeNeedsReboot *flexString `json:"upgrade_needs_reboot"`
	// Product carries the identity fields unconditionally (#640): live on a
	// 26.7.1_1 box that has never run a firmware check, GET
	// core/firmware/status returns exactly product/status/status_msg at the top
	// level — no last_check, no top-level product_id/product_version/
	// product_abi — with the identity present under product.* regardless.
	// ProductID/ProductVersion/ProductAbi here are that unconditional copy,
	// resolved against the legacy top-level fields top-level-wins-else-nested
	// by productID()/productVersion()/productAbi() below — the same pattern
	// upgradeNeedsReboot() already uses for product.product_check.
	Product struct {
		ProductID      string `json:"product_id"`
		ProductVersion string `json:"product_version"`
		ProductAbi     string `json:"product_abi"`
		ProductCheck   struct {
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
	// MajorUpgradeAvailable / MajorUpgradeVersion describe a pending MAJOR
	// release upgrade (26.1 -> 26.7), which is a different maintenance decision
	// from the package updates the *_packages_count gauges track: it is a
	// scheduled-window job, not something to apply on a Tuesday afternoon.
	// Both are meaningful only when CheckPresent — before the box's first check
	// there is nothing stored to read.
	MajorUpgradeAvailable bool
	MajorUpgradeVersion   string
}

// upgradeNeedsReboot resolves the major-upgrade reboot flag new-wins-else-
// legacy: the canonical top-level key when the response carries it, otherwise
// the copy nested under product.product_check. See the field comments on
// firmwareStatusResponse for why these are the same datum served twice.
func (r *firmwareStatusResponse) upgradeNeedsReboot() bool {
	if r.UpgradeNeedsReboot != nil {
		return r.UpgradeNeedsReboot.String() == "1"
	}
	return r.Product.ProductCheck.UpgradeNeedsReboot == "1"
}

// productID, productVersion and productAbi resolve the three identity fields
// top-level-wins-else-nested (#640): a legacy/checked box's top-level copy
// wins when present, and every box — checked or not — falls back to the copy
// nested under product.*, which FirmwareController.php populates
// unconditionally. Mirrors upgradeNeedsReboot() above.
func (r *firmwareStatusResponse) productID() string {
	if r.ProductID != "" {
		return r.ProductID
	}
	return r.Product.ProductID
}

func (r *firmwareStatusResponse) productVersion() string {
	if r.ProductVersion != "" {
		return r.ProductVersion
	}
	return r.Product.ProductVersion
}

func (r *firmwareStatusResponse) productAbi() string {
	if r.ProductAbi != "" {
		return r.ProductAbi
	}
	return r.Product.ProductAbi
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

// firmwareStatusCacheable is the response-cache admission rule for the firmware
// status endpoint (cacheAdmissionRules). The box answers 200 with an empty
// last_check while an update check is running and right after the stored status
// is cleared; that body carries no check result, and FetchFirmwareStatus's
// LastCheck gate below turns it into "every check-dependent series absent".
// Caching it would hold that absence for the full --exporter.firmware-cache-ttl
// (12h by default) while the box finished its check seconds later — GitHub issue
// 724. So a body without a last_check is decoded and served but never stored;
// the next poll asks the firewall again. Anything that does not decode is
// refused too: put() must never hold a body do() would not have accepted.
func firmwareStatusCacheable(body []byte) bool {
	var probe struct {
		LastCheck string `json:"last_check"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return false
	}
	return strings.TrimSpace(probe.LastCheck) != ""
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

	// Identity (#640): product_id/product_version/product_abi are present
	// unconditionally under product.* — verified live on a 26.7.1_1 box that
	// has never run a firmware check, which returns nothing but
	// product/status/status_msg at the top level. Populated OUTSIDE the
	// LastCheck gate below (unlike the check-dependent fields, which genuinely
	// have no answer before a check has run), and only when the resolved value
	// is non-empty, so a box with neither a top-level nor a nested copy keeps
	// NewFirmwareStatus()'s "undefined" default rather than being overwritten
	// with "".
	if id := resp.productID(); id != "" {
		data.ProductId = id
	}
	if v := resp.productVersion(); v != "" {
		data.ProductVersion = v
	}
	if abi := resp.productAbi(); abi != "" {
		data.ProductABI = abi
	}

	// OPNsense >= 25.x no longer flips the status field; a populated
	// last_check is the signal that an update check has run and the rest of
	// the payload is meaningful (upstream PR #101 / issue #100).
	if resp.LastCheck != "" {
		data.CheckPresent = true
		// os_version (the FreeBSD version) is NOT present under product.* —
		// unlike the three identity fields above, it genuinely only exists
		// once a check has run (#640). The fallback below fires when this
		// never runs.
		//
		// The prefix trim is what keeps ONE fact in ONE representation. This
		// endpoint sends the FreeBSD version WITH a "FreeBSD " prefix
		// ("FreeBSD 15.1-RELEASE-p1", observed on the prod box), while the
		// seam fallback below carries SystemInfo.FreeBSDVersion, which
		// system_resources.go has already trimmed. Without this, os_version
		// would mean two different string shapes depending on whether the box
		// had run a check — the label would silently change format after the
		// first update check, which is exactly the state-dependent-meaning
		// defect #640 was filed about. Trimming here also makes os_version
		// agree with opnsense_system_info's freebsd_version, its only other
		// publisher.
		//
		// Assigned only when non-empty, so an empty value cannot clobber the
		// "undefined" sentinel that the seam fallback below keys on — a
		// checked box that omits os_version still reaches the fallback rather
		// than publishing an empty label.
		if os := strings.TrimPrefix(strings.TrimSpace(resp.OsVersion), "FreeBSD "); os != "" {
			data.OsVersion = os
		}
		data.LastCheck = resp.LastCheck
		data.NeedsReboot = resp.NeedsReboot == "1"
		data.UpgradeNeedsReboot = resp.upgradeNeedsReboot()
		// Emptiness is the signal (see the field comment): a version string
		// means a major upgrade is on offer, "" means none is.
		data.MajorUpgradeVersion = strings.TrimSpace(resp.UpgradeMajorVersion)
		data.MajorUpgradeAvailable = data.MajorUpgradeVersion != ""
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

	// os_version fallback (#640): this endpoint never carries the FreeBSD
	// version before a check has run, so on an unchecked box data.OsVersion is
	// still NewFirmwareStatus()'s "undefined" sentinel at this point. Rather
	// than have this COLD-tier (15m) collector make its own duplicate
	// systemInformation request for data a second consumer already fetches,
	// read the shared result seam (#571) that fetchSystemInfo publishes to on
	// every one of its own (medium-tier, 60s default) polls.
	//
	// maxAge=20m is chosen to comfortably span this collector's own 15m poll
	// interval: even if the operator has overridden the system collector down
	// to something as slow as this collector's own default tier, whatever it
	// last published is still well within the window. It is not unbounded,
	// though — if the system collector is disabled entirely the seam simply
	// never gets an entry and this always misses, which is the correct answer
	// (no fabricated data), not a bug to work around with a longer window.
	//
	// A miss — seam not wired, system collector disabled, or nothing fresh
	// enough — degrades to leaving OsVersion at "undefined"; it never turns
	// into an error and never triggers a second request to the box.
	if data.OsVersion == "undefined" {
		if info, ok := fetchshare.Fresh[*SystemInfo](c.results, fetchshare.KeySystemInformation, 20*time.Minute); ok && info != nil && info.FreeBSDVersion != "" {
			data.OsVersion = info.FreeBSDVersion
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
		// FlatSize is the installed size — as a FORMATTED STRING, not bytes
		// (#583). scripts/firmware/query.sh:52 asks pkg for `%sh`, which is
		// already humanized ("168KiB"), and FirmwareController.php:854 then
		// passes it through formatBytes(), which returns any non-numeric input
		// unchanged (line 55-58). It is therefore the same mixed-unit base-2
		// shape as the firmware status download_size field, and is parsed with
		// the same helper.
		//
		// Two lossy edges to keep in mind for anything that sums these:
		// pkg/formatBytes render one decimal place, so the value is the display
		// string's precision (±0.05 of its unit) and not the exact on-disk
		// size; and an empty size is rewritten to the literal "N/A" (see
		// Locked below), which parses to nothing rather than to zero.
		FlatSize string `json:"flatsize"`
		// Locked / Automatic are pkg's `%k` and `%a` (query.sh:52): whether the
		// package is pinned against updates, and whether it was installed as an
		// automatic dependency rather than explicitly.
		//
		// TRAP: these NEVER arrive as "0". pkg emits a bare 0 or 1, but
		// FirmwareController.php:852-853 replaces any value for which PHP's
		// empty() is true with gettext('N/A') — and empty("0") is true in PHP.
		// So the wire vocabulary is exactly {"1", "N/A"}. Reading "N/A" as
		// false is a decode of a known-false value, not a guess: the producing
		// query emits nothing but 0 and 1.
		Locked    string `json:"locked"`
		Automatic string `json:"automatic"`
	} `json:"plugin"`
}

// FirmwarePlugin is one installed OPNsense plugin (os-*) from core/firmware/info.
type FirmwarePlugin struct {
	Name    string
	Version string
	// SizeBytes is the installed size in bytes, parsed from upstream's
	// formatted flatsize string. HasSize is false when the field was "N/A" or
	// otherwise unparseable — emit no series then, since a 0 would show the
	// plugin as free in a disk-attribution view.
	SizeBytes float64
	HasSize   bool
	// Locked: pkg-locked, so it will not be updated by an upgrade — the reason
	// a plugin can sit at an old version while everything else moves.
	// Automatic: installed as a dependency rather than deliberately.
	Locked    bool
	Automatic bool
}

// parseFirmwarePluginSize converts a firmwareInfo plugin[].flatsize value into
// bytes. The unit handling is shared with the firmware status download_size
// parser (both come out of the same formatBytes/pkg humanization), but this is
// a SINGLE item — never the comma-separated list download_size can be — and an
// empty value is not zero here: upstream rewrites an empty size to "N/A", so an
// empty string can only mean the key was missing entirely. Returns ok=false for
// anything it cannot resolve, including "N/A".
func parseFirmwarePluginSize(raw string) (float64, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	m := firmwareSizeItem.FindStringSubmatch(raw)
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
	return value * multiplier, true
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
// firmwareInfoCacheable is the response-cache admission rule for the firmware
// info endpoint (cacheAdmissionRules, OPN-0095 sweep). FirmwareController::
// infoAction builds package[] from `firmware local` and marks a plugin installed
// only from that same result, so an empty package list means pkg answered
// nothing (the pkg database is locked or configd timed out during an upgrade or
// check): the base system is itself a package and is never absent. Caching that
// body would report zero installed plugins for --exporter.firmware-cache-ttl.
func firmwareInfoCacheable(body []byte) bool {
	var probe struct {
		Package []json.RawMessage `json:"package"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return false
	}
	return len(probe.Package) > 0
}

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
		size, hasSize := parseFirmwarePluginSize(p.FlatSize)
		data.InstalledPlugins = append(data.InstalledPlugins, FirmwarePlugin{
			Name:      p.Name,
			Version:   p.Version,
			SizeBytes: size,
			HasSize:   hasSize,
			Locked:    p.Locked == "1",
			Automatic: p.Automatic == "1",
		})
	}
	return data, nil
}
