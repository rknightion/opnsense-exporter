package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
)

func TestFirmwareCollector_Update(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"last_check": "2024-01-15T10:30:00Z",
			"needs_reboot": "0",
			"os_version": "24.1",
			"product_id": "opnsense",
			"product_version": "24.1.1",
			"product_abi": "24.1:amd64",
			"new_packages": [
				{"name": "pkg1", "repository": "OPNsense", "version": "1.0"}
			],
			"upgrade_packages": [
				{"name": "pkg2", "repository": "OPNsense", "current_version": "1.0", "new_version": "2.0"}
			],
			"product": {
				"product_check": {
					"upgrade_needs_reboot": "0"
				}
			},
			"status": "ok"
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &firmwareCollector{subsystem: FirmwareSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 10 unconditional metrics (8 + the #373 remove_packages/upgrade_sets
	// counts) + the 3 stored-check series (#373 success + 2 states) + the #380
	// pending download gauge (download_size absent = unambiguously 0) + the
	// #583 major_upgrade_available gauge. major_upgrade_info is NOT counted:
	// this fixture carries no upgrade_major_version, so no major upgrade is on
	// offer and there is no version to name.
	expectedCount := 15
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Verify info metric has correct labels
	infoLabels := getMetricLabels(metrics[0])
	if infoLabels["os_version"] != "24.1" {
		t.Errorf("expected os_version '24.1', got %q", infoLabels["os_version"])
	}
	if infoLabels["product_version"] != "24.1.1" {
		t.Errorf("expected product_version '24.1.1', got %q", infoLabels["product_version"])
	}
	if infoLabels["product_id"] != "opnsense" {
		t.Errorf("expected product_id 'opnsense', got %q", infoLabels["product_id"])
	}
	if infoLabels["product_abi"] != "24.1:amd64" {
		t.Errorf("expected product_abi '24.1:amd64', got %q", infoLabels["product_abi"])
	}

	// needs_reboot should be 0
	if v := getMetricValue(metrics[1]); v != 0 {
		t.Errorf("expected needs_reboot=0, got %v", v)
	}

	// upgrade_needs_reboot should be 0
	if v := getMetricValue(metrics[2]); v != 0 {
		t.Errorf("expected upgrade_needs_reboot=0, got %v", v)
	}

	// last_check_timestamp_seconds should be > 0
	if v := getMetricValue(metrics[3]); v <= 0 {
		t.Errorf("expected last_check_timestamp_seconds > 0, got %v", v)
	}

	// new_packages_count should be 1
	if v := getMetricValue(metrics[4]); v != 1 {
		t.Errorf("expected new_packages_count=1, got %v", v)
	}

	// upgrade_packages_count should be 1
	if v := getMetricValue(metrics[5]); v != 1 {
		t.Errorf("expected upgrade_packages_count=1, got %v", v)
	}
}

func TestFirmwareCollector_Update_StatusNone(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "none"
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &firmwareCollector{subsystem: FirmwareSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// No stored check: only the 10 unconditional metrics. The #373/#380
	// check-health series are deliberately absent — see
	// TestFirmwareCollector_NoStoredCheckEmitsNoCheckSeries.
	expectedCount := 10
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestFirmwareCollector_Update_NeedsReboot(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"last_check": "2024-01-15T10:30:00Z",
			"needs_reboot": "1",
			"os_version": "24.1",
			"product_id": "opnsense",
			"product_version": "24.1.1",
			"product_abi": "24.1:amd64",
			"new_packages": [],
			"upgrade_packages": [],
			"product": {
				"product_check": {
					"upgrade_needs_reboot": "1"
				}
			},
			"status": "ok"
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &firmwareCollector{subsystem: FirmwareSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 15 since #583 added major_upgrade_available; see the count comment in
	// TestFirmwareCollector_Update.
	expectedCount := 15
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// needs_reboot should be 1
	if v := getMetricValue(metrics[1]); v != 1 {
		t.Errorf("expected needs_reboot=1, got %v", v)
	}

	// upgrade_needs_reboot should be 1
	if v := getMetricValue(metrics[2]); v != 1 {
		t.Errorf("expected upgrade_needs_reboot=1, got %v", v)
	}
}

// firmwareMetricsByName groups the collected metrics by fqName so the
// #373/#380 assertions do not depend on emission order.
func firmwareMetricsByName(metrics []prometheus.Metric, name string) []prometheus.Metric {
	var out []prometheus.Metric
	for _, m := range metrics {
		if hasFqName(m, name) {
			out = append(out, m)
		}
	}
	return out
}

// firmwareCheckMetrics collects the firmware collector against a canned
// core/firmware/status body.
func firmwareCheckMetrics(t *testing.T, body string) []prometheus.Metric {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &firmwareCollector{subsystem: FirmwareSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	return collectMetrics(t, c, client)
}

// TestFirmwareCollector_UpdateCheckHealthy covers #373's happy path: a stored
// check that succeeded emits success=1 plus exactly one bounded state series
// per component, and both new count gauges.
func TestFirmwareCollector_UpdateCheckHealthy(t *testing.T) {
	metrics := firmwareCheckMetrics(t, `{
		"last_check": "2026-07-25T10:00:00Z",
		"connection": "ok",
		"repository": "ok",
		"status": "update",
		"remove_packages": [{"name": "pkg-gone", "repository": "OPNsense", "version": "1.0"}],
		"upgrade_sets": [
			{"name": "base", "size": "180MiB", "current_version": "26.1.11", "new_version": "26.7", "repository": "OPNsense"}
		]
	}`)

	success := firmwareMetricsByName(metrics, "opnsense_firmware_update_check_success")
	if len(success) != 1 {
		t.Fatalf("expected exactly 1 update_check_success series, got %d", len(success))
	}
	if v := getMetricValue(success[0]); v != 1 {
		t.Errorf("expected update_check_success=1, got %v", v)
	}
	if labels := getMetricLabels(success[0]); len(labels) != 1 {
		t.Errorf("update_check_success must carry only the instance label, got %v", labels)
	}

	states := firmwareMetricsByName(metrics, "opnsense_firmware_update_check_state")
	if len(states) != 2 {
		t.Fatalf("expected exactly 2 update_check_state series (one per component), got %d", len(states))
	}
	got := map[string]string{}
	for _, m := range states {
		labels := getMetricLabels(m)
		got[labels["component"]] = labels["state"]
		if v := getMetricValue(m); v != 1 {
			t.Errorf("update_check_state must always be 1, got %v", v)
		}
	}
	if got["connection"] != "ok" || got["repository"] != "ok" {
		t.Errorf("unexpected state series: %v", got)
	}

	removeCount := firmwareMetricsByName(metrics, "opnsense_firmware_remove_packages_count")
	if len(removeCount) != 1 || getMetricValue(removeCount[0]) != 1 {
		t.Errorf("expected remove_packages_count=1, got %v", removeCount)
	}
	setsCount := firmwareMetricsByName(metrics, "opnsense_firmware_upgrade_sets_count")
	if len(setsCount) != 1 || getMetricValue(setsCount[0]) != 1 {
		t.Errorf("expected upgrade_sets_count=1, got %v", setsCount)
	}

	assertNoDuplicateSeries(t, metrics)
}

// TestFirmwareCollector_UpdateCheckFailures covers the false-safe failure mode
// #373 exists to fix: a check that ran but could not resolve, authenticate or
// verify the repository must read success=0, not "no updates pending".
func TestFirmwareCollector_UpdateCheckFailures(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		wantConnection string
		wantRepository string
	}{
		{
			name: "dns failure",
			body: `{
				"last_check": "2026-07-25T10:00:00Z",
				"connection": "unresolved",
				"repository": "ok",
				"status": "error",
				"status_msg": "Cannot resolve host pkg.opnsense.example.invalid"
			}`,
			wantConnection: "unresolved",
			wantRepository: "ok",
		},
		{
			name: "expired subscription",
			body: `{
				"last_check": "2026-07-25T10:00:00Z",
				"connection": "unauthenticated",
				"repository": "forbidden",
				"status": "error"
			}`,
			wantConnection: "unauthenticated",
			wantRepository: "forbidden",
		},
		{
			name: "revoked fingerprint",
			body: `{
				"last_check": "2026-07-25T10:00:00Z",
				"connection": "ok",
				"repository": "revoked",
				"status": "error"
			}`,
			wantConnection: "ok",
			wantRepository: "revoked",
		},
		{
			name: "future upstream state collapses to unknown",
			body: `{
				"last_check": "2026-07-25T10:00:00Z",
				"connection": "brand-new-failure-mode",
				"repository": "https://pkg.opnsense.org/FreeBSD:14:amd64/26.7"
			}`,
			wantConnection: "unknown",
			wantRepository: "unknown",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			metrics := firmwareCheckMetrics(t, tc.body)

			success := firmwareMetricsByName(metrics, "opnsense_firmware_update_check_success")
			if len(success) != 1 {
				t.Fatalf("expected 1 update_check_success series, got %d", len(success))
			}
			if v := getMetricValue(success[0]); v != 0 {
				t.Errorf("expected update_check_success=0, got %v", v)
			}

			states := firmwareMetricsByName(metrics, "opnsense_firmware_update_check_state")
			if len(states) != 2 {
				t.Fatalf("expected 2 update_check_state series, got %d", len(states))
			}
			got := map[string]string{}
			for _, m := range states {
				labels := getMetricLabels(m)
				got[labels["component"]] = labels["state"]
			}
			if got["connection"] != tc.wantConnection || got["repository"] != tc.wantRepository {
				t.Errorf("state series = %v, want connection=%q repository=%q", got, tc.wantConnection, tc.wantRepository)
			}

			// No free-form message, mirror URL or repository identifier may
			// reach a label — that is what keeps this family bounded.
			for _, m := range metrics {
				for name, value := range getMetricLabels(m) {
					for _, forbidden := range []string{"Cannot resolve", "http", "://", "opnsense.example", "pkg.opnsense", "brand-new-failure-mode", "OPNsense"} {
						if strings.Contains(value, forbidden) {
							t.Errorf("label %s=%q leaks free-form upstream text (%q)", name, value, forbidden)
						}
					}
				}
			}
		})
	}
}

// TestFirmwareCollector_NoStoredCheckEmitsNoCheckSeries is the anti-fabrication
// guard: before the box has ever run an update check there is no verdict, so
// the #373/#380 series must be ABSENT rather than reporting a healthy-looking 0
// (or, worse, success=1).
func TestFirmwareCollector_NoStoredCheckEmitsNoCheckSeries(t *testing.T) {
	metrics := firmwareCheckMetrics(t, `{"status": "none"}`)

	for _, name := range []string{
		"opnsense_firmware_update_check_success",
		"opnsense_firmware_update_check_state",
		"opnsense_firmware_pending_download_bytes",
	} {
		if got := firmwareMetricsByName(metrics, name); len(got) != 0 {
			t.Errorf("%s must not be emitted without a stored check, got %d series", name, len(got))
		}
	}

	// The count gauges are unconditional siblings of the existing package
	// counts, so they stay at 0 (same convention as new/upgrade/downgrade).
	for _, name := range []string{
		"opnsense_firmware_remove_packages_count",
		"opnsense_firmware_upgrade_sets_count",
	} {
		got := firmwareMetricsByName(metrics, name)
		if len(got) != 1 {
			t.Fatalf("expected %s to always be emitted, got %d series", name, len(got))
		}
		if v := getMetricValue(got[0]); v != 0 {
			t.Errorf("expected %s=0, got %v", name, v)
		}
	}
}

// TestFirmwareCollector_PendingDownloadBytes covers #380 end to end, including
// the malformed case, which must emit NOTHING rather than a fabricated 0.
func TestFirmwareCollector_PendingDownloadBytes(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantSerie bool
		wantValue float64
	}{
		{
			name:      "live dev-box value",
			body:      `{"last_check": "2026-07-25T10:00:00Z", "download_size": "37MiB"}`,
			wantSerie: true,
			wantValue: 37 * 1024 * 1024,
		},
		{
			name:      "base upgrade csv sum",
			body:      `{"last_check": "2026-07-25T10:00:00Z", "download_size": "180MiB,40MiB"}`,
			wantSerie: true,
			wantValue: 220 * 1024 * 1024,
		},
		{
			name:      "nothing to download",
			body:      `{"last_check": "2026-07-25T10:00:00Z", "download_size": ""}`,
			wantSerie: true,
			wantValue: 0,
		},
		{
			name:      "malformed never fabricates zero",
			body:      `{"last_check": "2026-07-25T10:00:00Z", "download_size": "a few hundred megs"}`,
			wantSerie: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			metrics := firmwareCheckMetrics(t, tc.body)
			got := firmwareMetricsByName(metrics, "opnsense_firmware_pending_download_bytes")
			if !tc.wantSerie {
				if len(got) != 0 {
					t.Fatalf("expected no pending_download_bytes series, got %d (value %v)", len(got), getMetricValue(got[0]))
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("expected 1 pending_download_bytes series, got %d", len(got))
			}
			if v := getMetricValue(got[0]); v != tc.wantValue {
				t.Errorf("pending_download_bytes = %v, want %v", v, tc.wantValue)
			}
			if labels := getMetricLabels(got[0]); len(labels) != 1 {
				t.Errorf("pending_download_bytes must carry only the instance label, got %v", labels)
			}
		})
	}
}

func TestFirmwareCollector_Name(t *testing.T) {
	c := &firmwareCollector{subsystem: FirmwareSubsystem}
	if c.Name() != FirmwareSubsystem {
		t.Errorf("expected %s, got %s", FirmwareSubsystem, c.Name())
	}
}

const firmwareDetailsStatusBody = `{
	"last_check": "2024-01-15T10:30:00Z",
	"needs_reboot": "0",
	"os_version": "24.1",
	"product_id": "opnsense",
	"product_version": "24.1.1",
	"product_abi": "24.1:amd64",
	"new_packages": [],
	"upgrade_packages": [
		{"name": "curl", "repository": "OPNsense", "current_version": "8.8.0", "new_version": "8.9.1"}
	],
	"product": {
		"product_check": {
			"upgrade_needs_reboot": "0"
		}
	},
	"status": "ok"
}`

const firmwareDetailsInfoBody = `{
	"product_id": "opnsense",
	"product_version": "24.1.1",
	"plugin": [
		{"name": "os-ddclient", "version": "1.31", "installed": "1"},
		{"name": "os-acme-client", "version": "4.10", "installed": "0"}
	]
}`

func TestFirmwareCollector_Update_DetailsEnabled(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/core/firmware/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(firmwareDetailsStatusBody))
	})
	mux.HandleFunc("/api/core/firmware/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(firmwareDetailsInfoBody))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &firmwareCollector{subsystem: FirmwareSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)

	// 15 non-detail metrics (8 base + #237 downgrade/reinstall counts + #373
	// remove/upgrade-set counts + #373 success/2 states + #380 download bytes
	// + #583 major_upgrade_available) + 1 package_update_available
	// + 1 plugin_installed + the two #583 per-plugin policy gauges
	// (plugin_locked, plugin_automatic) = 19. plugin_size_bytes is NOT counted:
	// this fixture's plugin row carries no flatsize, and an unreportable size
	// emits no series rather than a fabricated 0.
	expectedCount := 19
	if len(metrics) != expectedCount {
		t.Fatalf("expected %d metrics with details enabled, got %d", expectedCount, len(metrics))
	}

	// Looked up by name rather than index: the detail metrics are appended last,
	// so a new unconditional metric must not silently shift these assertions.
	pkgMetrics := firmwareMetricsByName(metrics, "opnsense_firmware_package_update_available")
	if len(pkgMetrics) != 1 {
		t.Fatalf("expected 1 package_update_available series, got %d", len(pkgMetrics))
	}
	pkgLabels := getMetricLabels(pkgMetrics[0])
	if pkgLabels["name"] != "curl" || pkgLabels["installed_version"] != "8.8.0" || pkgLabels["new_version"] != "8.9.1" {
		t.Errorf("unexpected package_update_available labels: %v", pkgLabels)
	}
	if v := getMetricValue(pkgMetrics[0]); v != 1 {
		t.Errorf("expected package_update_available=1, got %v", v)
	}

	// plugin_installed for os-ddclient (os-acme-client is not installed)
	plgMetrics := firmwareMetricsByName(metrics, "opnsense_firmware_plugin_installed")
	if len(plgMetrics) != 1 {
		t.Fatalf("expected 1 plugin_installed series, got %d", len(plgMetrics))
	}
	plgLabels := getMetricLabels(plgMetrics[0])
	if plgLabels["name"] != "os-ddclient" || plgLabels["version"] != "1.31" {
		t.Errorf("unexpected plugin_installed labels: %v", plgLabels)
	}
}

func TestFirmwareCollector_Update_DetailsDisabledByDefault(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/core/firmware/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(firmwareDetailsStatusBody))
	})
	mux.HandleFunc("/api/core/firmware/info", func(w http.ResponseWriter, r *http.Request) {
		t.Error("core/firmware/info must not be fetched when details are disabled")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &firmwareCollector{subsystem: FirmwareSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 15 since #583 added major_upgrade_available, which is unconditional once
	// a check is stored; none of the #583 per-plugin gauges appear, which is
	// the point of this test.
	expectedCount := 15
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics with details disabled, got %d", expectedCount, len(metrics))
	}
}

// TestFirmwareCollector_MajorUpgrade covers #583: a pending major release
// (26.1 -> 26.7) is a scheduled-window decision, not the same maintenance
// event as the package updates *_packages_count already tracks.
func TestFirmwareCollector_MajorUpgrade(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"last_check":"Tue Jun  9 10:13:17 UTC 2026",
			"os_version":"FreeBSD 14","product_version":"26.1","product_id":"OPNsense","product_abi":"26.1",
			"upgrade_major_version":"26.7","upgrade_needs_reboot":"1",
			"product":{"product_check":{"upgrade_needs_reboot":"1"}},"status":"ok"}`))
	}))
	defer server.Close()

	c := &firmwareCollector{subsystem: FirmwareSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, newCollectorTestClient(t, server))
	assertNoDuplicateSeries(t, metrics)

	var sawAvailable, sawInfo bool
	for _, m := range metrics {
		switch {
		case hasFqName(m, "opnsense_firmware_major_upgrade_available"):
			sawAvailable = true
			if v := getMetricValue(m); v != 1 {
				t.Errorf("major_upgrade_available = %v, want 1", v)
			}
		case hasFqName(m, "opnsense_firmware_major_upgrade_info"):
			sawInfo = true
			if got := getMetricLabels(m)["version"]; got != "26.7" {
				t.Errorf("major_upgrade_info version label = %q, want %q", got, "26.7")
			}
			if v := getMetricValue(m); v != 1 {
				t.Errorf("major_upgrade_info = %v, want 1", v)
			}
		}
	}
	if !sawAvailable || !sawInfo {
		t.Errorf("missing metric(s): available=%v info=%v", sawAvailable, sawInfo)
	}
}

// TestFirmwareCollector_NoMajorUpgrade: with a check stored but no major
// upgrade on offer, the 0/1 gauge must be a real 0 (so an alert has a series
// to evaluate) while the version info series must be ABSENT — there is no
// version to name, and an info metric labelled version="" is noise that
// never goes away.
func TestFirmwareCollector_NoMajorUpgrade(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"last_check":"Tue Jun  9 10:13:17 UTC 2026",
			"upgrade_major_version":"","upgrade_needs_reboot":"0",
			"product":{"product_check":{"upgrade_needs_reboot":"0"}},"status":"ok"}`))
	}))
	defer server.Close()

	c := &firmwareCollector{subsystem: FirmwareSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, newCollectorTestClient(t, server))

	var sawAvailable bool
	for _, m := range metrics {
		if hasFqName(m, "opnsense_firmware_major_upgrade_info") {
			t.Fatalf("major_upgrade_info must not be emitted with no major upgrade (labels %v)", getMetricLabels(m))
		}
		if hasFqName(m, "opnsense_firmware_major_upgrade_available") {
			sawAvailable = true
			if v := getMetricValue(m); v != 0 {
				t.Errorf("major_upgrade_available = %v, want 0", v)
			}
		}
	}
	if !sawAvailable {
		t.Error("major_upgrade_available must be emitted as a real 0 once a check is stored")
	}
}

// TestFirmwareCollector_NoStoredCheckEmitsNoMajorUpgradeSeries: before the box
// has ever run an update check the envelope is minimal and there is nothing
// stored to read. Emitting available=0 there would claim "no major upgrade
// pending" on a firewall that has never looked.
func TestFirmwareCollector_NoStoredCheckEmitsNoMajorUpgradeSeries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"product":{"product_check":null},"status":"none","status_msg":"check first"}`))
	}))
	defer server.Close()

	c := &firmwareCollector{subsystem: FirmwareSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, newCollectorTestClient(t, server))

	for _, m := range metrics {
		if hasFqName(m, "opnsense_firmware_major_upgrade_available") ||
			hasFqName(m, "opnsense_firmware_major_upgrade_info") {
			t.Fatalf("no major-upgrade series may be emitted before a check is stored: %s", m.Desc().String())
		}
	}
}

// TestFirmwareCollector_PluginDetail covers the #583 per-plugin gauges. They
// ride the SAME --exporter.enable-firmware-package-details gate as
// plugin_installed, so nothing new is paid for on a default scrape.
func TestFirmwareCollector_PluginDetail(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/core/firmware/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"last_check":"Tue Jun  9 10:13:17 UTC 2026","status":"ok",
			"product":{"product_check":{"upgrade_needs_reboot":"0"}}}`))
	})
	mux.HandleFunc("/api/core/firmware/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"product_id":"OPNsense","product_version":"26.1","plugin":[
			{"name":"os-tailscale","version":"1.4","installed":"1","flatsize":"168KiB","locked":"1","automatic":"N/A"},
			{"name":"os-frr","version":"1.0","installed":"1","flatsize":"N/A","locked":"N/A","automatic":"1"}
		]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := &firmwareCollector{subsystem: FirmwareSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)
	metrics := collectMetrics(t, c, newCollectorTestClient(t, server))
	assertNoDuplicateSeries(t, metrics)

	size := map[string]float64{}
	locked := map[string]float64{}
	automatic := map[string]float64{}
	for _, m := range metrics {
		name := getMetricLabels(m)["name"]
		switch {
		case hasFqName(m, "opnsense_firmware_plugin_size_bytes"):
			size[name] = getMetricValue(m)
		case hasFqName(m, "opnsense_firmware_plugin_locked"):
			locked[name] = getMetricValue(m)
		case hasFqName(m, "opnsense_firmware_plugin_automatic"):
			automatic[name] = getMetricValue(m)
		}
	}

	if size["os-tailscale"] != 168*1024 {
		t.Errorf("os-tailscale size = %v, want %v", size["os-tailscale"], 168*1024)
	}
	// "N/A" is not zero. A plugin whose size upstream could not report must
	// emit no size series rather than appear free in a disk-attribution panel.
	if _, ok := size["os-frr"]; ok {
		t.Errorf("os-frr must emit no size series, got %v", size["os-frr"])
	}
	// The "N/A" trap: PHP's empty("0") is true, so upstream rewrites a false
	// flag to "N/A" and the wire vocabulary is {"1","N/A"} — never "0".
	if locked["os-tailscale"] != 1 || locked["os-frr"] != 0 {
		t.Errorf("locked = %v, want os-tailscale=1 os-frr=0", locked)
	}
	if automatic["os-tailscale"] != 0 || automatic["os-frr"] != 1 {
		t.Errorf("automatic = %v, want os-tailscale=0 os-frr=1", automatic)
	}
}

// TestFirmwareCollector_PluginDetailOffByDefault pins the gating: none of the
// #583 per-plugin series may appear on a default scrape.
func TestFirmwareCollector_PluginDetailOffByDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"last_check":"Tue Jun  9 10:13:17 UTC 2026","status":"ok",
			"product":{"product_check":{"upgrade_needs_reboot":"0"}}}`))
	}))
	defer server.Close()

	c := &firmwareCollector{subsystem: FirmwareSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, newCollectorTestClient(t, server))

	for _, m := range metrics {
		for _, banned := range []string{
			"opnsense_firmware_plugin_size_bytes",
			"opnsense_firmware_plugin_locked",
			"opnsense_firmware_plugin_automatic",
		} {
			if hasFqName(m, banned) {
				t.Errorf("%s emitted without --exporter.enable-firmware-package-details", banned)
			}
		}
	}
}
