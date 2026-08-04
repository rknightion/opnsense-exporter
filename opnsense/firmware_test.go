package opnsense

import (
	"net/http"
	"strings"
	"testing"

	"github.com/rknightion/opnsense2otel/v4/internal/fetchshare"
)

func TestFetchFirmwareStatus_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"last_check": "2024-01-15T10:30:00",
			"needs_reboot": "1",
			"os_version": "24.1",
			"product_id": "opnsense",
			"product_version": "24.1.1",
			"product_abi": "24.1:amd64",
			"new_packages": [
				{"name": "pkg-new", "repository": "OPNsense", "version": "1.0"}
			],
			"upgrade_packages": [
				{"name": "pkg-upgrade1", "repository": "OPNsense", "current_version": "1.0", "new_version": "2.0"},
				{"name": "pkg-upgrade2", "repository": "OPNsense", "current_version": "3.0", "new_version": "4.0"}
			],
			"product": {
				"product_check": {
					"upgrade_needs_reboot": "1"
				}
			},
			"status": "ok"
		}`))
	})
	defer server.Close()

	firmware, err := client.FetchFirmwareStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if firmware.OsVersion != "24.1" {
		t.Errorf("expected OsVersion '24.1', got %q", firmware.OsVersion)
	}
	if firmware.ProductId != "opnsense" {
		t.Errorf("expected ProductId 'opnsense', got %q", firmware.ProductId)
	}
	if firmware.ProductVersion != "24.1.1" {
		t.Errorf("expected ProductVersion '24.1.1', got %q", firmware.ProductVersion)
	}
	if firmware.ProductABI != "24.1:amd64" {
		t.Errorf("expected ProductABI '24.1:amd64', got %q", firmware.ProductABI)
	}
	if firmware.NeedsReboot != true {
		t.Errorf("expected NeedsReboot true, got %v", firmware.NeedsReboot)
	}
	if firmware.UpgradeNeedsReboot != true {
		t.Errorf("expected UpgradeNeedsReboot true, got %v", firmware.UpgradeNeedsReboot)
	}
	if firmware.NewPackages != 1 {
		t.Errorf("expected NewPackages=1, got %d", firmware.NewPackages)
	}
	if firmware.UpgradePackages != 2 {
		t.Errorf("expected UpgradePackages=2, got %d", firmware.UpgradePackages)
	}
	// "2024-01-15T10:30:00" parsed as UTC = 1705314600
	expectedTimestamp := float64(1705314600)
	if firmware.LastCheckTimestamp != expectedTimestamp {
		t.Errorf("expected LastCheckTimestamp %v, got %v", expectedTimestamp, firmware.LastCheckTimestamp)
	}
}

func TestFetchFirmwareStatus_StatusNone(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "none",
			"os_version": "24.1",
			"product_id": "opnsense",
			"product_version": "24.1.1"
		}`))
	})
	defer server.Close()

	firmware, err := client.FetchFirmwareStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// #640: identity is now resolved unconditionally (top-level-wins-else-
	// nested), independent of LastCheck, so a top-level product_id present here
	// populates even though status=none carries no last_check. os_version has
	// no equivalent unconditional source on this endpoint, so it stays at the
	// NewFirmwareStatus() default (no seam wired in this test).
	if firmware.OsVersion != "undefined" {
		t.Errorf("expected OsVersion 'undefined' for status=none, got %q", firmware.OsVersion)
	}
	if firmware.ProductId != "opnsense" {
		t.Errorf("expected ProductId 'opnsense' (#640: identity resolves regardless of check state), got %q", firmware.ProductId)
	}
	if firmware.NeedsReboot != false {
		t.Errorf("expected NeedsReboot false for status=none, got %v", firmware.NeedsReboot)
	}
	if firmware.UpgradeNeedsReboot != false {
		t.Errorf("expected UpgradeNeedsReboot false for status=none, got %v", firmware.UpgradeNeedsReboot)
	}
	if firmware.LastCheckTimestamp != 0 {
		t.Errorf("expected LastCheckTimestamp 0 for status=none, got %v", firmware.LastCheckTimestamp)
	}
	if firmware.NewPackages != 0 {
		t.Errorf("expected NewPackages=0, got %d", firmware.NewPackages)
	}
	if firmware.UpgradePackages != 0 {
		t.Errorf("expected UpgradePackages=0, got %d", firmware.UpgradePackages)
	}
}

func TestFetchFirmwareStatus_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchFirmwareStatus()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestNewFirmwareStatus(t *testing.T) {
	fs := NewFirmwareStatus()

	if fs.LastCheck != "undefined" {
		t.Errorf("expected LastCheck 'undefined', got %q", fs.LastCheck)
	}
	if fs.NeedsReboot != false {
		t.Errorf("expected NeedsReboot false, got %v", fs.NeedsReboot)
	}
	if fs.OsVersion != "undefined" {
		t.Errorf("expected OsVersion 'undefined', got %q", fs.OsVersion)
	}
	if fs.ProductABI != "undefined" {
		t.Errorf("expected ProductABI 'undefined', got %q", fs.ProductABI)
	}
	if fs.ProductId != "undefined" {
		t.Errorf("expected ProductId 'undefined', got %q", fs.ProductId)
	}
	if fs.ProductVersion != "undefined" {
		t.Errorf("expected ProductVersion 'undefined', got %q", fs.ProductVersion)
	}
	if fs.UpgradeNeedsReboot != false {
		t.Errorf("expected UpgradeNeedsReboot false, got %v", fs.UpgradeNeedsReboot)
	}
	if fs.NewPackages != 0 {
		t.Errorf("expected NewPackages=0, got %d", fs.NewPackages)
	}
	if fs.UpgradePackages != 0 {
		t.Errorf("expected UpgradePackages=0, got %d", fs.UpgradePackages)
	}
	if fs.LastCheckTimestamp != 0 {
		t.Errorf("expected LastCheckTimestamp=0, got %v", fs.LastCheckTimestamp)
	}
	// #373/#380: the update-check fields must stay zero-valued in the default,
	// so a box that has never run a check emits no check-health series at all.
	if fs.CheckPresent {
		t.Errorf("expected CheckPresent=false, got %v", fs.CheckPresent)
	}
	if fs.Connection != "" || fs.Repository != "" {
		t.Errorf("expected empty Connection/Repository, got %q/%q", fs.Connection, fs.Repository)
	}
	if fs.RemovePackages != 0 || fs.UpgradeSets != 0 {
		t.Errorf("expected zero RemovePackages/UpgradeSets, got %d/%d", fs.RemovePackages, fs.UpgradeSets)
	}
	if fs.PendingDownloadBytes != 0 || fs.PendingDownloadBytesValid {
		t.Errorf("expected zero/invalid pending download bytes, got %v/%v", fs.PendingDownloadBytes, fs.PendingDownloadBytesValid)
	}
}

func TestParseLastCheckTimestamp(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected float64
	}{
		{"RFC3339 with Z", "2024-01-15T10:30:00Z", 1705314600},
		{"No timezone", "2024-01-15T10:30:00", 1705314600},
		{"Undefined", "undefined", 0},
		{"Empty string", "", 0},
		{"Garbage", "garbage", 0},
		{"UnixDate BST", "Tue Jun  9 10:13:17 BST 2026", 1780999997},
		{"UnixDate UTC", "Tue Jun  9 10:13:17 UTC 2026", 1780999997},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseLastCheckTimestamp(tc.input)
			if got != tc.expected {
				t.Errorf("parseLastCheckTimestamp(%q) = %v; want %v", tc.input, got, tc.expected)
			}
		})
	}
}

func TestFetchFirmwareStatus_UpgradePackageDetails(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"last_check": "2026-06-09T10:13:17",
			"needs_reboot": "0",
			"os_version": "FreeBSD 14.3-RELEASE-p14",
			"product_id": "opnsense",
			"product_version": "26.1.9",
			"product_abi": "26.1",
			"new_packages": [],
			"upgrade_packages": [
				{"name": "curl", "repository": "OPNsense", "current_version": "8.8.0", "new_version": "8.9.1"},
				{"name": "openssl", "repository": "OPNsense", "current_version": "3.0.13", "new_version": "3.0.14"}
			],
			"product": {
				"product_check": {
					"upgrade_needs_reboot": "0"
				}
			}
		}`))
	})
	defer server.Close()

	firmware, err := client.FetchFirmwareStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(firmware.UpgradePackageDetails) != 2 {
		t.Fatalf("expected 2 upgrade package details, got %d", len(firmware.UpgradePackageDetails))
	}
	first := firmware.UpgradePackageDetails[0]
	if first.Name != "curl" || first.CurrentVersion != "8.8.0" || first.NewVersion != "8.9.1" {
		t.Errorf("unexpected first upgrade detail: %+v", first)
	}
}

// TestFetchFirmwareStatus_DowngradeReinstallPackages covers #237: the
// downgrade_packages/reinstall_packages arrays (state-dependent superset,
// present alongside new_packages/upgrade_packages once a firmware check has
// run) are counted the same way as the existing package-count fields.
func TestFetchFirmwareStatus_DowngradeReinstallPackages(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"last_check": "2026-06-09T10:13:17",
			"needs_reboot": "0",
			"os_version": "26.7",
			"product_id": "opnsense",
			"product_version": "26.7",
			"product_abi": "26.7",
			"new_packages": [],
			"upgrade_packages": [],
			"downgrade_packages": [
				{"name": "pkgA", "repository": "OPNsense", "current_version": "2.0", "new_version": "1.0"}
			],
			"reinstall_packages": [
				{"name": "pkgB", "repository": "OPNsense", "version": "1.0"},
				{"name": "pkgC", "repository": "OPNsense", "version": "2.0"}
			],
			"product": {
				"product_check": {
					"upgrade_needs_reboot": "0"
				}
			}
		}`))
	})
	defer server.Close()

	firmware, err := client.FetchFirmwareStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if firmware.DowngradePackages != 1 {
		t.Errorf("expected DowngradePackages=1, got %d", firmware.DowngradePackages)
	}
	if firmware.ReinstallPackages != 2 {
		t.Errorf("expected ReinstallPackages=2, got %d", firmware.ReinstallPackages)
	}
}

// TestFetchFirmwareStatus_DowngradeReinstallAbsent covers the common case (no
// firmware check has surfaced downgrade/reinstall candidates): both counts
// must read 0, not error.
func TestFetchFirmwareStatus_DowngradeReinstallAbsent(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"last_check": "2026-06-09T10:13:17",
			"needs_reboot": "0",
			"os_version": "26.1",
			"product_id": "opnsense",
			"product_version": "26.1.9",
			"product_abi": "26.1",
			"new_packages": [],
			"upgrade_packages": [],
			"product": {
				"product_check": {
					"upgrade_needs_reboot": "0"
				}
			}
		}`))
	})
	defer server.Close()

	firmware, err := client.FetchFirmwareStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if firmware.DowngradePackages != 0 || firmware.ReinstallPackages != 0 {
		t.Errorf("expected zero downgrade/reinstall counts, got %d/%d", firmware.DowngradePackages, firmware.ReinstallPackages)
	}
}

// TestFetchFirmwareStatus_UpdateCheckHealth covers #373: the stored check's own
// verdict. Upstream writes last_check BEFORE it attempts the package operation
// and then persists fixed connection/repository state strings even on failure,
// so a non-empty last_check alone does not mean the check succeeded.
func TestFetchFirmwareStatus_UpdateCheckHealth(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		wantPresent    bool
		wantConnection string
		wantRepository string
	}{
		{
			name: "successful stored check",
			body: `{
				"last_check": "2026-07-25T10:00:00",
				"connection": "ok",
				"repository": "ok",
				"status": "update"
			}`,
			wantPresent:    true,
			wantConnection: "ok",
			wantRepository: "ok",
		},
		{
			name: "connection failure",
			body: `{
				"last_check": "2026-07-25T10:00:00",
				"connection": "unresolved",
				"repository": "ok",
				"status": "error",
				"status_msg": "Cannot resolve host mirror.example.invalid"
			}`,
			wantPresent:    true,
			wantConnection: "unresolved",
			wantRepository: "ok",
		},
		{
			name: "repository failure",
			body: `{
				"last_check": "2026-07-25T10:00:00",
				"connection": "ok",
				"repository": "revoked",
				"status": "error"
			}`,
			wantPresent:    true,
			wantConnection: "ok",
			wantRepository: "revoked",
		},
		{
			name: "connection error state",
			body: `{
				"last_check": "2026-07-25T10:00:00",
				"connection": "error",
				"repository": "error"
			}`,
			wantPresent:    true,
			wantConnection: "error",
			wantRepository: "error",
		},
		{
			name: "unknown future states collapse",
			body: `{
				"last_check": "2026-07-25T10:00:00",
				"connection": "quantum-entangled",
				"repository": "https://pkg.opnsense.org/FreeBSD:14:amd64/26.7"
			}`,
			wantPresent:    true,
			wantConnection: "unknown",
			wantRepository: "unknown",
		},
		{
			name: "stored check without state fields",
			body: `{
				"last_check": "2026-07-25T10:00:00"
			}`,
			wantPresent:    true,
			wantConnection: "unknown",
			wantRepository: "unknown",
		},
		{
			name:           "minimal pre-check envelope",
			body:           `{"status": "none"}`,
			wantPresent:    false,
			wantConnection: "",
			wantRepository: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.body))
			})
			defer server.Close()

			firmware, err := client.FetchFirmwareStatus()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if firmware.CheckPresent != tc.wantPresent {
				t.Errorf("CheckPresent = %v, want %v", firmware.CheckPresent, tc.wantPresent)
			}
			if firmware.Connection != tc.wantConnection {
				t.Errorf("Connection = %q, want %q", firmware.Connection, tc.wantConnection)
			}
			if firmware.Repository != tc.wantRepository {
				t.Errorf("Repository = %q, want %q", firmware.Repository, tc.wantRepository)
			}
		})
	}
}

// TestCanonicalizeFirmwareCheckState pins the two CLOSED state vocabularies from
// the header comment of the installed 26.7
// /usr/local/opnsense/scripts/firmware/check.sh (lines 30-31). Note that the
// upstream lists include "error", which #373's body omitted.
func TestCanonicalizeFirmwareCheckState(t *testing.T) {
	connection := []string{"error", "unauthenticated", "misconfigured", "unresolved", "ok"}
	repository := []string{"error", "untrusted", "unsigned", "revoked", "incomplete", "forbidden", "ok"}

	for _, s := range connection {
		if got := canonicalizeConnectionState(s); got != s {
			t.Errorf("canonicalizeConnectionState(%q) = %q, want %q", s, got, s)
		}
		if got := canonicalizeConnectionState(strings.ToUpper(s)); got != s {
			t.Errorf("canonicalizeConnectionState(%q) = %q, want %q (case-insensitive)", strings.ToUpper(s), got, s)
		}
	}
	for _, s := range repository {
		if got := canonicalizeRepositoryState(s); got != s {
			t.Errorf("canonicalizeRepositoryState(%q) = %q, want %q", s, got, s)
		}
	}
	// Cross-vocabulary leakage: a repository-only state is not a connection state.
	if got := canonicalizeConnectionState("revoked"); got != "unknown" {
		t.Errorf("canonicalizeConnectionState(%q) = %q, want unknown", "revoked", got)
	}
	if got := canonicalizeRepositoryState("unresolved"); got != "unknown" {
		t.Errorf("canonicalizeRepositoryState(%q) = %q, want unknown", "unresolved", got)
	}
	for _, s := range []string{"", "  ", "future-state", "Cannot resolve host"} {
		if got := canonicalizeConnectionState(s); got != "unknown" {
			t.Errorf("canonicalizeConnectionState(%q) = %q, want unknown", s, got)
		}
		if got := canonicalizeRepositoryState(s); got != "unknown" {
			t.Errorf("canonicalizeRepositoryState(%q) = %q, want unknown", s, got)
		}
	}
}

// TestFetchFirmwareStatus_RemoveUpgradeSetsCounts covers the two count gauges
// #373 adds. Both arrays were EMPTY on the 26.7.r_35 dev box, so their inner
// shapes are derived from the installed check.sh (remove_packages at lines
// 256/262, upgrade_sets at 374/385/397) rather than from a live capture.
func TestFetchFirmwareStatus_RemoveUpgradeSetsCounts(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"last_check": "2026-07-25T10:00:00",
			"connection": "ok",
			"repository": "ok",
			"remove_packages": [
				{"name": "pkg-gone", "repository": "OPNsense", "version": "1.0"}
			],
			"upgrade_sets": [
				{"name": "base", "size": "180MiB", "current_version": "26.1.11", "new_version": "26.7", "repository": "OPNsense"},
				{"name": "kernel", "size": "40MiB", "current_version": "26.1.11", "new_version": "26.7", "repository": "OPNsense"}
			]
		}`))
	})
	defer server.Close()

	firmware, err := client.FetchFirmwareStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if firmware.RemovePackages != 1 {
		t.Errorf("expected RemovePackages=1, got %d", firmware.RemovePackages)
	}
	if firmware.UpgradeSets != 2 {
		t.Errorf("expected UpgradeSets=2, got %d", firmware.UpgradeSets)
	}
}

// TestFetchFirmwareStatus_RemoveUpgradeSetsAbsent is the live dev-box shape:
// both arrays empty/absent, so both counts read 0 without error.
func TestFetchFirmwareStatus_RemoveUpgradeSetsAbsent(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"last_check": "2026-07-25T10:00:00",
			"connection": "ok",
			"repository": "ok",
			"remove_packages": [],
			"upgrade_packages": []
		}`))
	})
	defer server.Close()

	firmware, err := client.FetchFirmwareStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if firmware.RemovePackages != 0 || firmware.UpgradeSets != 0 {
		t.Errorf("expected zero remove/upgrade-set counts, got %d/%d", firmware.RemovePackages, firmware.UpgradeSets)
	}
}

// TestFetchFirmwareStatus_AllPackagesNotDecoded guards the #373 acceptance
// criterion that the composite inventories are NOT turned into per-package data:
// all_packages/all_sets are upstream's own recombination of the five action
// arrays, so decoding them would duplicate every entry.
func TestFetchFirmwareStatus_AllPackagesNotDecoded(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"last_check": "2026-07-25T10:00:00",
			"connection": "ok",
			"repository": "ok",
			"upgrade_packages": [
				{"name": "curl", "repository": "OPNsense", "current_version": "8.8.0", "new_version": "8.9.1"}
			],
			"all_packages": [
				{"name": "curl", "repository": "OPNsense", "current_version": "8.8.0", "new_version": "8.9.1", "action": "upgrade"},
				{"name": "openssl", "repository": "OPNsense", "current_version": "3.0.13", "new_version": "3.0.14", "action": "upgrade"}
			],
			"all_sets": [
				{"name": "base", "current_version": "26.1.11", "new_version": "26.7", "action": "upgrade"}
			]
		}`))
	})
	defer server.Close()

	firmware, err := client.FetchFirmwareStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(firmware.UpgradePackageDetails) != 1 {
		t.Fatalf("all_packages must not contribute package details: got %d, want 1 (from upgrade_packages only)",
			len(firmware.UpgradePackageDetails))
	}
	if firmware.UpgradePackages != 1 {
		t.Errorf("expected UpgradePackages=1 (upgrade_packages only), got %d", firmware.UpgradePackages)
	}
	if firmware.UpgradeSets != 0 {
		t.Errorf("all_sets must not be counted as upgrade_sets: got %d", firmware.UpgradeSets)
	}
}

// TestParseFirmwareDownloadSize covers #380. The wire field is a
// comma-separated list of mixed-unit sizes; the unit is the first alphabetic
// character after the number (base-2). Upstream's own regex is (\d+) and
// therefore truncates a fractional size; we deliberately accept the decimal.
func TestParseFirmwareDownloadSize(t *testing.T) {
	const (
		ki = 1024.0
		mi = ki * 1024
		gi = mi * 1024
		ti = gi * 1024
		pi = ti * 1024
	)
	tests := []struct {
		name      string
		raw       string
		want      float64
		wantValid bool
	}{
		{"empty means nothing to download", "", 0, true},
		{"whitespace only", "   ", 0, true},
		{"explicit zero", "0", 0, true},
		{"bare bytes", "512", 512, true},
		{"byte unit letter", "512B", 512, true},
		{"kibibytes", "4KiB", 4 * ki, true},
		{"kibibytes lowercase", "4kb", 4 * ki, true},
		{"mebibytes live dev-box value", "37MiB", 37 * mi, true},
		{"gibibytes", "2GiB", 2 * gi, true},
		{"tebibytes", "3TiB", 3 * ti, true},
		{"pebibytes", "1PiB", 1 * pi, true},
		{"decimal accepted, not truncated like upstream", "1.5GiB", 1.5 * gi, true},
		{"csv sum", "37MiB,4KiB", 37*mi + 4*ki, true},
		{"csv sum with spaces", " 180MiB , 40MiB , 512 ", 180*mi + 40*mi + 512, true},
		{"space between number and unit", "37 MiB", 37 * mi, true},
		{"malformed emits nothing", "garbage", 0, false},
		{"unit without number", "MiB", 0, false},
		{"one bad csv item poisons the whole value", "37MiB,garbage", 0, false},
		{"unknown unit letter", "37XiB", 0, false},
		{"negative", "-5MiB", 0, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseFirmwareDownloadSize(tc.raw)
			if ok != tc.wantValid {
				t.Fatalf("parseFirmwareDownloadSize(%q) valid = %v, want %v", tc.raw, ok, tc.wantValid)
			}
			if ok && got != tc.want {
				t.Errorf("parseFirmwareDownloadSize(%q) = %v, want %v", tc.raw, got, tc.want)
			}
			if !ok && got != 0 {
				t.Errorf("parseFirmwareDownloadSize(%q) returned %v on failure, want 0", tc.raw, got)
			}
		})
	}
}

// TestFetchFirmwareStatus_PendingDownloadSizeGating covers #380's emission
// gating: nothing at all before a stored check exists, an unambiguous 0 when
// the field is empty/absent, and NO value (never a fabricated 0) when the
// field cannot be parsed.
func TestFetchFirmwareStatus_PendingDownloadSizeGating(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantValid bool
		wantBytes float64
	}{
		{
			name:      "no stored check",
			body:      `{"status": "none", "download_size": "37MiB"}`,
			wantValid: false,
		},
		{
			name:      "stored check, field absent",
			body:      `{"last_check": "2026-07-25T10:00:00", "connection": "ok", "repository": "ok"}`,
			wantValid: true,
			wantBytes: 0,
		},
		{
			name:      "stored check, field empty",
			body:      `{"last_check": "2026-07-25T10:00:00", "download_size": ""}`,
			wantValid: true,
			wantBytes: 0,
		},
		{
			name:      "stored check, live dev-box value",
			body:      `{"last_check": "2026-07-25T10:00:00", "download_size": "37MiB"}`,
			wantValid: true,
			wantBytes: 37 * 1024 * 1024,
		},
		{
			name:      "stored check, malformed value",
			body:      `{"last_check": "2026-07-25T10:00:00", "download_size": "quite big"}`,
			wantValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.body))
			})
			defer server.Close()

			firmware, err := client.FetchFirmwareStatus()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if firmware.PendingDownloadBytesValid != tc.wantValid {
				t.Fatalf("PendingDownloadBytesValid = %v, want %v", firmware.PendingDownloadBytesValid, tc.wantValid)
			}
			if firmware.PendingDownloadBytes != tc.wantBytes {
				t.Errorf("PendingDownloadBytes = %v, want %v", firmware.PendingDownloadBytes, tc.wantBytes)
			}
		})
	}
}

func TestFetchFirmwareInfo_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"product_id": "opnsense",
			"product_version": "26.1.9",
			"package": [
				{"name": "abseil", "version": "20250127.1_1", "installed": "0"},
				{"name": "curl", "version": "8.9.1", "installed": "1"}
			],
			"plugin": [
				{"name": "os-ddclient", "version": "1.31", "installed": "1"},
				{"name": "os-acme-client", "version": "4.10", "installed": "0"},
				{"name": "os-tailscale", "version": "1.10", "installed": "1"}
			]
		}`))
	})
	defer server.Close()

	info, err := client.FetchFirmwareInfo()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ProductID != "opnsense" {
		t.Errorf("expected ProductID 'opnsense', got %q", info.ProductID)
	}
	if info.ProductVersion != "26.1.9" {
		t.Errorf("expected ProductVersion '26.1.9', got %q", info.ProductVersion)
	}
	if len(info.InstalledPlugins) != 2 {
		t.Fatalf("expected 2 installed plugins (installed==\"1\" only), got %d", len(info.InstalledPlugins))
	}
	if info.InstalledPlugins[0].Name != "os-ddclient" || info.InstalledPlugins[0].Version != "1.31" {
		t.Errorf("unexpected first plugin: %+v", info.InstalledPlugins[0])
	}
	if info.InstalledPlugins[1].Name != "os-tailscale" {
		t.Errorf("expected second plugin os-tailscale, got %q", info.InstalledPlugins[1].Name)
	}
}

func TestFetchFirmwareInfo_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchFirmwareInfo()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

// OPNsense >= 25.x leaves status at "none" even when firmware data is valid;
// last_check is the validity signal (upstream PR #101). Verified live on
// 26.1.9: status "none" + last_check "Tue Jun  9 10:13:17 BST 2026".
func TestFetchFirmwareStatus_StatusNoneWithLastCheck(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "none",
			"last_check": "Tue Jun  9 10:13:17 BST 2026",
			"needs_reboot": "0",
			"os_version": "FreeBSD 14.3-RELEASE-p14",
			"product_id": "opnsense",
			"product_version": "26.1.9",
			"product_abi": "26.1",
			"new_packages": [],
			"upgrade_packages": [],
			"product": {
				"product_check": {
					"upgrade_needs_reboot": "0"
				}
			}
		}`))
	})
	defer server.Close()

	firmware, err := client.FetchFirmwareStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if firmware.OsVersion != "FreeBSD 14.3-RELEASE-p14" {
		t.Errorf("expected real OsVersion despite status=none, got %q", firmware.OsVersion)
	}
	if firmware.ProductVersion != "26.1.9" {
		t.Errorf("expected ProductVersion '26.1.9', got %q", firmware.ProductVersion)
	}
	// "Tue Jun  9 10:13:17 BST 2026" — parsed with ParseInLocation(..., UTC),
	// so the abbreviation gets offset 0 and the wall-clock time is treated as
	// UTC deterministically on every host: 1780999997.
	if firmware.LastCheckTimestamp != 1780999997 {
		t.Errorf("expected LastCheckTimestamp 1780999997, got %v", firmware.LastCheckTimestamp)
	}
}

// TestFetchFirmwareStatus_MajorUpgrade pins the #583 major-version-upgrade
// decode.
//
// Wire evidence: OPNsense core src/opnsense/scripts/firmware/check.sh
// (identical on stable/26.1 and stable/26.7) writes BOTH keys unconditionally
// into the stored check's JSON heredoc (lines 422-423), so within a stored
// check they are always present. `upgrade_major_version=$(opnsense-update -vR)`
// is assigned only inside `if [ -n "${packages_is_size}" ]` (line 366), so it
// is an EMPTY STRING when no major upgrade is offered and a version string
// ("26.7") when one is — emptiness IS the availability signal.
//
// `upgrade_needs_reboot` starts at "0" (line 68) and flips to "1" when a major
// upgrade's packages/kernel/base sets differ. FirmwareController.php:126-127
// does `$response = $product['product_check']; $response['product'] = $product;`
// so the top level and product.product_check are the SAME object; the exporter
// reads top-level first and falls back to the nested copy.
func TestFetchFirmwareStatus_MajorUpgrade(t *testing.T) {
	cases := []struct {
		name            string
		body            string
		wantAvailable   bool
		wantVersion     string
		wantNeedsReboot bool
	}{
		{
			name: "major upgrade offered",
			body: `{"last_check":"Tue Jun  9 10:13:17 UTC 2026",
			        "upgrade_major_version":"26.7","upgrade_needs_reboot":"1",
			        "product":{"product_check":{"upgrade_needs_reboot":"1"}}}`,
			wantAvailable:   true,
			wantVersion:     "26.7",
			wantNeedsReboot: true,
		},
		{
			name: "check stored, no major upgrade — empty string, not a missing key",
			body: `{"last_check":"Tue Jun  9 10:13:17 UTC 2026",
			        "upgrade_major_version":"","upgrade_needs_reboot":"0",
			        "product":{"product_check":{"upgrade_needs_reboot":"0"}}}`,
			wantAvailable:   false,
			wantVersion:     "",
			wantNeedsReboot: false,
		},
		{
			name: "top-level key absent — falls back to the nested product_check copy",
			body: `{"last_check":"Tue Jun  9 10:13:17 UTC 2026",
			        "product":{"product_check":{"upgrade_needs_reboot":"1"}}}`,
			wantAvailable:   false,
			wantVersion:     "",
			wantNeedsReboot: true,
		},
		{
			name:            "no stored check — nothing is claimed at all",
			body:            `{"status":"none","product":{"product_check":null}}`,
			wantAvailable:   false,
			wantVersion:     "",
			wantNeedsReboot: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.body))
			})
			defer server.Close()

			data, err := client.FetchFirmwareStatus()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if data.MajorUpgradeAvailable != tc.wantAvailable {
				t.Errorf("MajorUpgradeAvailable = %v, want %v", data.MajorUpgradeAvailable, tc.wantAvailable)
			}
			if data.MajorUpgradeVersion != tc.wantVersion {
				t.Errorf("MajorUpgradeVersion = %q, want %q", data.MajorUpgradeVersion, tc.wantVersion)
			}
			if data.UpgradeNeedsReboot != tc.wantNeedsReboot {
				t.Errorf("UpgradeNeedsReboot = %v, want %v", data.UpgradeNeedsReboot, tc.wantNeedsReboot)
			}
		})
	}
}

// TestFetchFirmwareInfo_PluginPolicyAndSize pins the #583 plugin decode, and
// with it two upstream traps the issue got wrong.
//
// TRAP 1 — flatsize is NOT bytes. scripts/firmware/query.sh:52 queries pkg with
// `%sh`, pkg's HUMANIZED size, and FirmwareController.php:854 then runs it
// through formatBytes(), which returns a non-numeric input unchanged. So the
// wire value is a formatted base-2 string ("168KiB", "1.2MiB").
//
// TRAP 2 — locked/automatic never arrive as "0". query.sh emits pkg's `%k`/`%a`
// as a bare 0 or 1, but FirmwareController.php:852-853 rewrites any value for
// which PHP's empty() is true, and empty("0") IS true. The string "0" is
// therefore replaced by gettext('N/A') before it reaches the wire.
func TestFetchFirmwareInfo_PluginPolicyAndSize(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"product_id": "OPNsense", "product_version": "26.7",
			"plugin": [
				{"name":"os-tailscale","version":"1.4","installed":"1",
				 "flatsize":"168KiB","locked":"1","automatic":"1"},
				{"name":"os-frr","version":"1.0","installed":"1",
				 "flatsize":"1.2MiB","locked":"N/A","automatic":"N/A"},
				{"name":"os-tiny","version":"0.1","installed":"1",
				 "flatsize":"512B","locked":"N/A","automatic":"N/A"},
				{"name":"os-nosize","version":"0.1","installed":"1",
				 "flatsize":"N/A","locked":"N/A","automatic":"N/A"},
				{"name":"os-notinstalled","version":"9.9","installed":"0",
				 "flatsize":"9MiB","locked":"1","automatic":"1"}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchFirmwareInfo()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.InstalledPlugins) != 4 {
		t.Fatalf("expected 4 installed plugins, got %d", len(data.InstalledPlugins))
	}

	want := []FirmwarePlugin{
		{Name: "os-tailscale", Version: "1.4", SizeBytes: 168 * 1024, HasSize: true, Locked: true, Automatic: true},
		{Name: "os-frr", Version: "1.0", SizeBytes: 1.2 * 1024 * 1024, HasSize: true},
		{Name: "os-tiny", Version: "0.1", SizeBytes: 512, HasSize: true},
		// "N/A" is unparseable, so no size is claimed at all — a 0 would show
		// up in a disk-attribution panel as a plugin that costs nothing.
		{Name: "os-nosize", Version: "0.1"},
	}
	for i, w := range want {
		got := data.InstalledPlugins[i]
		if got != w {
			t.Errorf("plugin[%d]: got %+v, want %+v", i, got, w)
		}
	}
}

// TestFetchFirmwareStatus_UncheckedBoxBareEnvelope covers #640: the bare
// three-key envelope observed live on a 26.7.1_1 box that has never run a
// firmware update check.
//
// This is a REAL CAPTURE, not a synthesized shape (CLAUDE.md's fixture rule):
// GET core/firmware/status on that box returned exactly product/status/
// status_msg at the top level -- no last_check, no top-level product_id/
// product_version/product_abi -- with the identity present unconditionally
// nested under product.*. product_series/product_arch are real fields on
// that payload too but are not consumed, matching the "not decoded" pattern
// used elsewhere in this file (all_packages/all_sets).
func TestFetchFirmwareStatus_UncheckedBoxBareEnvelope(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"product": {
				"product_id": "opnsense",
				"product_version": "26.7.1_1",
				"product_abi": "26.7",
				"product_series": "26.7",
				"product_arch": "amd64"
			},
			"status": "none",
			"status_msg": ""
		}`))
	})
	defer server.Close()

	firmware, err := client.FetchFirmwareStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if firmware.ProductId != "opnsense" {
		t.Errorf("expected ProductId 'opnsense', got %q", firmware.ProductId)
	}
	if firmware.ProductVersion != "26.7.1_1" {
		t.Errorf("expected ProductVersion '26.7.1_1', got %q", firmware.ProductVersion)
	}
	if firmware.ProductABI != "26.7" {
		t.Errorf("expected ProductABI '26.7', got %q", firmware.ProductABI)
	}

	// os_version is not recoverable from this endpoint before a check has run
	// (#640), and no result seam is wired in this test, so it stays at the
	// NewFirmwareStatus() default.
	if firmware.OsVersion != "undefined" {
		t.Errorf("expected OsVersion 'undefined' (no seam wired), got %q", firmware.OsVersion)
	}

	// Genuinely check-dependent fields must stay at their zero/false/absent
	// defaults -- no check has run, so there is genuinely no answer, and
	// fabricating one would be worse than "undefined".
	if firmware.CheckPresent {
		t.Errorf("expected CheckPresent=false, got %v", firmware.CheckPresent)
	}
	if firmware.LastCheckTimestamp != 0 {
		t.Errorf("expected LastCheckTimestamp=0, got %v", firmware.LastCheckTimestamp)
	}
	if firmware.NewPackages != 0 || firmware.UpgradePackages != 0 {
		t.Errorf("expected zero package counts, got new=%d upgrade=%d", firmware.NewPackages, firmware.UpgradePackages)
	}
	if firmware.DowngradePackages != 0 || firmware.ReinstallPackages != 0 {
		t.Errorf("expected zero downgrade/reinstall counts, got %d/%d", firmware.DowngradePackages, firmware.ReinstallPackages)
	}
	if firmware.RemovePackages != 0 || firmware.UpgradeSets != 0 {
		t.Errorf("expected zero remove/upgrade-set counts, got %d/%d", firmware.RemovePackages, firmware.UpgradeSets)
	}
}

// TestFetchFirmwareStatus_IdentityTopLevelWinsOverNested is the main
// regression guard for #640: when BOTH a legacy top-level copy and the
// nested product.* copy are present with DIFFERENT values, top-level must
// win -- this is what keeps a checked box's existing behaviour completely
// unchanged by the fix.
func TestFetchFirmwareStatus_IdentityTopLevelWinsOverNested(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"last_check": "2026-07-25T10:00:00",
			"product_id": "top-level-id",
			"product_version": "top-level-version",
			"product_abi": "top-level-abi",
			"product": {
				"product_id": "nested-id",
				"product_version": "nested-version",
				"product_abi": "nested-abi"
			}
		}`))
	})
	defer server.Close()

	firmware, err := client.FetchFirmwareStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if firmware.ProductId != "top-level-id" {
		t.Errorf("expected top-level ProductId to win, got %q", firmware.ProductId)
	}
	if firmware.ProductVersion != "top-level-version" {
		t.Errorf("expected top-level ProductVersion to win, got %q", firmware.ProductVersion)
	}
	if firmware.ProductABI != "top-level-abi" {
		t.Errorf("expected top-level ProductABI to win, got %q", firmware.ProductABI)
	}
}

// TestFetchFirmwareStatus_IdentityFallsBackToNested is the flip side: with no
// top-level copy at all, the nested product.* copy is used.
func TestFetchFirmwareStatus_IdentityFallsBackToNested(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"product": {
				"product_id": "nested-id",
				"product_version": "nested-version",
				"product_abi": "nested-abi"
			},
			"status": "none"
		}`))
	})
	defer server.Close()

	firmware, err := client.FetchFirmwareStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if firmware.ProductId != "nested-id" {
		t.Errorf("expected nested ProductId fallback, got %q", firmware.ProductId)
	}
	if firmware.ProductVersion != "nested-version" {
		t.Errorf("expected nested ProductVersion fallback, got %q", firmware.ProductVersion)
	}
	if firmware.ProductABI != "nested-abi" {
		t.Errorf("expected nested ProductABI fallback, got %q", firmware.ProductABI)
	}
}

// TestFetchFirmwareStatus_OsVersionFromSeam covers #640/#571: on an unchecked
// box (no answer of its own), os_version is filled in from the shared result
// seam's most recent systemInformation snapshot instead of a duplicate
// request to the box.
func TestFetchFirmwareStatus_OsVersionFromSeam(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"product": {"product_id": "opnsense"}, "status": "none"}`))
	})
	defer server.Close()

	seam := fetchshare.New()
	client.SetResultSeam(seam)
	seam.Publish(fetchshare.KeySystemInformation, &SystemInfo{FreeBSDVersion: "15.1-RELEASE-p1"})

	firmware, err := client.FetchFirmwareStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if firmware.OsVersion != "15.1-RELEASE-p1" {
		t.Errorf("expected OsVersion from the seam, got %q", firmware.OsVersion)
	}
}

// TestFetchFirmwareStatus_OsVersionSeamMiss covers the degrade-gracefully
// half of #640: no seam wired at all, and a seam wired but with nothing
// published under the key, both fall back to the "undefined" default rather
// than erroring or fabricating a value.
func TestFetchFirmwareStatus_OsVersionSeamMiss(t *testing.T) {
	const body = `{"product": {"product_id": "opnsense"}, "status": "none"}`

	t.Run("no seam wired", func(t *testing.T) {
		server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(body))
		})
		defer server.Close()

		firmware, err := client.FetchFirmwareStatus()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if firmware.OsVersion != "undefined" {
			t.Errorf("expected OsVersion 'undefined', got %q", firmware.OsVersion)
		}
	})

	t.Run("seam wired but empty", func(t *testing.T) {
		server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(body))
		})
		defer server.Close()

		client.SetResultSeam(fetchshare.New())

		firmware, err := client.FetchFirmwareStatus()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if firmware.OsVersion != "undefined" {
			t.Errorf("expected OsVersion 'undefined', got %q", firmware.OsVersion)
		}
	})
}

// TestFetchFirmwareStatus_OsVersionSeamDoesNotOverrideCheckedBox is a
// regression guard: even with a fresh seam value available, a checked box's
// own (legacy, gated) os_version must win. The seam is a fallback for when
// this endpoint has no answer of its own, never an override of one it does
// have.
func TestFetchFirmwareStatus_OsVersionSeamDoesNotOverrideCheckedBox(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"last_check": "2026-07-25T10:00:00",
			"os_version": "FreeBSD 14.3-RELEASE-p14",
			"product_id": "opnsense"
		}`))
	})
	defer server.Close()

	seam := fetchshare.New()
	client.SetResultSeam(seam)
	seam.Publish(fetchshare.KeySystemInformation, &SystemInfo{FreeBSDVersion: "15.1-RELEASE-p1"})

	firmware, err := client.FetchFirmwareStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if firmware.OsVersion != "FreeBSD 14.3-RELEASE-p14" {
		t.Errorf("expected the endpoint's own os_version to win over the seam, got %q", firmware.OsVersion)
	}
}
