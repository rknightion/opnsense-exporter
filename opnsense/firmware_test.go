package opnsense

import (
	"net/http"
	"testing"
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

	// When status is "none", defaults from NewFirmwareStatus() should remain
	if firmware.OsVersion != "undefined" {
		t.Errorf("expected OsVersion 'undefined' for status=none, got %q", firmware.OsVersion)
	}
	if firmware.ProductId != "undefined" {
		t.Errorf("expected ProductId 'undefined' for status=none, got %q", firmware.ProductId)
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
