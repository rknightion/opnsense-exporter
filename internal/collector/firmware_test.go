package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

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

	expectedCount := 6
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

	expectedCount := 6
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

	expectedCount := 6
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

	// 6 base metrics + 1 package_update_available + 1 plugin_installed = 8
	expectedCount := 8
	if len(metrics) != expectedCount {
		t.Fatalf("expected %d metrics with details enabled, got %d", expectedCount, len(metrics))
	}

	// metrics[6] = package_update_available for curl
	pkgLabels := getMetricLabels(metrics[6])
	if pkgLabels["name"] != "curl" || pkgLabels["installed_version"] != "8.8.0" || pkgLabels["new_version"] != "8.9.1" {
		t.Errorf("unexpected package_update_available labels: %v", pkgLabels)
	}
	if v := getMetricValue(metrics[6]); v != 1 {
		t.Errorf("expected package_update_available=1, got %v", v)
	}

	// metrics[7] = plugin_installed for os-ddclient (os-acme-client is not installed)
	plgLabels := getMetricLabels(metrics[7])
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

	expectedCount := 6
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics with details disabled, got %d", expectedCount, len(metrics))
	}
}
