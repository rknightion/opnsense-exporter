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
