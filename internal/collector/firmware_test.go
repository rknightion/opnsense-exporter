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

	// 9 firmware metrics: needsReboot, newPackages, lastCheck, osVersion, productAbi, productId, productVersion, upgradePackages, upgradeNeedsReboot
	expectedCount := 9
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
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

	// Even with status "none", all 9 metrics are emitted (with default values)
	expectedCount := 9
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestFirmwareCollector_Name(t *testing.T) {
	c := &firmwareCollector{subsystem: FirmwareSubsystem}
	if c.Name() != FirmwareSubsystem {
		t.Errorf("expected %s, got %s", FirmwareSubsystem, c.Name())
	}
}
