package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

func dhcpv4TestMux(t *testing.T, response string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/dhcpv4/leases/searchLease", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(response))
	})
	return mux
}

func TestDhcpv4Collector_Update_NoDetails(t *testing.T) {
	response := `{
		"total": 3,
		"rowCount": 3,
		"current": 1,
		"rows": [
			{
				"address": "192.168.1.10",
				"mac": "00:11:22:33:44:55",
				"type": "static",
				"state": "active",
				"status": "online",
				"hostname": "desktop",
				"descr": "Main PC",
				"starts": "",
				"ends": "",
				"if": "em0",
				"if_descr": "LAN",
				"man": ""
			},
			{
				"address": "192.168.1.20",
				"mac": "AA:BB:CC:DD:EE:FF",
				"type": "dynamic",
				"state": "active",
				"status": "online",
				"hostname": "phone",
				"descr": "",
				"starts": "2024/01/01 10:00:00",
				"ends": "2024/01/01 22:00:00",
				"if": "em0",
				"if_descr": "LAN",
				"man": ""
			},
			{
				"address": "10.0.0.10",
				"mac": "11:22:33:44:55:66",
				"type": "dynamic",
				"state": "active",
				"status": "offline",
				"hostname": "iot-device",
				"descr": "",
				"starts": "2024/01/01 08:00:00",
				"ends": "2024/01/01 20:00:00",
				"if": "em1",
				"if_descr": "IOT",
				"man": ""
			}
		],
		"interfaces": {"em0": "LAN", "em1": "IOT"}
	}`

	mux := dhcpv4TestMux(t, response)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &dhcpv4Collector{subsystem: Dhcpv4Subsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	// detailsEnabled is false by default

	metrics := collectMetrics(t, c, client)

	// 1 leasesTotal + 1 reservedTotal + 1 dynamicTotal + 2 leasesByIface (LAN, IOT) = 5
	expectedCount := 5
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Verify metric values
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		value := getMetricValue(m)

		if strings.Contains(desc, "leases_total") && labels["opnsense_instance"] == "test" {
			if value != 3 {
				t.Errorf("expected leases_total=3, got %v", value)
			}
		}
		if strings.Contains(desc, "leases_reserved_total") && labels["opnsense_instance"] == "test" {
			if value != 1 {
				t.Errorf("expected leases_reserved_total=1, got %v", value)
			}
		}
		if strings.Contains(desc, "leases_dynamic_total") && labels["opnsense_instance"] == "test" {
			if value != 2 {
				t.Errorf("expected leases_dynamic_total=2, got %v", value)
			}
		}
	}
}

func TestDhcpv4Collector_Update_WithDetails(t *testing.T) {
	response := `{
		"total": 2,
		"rowCount": 2,
		"current": 1,
		"rows": [
			{
				"address": "192.168.1.10",
				"mac": "00:11:22:33:44:55",
				"type": "static",
				"state": "active",
				"status": "online",
				"hostname": "desktop",
				"descr": "Main PC",
				"starts": "",
				"ends": "",
				"if": "em0",
				"if_descr": "LAN",
				"man": ""
			},
			{
				"address": "192.168.1.20",
				"mac": "AA:BB:CC:DD:EE:FF",
				"type": "dynamic",
				"state": "active",
				"status": "online",
				"hostname": "phone",
				"descr": "",
				"starts": "2024/01/01 10:00:00",
				"ends": "2024/01/01 22:00:00",
				"if": "em0",
				"if_descr": "LAN",
				"man": ""
			}
		],
		"interfaces": {"em0": "LAN"}
	}`

	mux := dhcpv4TestMux(t, response)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &dhcpv4Collector{subsystem: Dhcpv4Subsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)

	// 1 leasesTotal + 1 reservedTotal + 1 dynamicTotal + 1 leasesByIface (LAN) + 2 leaseInfo = 6
	expectedCount := 6
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Verify a detail metric exists with correct labels
	foundDetail := false
	for _, m := range metrics {
		labels := getMetricLabels(m)
		if labels["address"] == "192.168.1.10" && labels["hostname"] == "desktop" {
			foundDetail = true
			if labels["mac"] != "00:11:22:33:44:55" {
				t.Errorf("expected mac '00:11:22:33:44:55', got %q", labels["mac"])
			}
			if labels["interface"] != "LAN" {
				t.Errorf("expected interface 'LAN', got %q", labels["interface"])
			}
			if labels["device"] != "em0" {
				t.Errorf("expected device 'em0', got %q", labels["device"])
			}
			if labels["type"] != "static" {
				t.Errorf("expected type 'static', got %q", labels["type"])
			}
			if labels["state"] != "active" {
				t.Errorf("expected state 'active', got %q", labels["state"])
			}
			if labels["status"] != "online" {
				t.Errorf("expected status 'online', got %q", labels["status"])
			}
			value := getMetricValue(m)
			if value != 1 {
				t.Errorf("expected lease_info value=1, got %v", value)
			}
		}
	}
	if !foundDetail {
		t.Error("expected to find detail metric for address 192.168.1.10")
	}
}

func TestDhcpv4Collector_Update_Empty(t *testing.T) {
	response := `{
		"total": 0,
		"rowCount": 0,
		"current": 1,
		"rows": [],
		"interfaces": {}
	}`

	mux := dhcpv4TestMux(t, response)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &dhcpv4Collector{subsystem: Dhcpv4Subsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 1 leasesTotal + 1 reservedTotal + 1 dynamicTotal = 3 (no leasesByIface)
	expectedCount := 3
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	for _, m := range metrics {
		value := getMetricValue(m)
		if value != 0 {
			t.Errorf("expected metric value 0, got %v", value)
		}
	}
}

func TestDhcpv4Collector_Update_ArrayQuirks(t *testing.T) {
	// OPNsense PHP may serialize empty fields as [] (API model drift).
	// The collector must handle this without errors.
	response := `{
		"total": 1,
		"rowCount": 1,
		"current": 1,
		"rows": [
			{
				"address": "192.168.1.10",
				"mac": [],
				"type": "static",
				"state": [],
				"status": [],
				"hostname": [],
				"descr": [],
				"starts": [],
				"ends": [],
				"if": [],
				"if_descr": "LAN",
				"man": []
			}
		],
		"interfaces": []
	}`

	mux := dhcpv4TestMux(t, response)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &dhcpv4Collector{subsystem: Dhcpv4Subsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 1 leasesTotal + 1 reservedTotal + 1 dynamicTotal + 1 leasesByIface (LAN) = 4
	expectedCount := 4
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

// TestDhcpv4Collector_Update_PluginAbsent guards #87: when the ISC DHCPv4 plugin
// is absent (endpoint 404s) the collector must stay completely silent, not emit
// leases_total=0 which is indistinguishable from a present-but-empty server.
func TestDhcpv4Collector_Update_PluginAbsent(t *testing.T) {
	mux := http.NewServeMux() // no handlers: all requests 404 → plugin absent
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &dhcpv4Collector{subsystem: Dhcpv4Subsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when plugin absent (404), got %d", len(metrics))
	}
}

func TestDhcpv4Collector_Name(t *testing.T) {
	c := &dhcpv4Collector{subsystem: Dhcpv4Subsystem}
	if c.Name() != Dhcpv4Subsystem {
		t.Errorf("expected %s, got %s", Dhcpv4Subsystem, c.Name())
	}
}
