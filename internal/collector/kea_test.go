package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

func keaTestMux(t *testing.T, v4Response, v6Response string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/kea/leases4/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(v4Response))
	})
	mux.HandleFunc("/api/kea/leases6/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(v6Response))
	})
	return mux
}

func TestKeaCollector_Update(t *testing.T) {
	v4Response := `{
		"total": 2,
		"rowCount": 2,
		"current": 1,
		"rows": [
			{
				"address": "192.168.1.10",
				"hwaddr": "00:11:22:33:44:55",
				"hostname": "desktop",
				"expire": 1772401000,
				"if_descr": "LAN",
				"is_reserved": "1"
			},
			{
				"address": "192.168.1.20",
				"hwaddr": "AA:BB:CC:DD:EE:FF",
				"hostname": "phone",
				"expire": 1772402000,
				"if_descr": "LAN",
				"is_reserved": "0"
			}
		],
		"interfaces": {"em0": "LAN"}
	}`

	v6Response := `{
		"total": 1,
		"rowCount": 1,
		"current": 1,
		"rows": [
			{
				"address": "fd00::10",
				"hwaddr": "11:22:33:44:55:66",
				"hostname": "server1",
				"expire": 1772501000,
				"if_descr": "LAN",
				"is_reserved": "0"
			}
		],
		"interfaces": {"em0": "LAN"}
	}`

	mux := keaTestMux(t, v4Response, v6Response)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &keaCollector{subsystem: KeaSubsystem}
	c.Register("opnsense", "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// v4: 1 leasesTotal + 1 reservedTotal + 1 dynamicTotal + 1 leasesByIface (LAN) = 4
	// v6: 1 leasesTotal + 1 reservedTotal + 1 dynamicTotal + 1 leasesByIface (LAN) = 4
	// Total = 8
	expectedCount := 8
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Verify some v4 metric values
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		value := getMetricValue(m)

		if strings.Contains(desc, "dhcp4_leases_total") && labels["opnsense_instance"] == "test" {
			if value != 2 {
				t.Errorf("expected dhcp4_leases_total=2, got %v", value)
			}
		}
		if strings.Contains(desc, "dhcp4_leases_reserved_total") && labels["opnsense_instance"] == "test" {
			if value != 1 {
				t.Errorf("expected dhcp4_leases_reserved_total=1, got %v", value)
			}
		}
		if strings.Contains(desc, "dhcp4_leases_dynamic_total") && labels["opnsense_instance"] == "test" {
			if value != 1 {
				t.Errorf("expected dhcp4_leases_dynamic_total=1, got %v", value)
			}
		}
		if strings.Contains(desc, "dhcp6_leases_total") && labels["opnsense_instance"] == "test" {
			if value != 1 {
				t.Errorf("expected dhcp6_leases_total=1, got %v", value)
			}
		}
	}
}

func TestKeaCollector_Update_WithDetails(t *testing.T) {
	v4Response := `{
		"total": 2,
		"rowCount": 2,
		"current": 1,
		"rows": [
			{
				"address": "192.168.1.10",
				"hwaddr": "00:11:22:33:44:55",
				"hostname": "desktop",
				"expire": 1772401000,
				"if_descr": "LAN",
				"is_reserved": "1"
			},
			{
				"address": "192.168.1.20",
				"hwaddr": "AA:BB:CC:DD:EE:FF",
				"hostname": "phone",
				"expire": 1772402000,
				"if_descr": "LAN",
				"is_reserved": "0"
			}
		],
		"interfaces": {"em0": "LAN"}
	}`

	v6Response := `{
		"total": 1,
		"rowCount": 1,
		"current": 1,
		"rows": [
			{
				"address": "fd00::10",
				"hwaddr": "11:22:33:44:55:66",
				"hostname": "server1",
				"expire": 1772501000,
				"if_descr": "LAN",
				"is_reserved": "0"
			}
		],
		"interfaces": {"em0": "LAN"}
	}`

	mux := keaTestMux(t, v4Response, v6Response)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &keaCollector{subsystem: KeaSubsystem}
	c.Register("opnsense", "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)

	// v4: 3 summary + 1 leasesByIface (LAN) + 2 leaseInfo = 6
	// v6: 3 summary + 1 leasesByIface (LAN) + 1 leaseInfo = 5
	// Total = 11
	expectedCount := 11
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Verify a detail metric exists with correct labels
	foundDetail := false
	for _, m := range metrics {
		labels := getMetricLabels(m)
		if labels["address"] == "192.168.1.10" && labels["hostname"] == "desktop" {
			foundDetail = true
			if labels["hwaddr"] != "00:11:22:33:44:55" {
				t.Errorf("expected hwaddr '00:11:22:33:44:55', got %q", labels["hwaddr"])
			}
			if labels["interface"] != "LAN" {
				t.Errorf("expected interface 'LAN', got %q", labels["interface"])
			}
			value := getMetricValue(m)
			if value != 1772401000 {
				t.Errorf("expected expire value 1772401000, got %v", value)
			}
		}
	}
	if !foundDetail {
		t.Error("expected to find detail metric for address 192.168.1.10")
	}
}

func TestKeaCollector_Update_Empty(t *testing.T) {
	emptyResponse := `{
		"total": 0,
		"rowCount": 0,
		"current": 1,
		"rows": [],
		"interfaces": {}
	}`

	mux := keaTestMux(t, emptyResponse, emptyResponse)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &keaCollector{subsystem: KeaSubsystem}
	c.Register("opnsense", "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// v4: 3 summary (total=0, reserved=0, dynamic=0), no leasesByIface
	// v6: 3 summary (total=0, reserved=0, dynamic=0), no leasesByIface
	// Total = 6
	expectedCount := 6
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Verify all values are 0
	for _, m := range metrics {
		value := getMetricValue(m)
		if value != 0 {
			t.Errorf("expected metric value 0, got %v", value)
		}
	}
}

func TestKeaCollector_Name(t *testing.T) {
	c := &keaCollector{subsystem: KeaSubsystem}
	if c.Name() != KeaSubsystem {
		t.Errorf("expected %s, got %s", KeaSubsystem, c.Name())
	}
}
