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
	// Stubs for new pool-size and service-status endpoints (empty rows / running).
	mux.HandleFunc("/api/kea/dhcpv4/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	mux.HandleFunc("/api/kea/dhcpv6/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	mux.HandleFunc("/api/kea/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
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
	// + 1 kea_service_running = 9
	expectedCount := 9
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
	// + 1 kea_service_running = 12
	expectedCount := 12
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
	// + 1 kea_service_running = 7
	expectedCount := 7
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Verify all values are 0 — service stub returns "running" (value=1);
	// all lease-based metrics are 0; service_running itself is 1 so skip it
	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "kea_service_running") {
			continue
		}
		value := getMetricValue(m)
		if value != 0 {
			t.Errorf("expected metric value 0, got %v for %s", value, desc)
		}
	}
}

func TestKeaCollector_Update_KeaDisabled(t *testing.T) {
	// When Kea is not enabled, OPNsense returns "interfaces": [] instead of {}.
	// The collector must handle this without errors and emit zero-value metrics.
	keaDisabledResponse := `{
		"total": 0,
		"rowCount": 0,
		"current": 1,
		"rows": [],
		"interfaces": []
	}`

	// Build mux manually (not via keaTestMux) so we can set service status to
	// "stopped" — all emitted metric values should be zero.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/kea/leases4/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(keaDisabledResponse))
	})
	mux.HandleFunc("/api/kea/leases6/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(keaDisabledResponse))
	})
	mux.HandleFunc("/api/kea/dhcpv4/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	mux.HandleFunc("/api/kea/dhcpv6/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	mux.HandleFunc("/api/kea/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"stopped"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &keaCollector{subsystem: KeaSubsystem}
	c.Register("opnsense", "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// v4: 3 summary (total=0, reserved=0, dynamic=0), no leasesByIface
	// v6: 3 summary (total=0, reserved=0, dynamic=0), no leasesByIface
	// + 1 kea_service_running (value=0, stopped) = 7
	expectedCount := 7
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

func TestKeaCollector_Name(t *testing.T) {
	c := &keaCollector{subsystem: KeaSubsystem}
	if c.Name() != KeaSubsystem {
		t.Errorf("expected %s, got %s", KeaSubsystem, c.Name())
	}
}

func TestKeaCollector_PoolAndService(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/kea/leases4/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	mux.HandleFunc("/api/kea/leases6/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	mux.HandleFunc("/api/kea/dhcpv4/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[{"uuid":"u1","subnet":"10.0.0.0/24","pools":"10.0.0.110 - 10.0.0.240","interface":"lan","%interface":"LAN"}],"rowCount":1,"total":1,"current":1}`))
	})
	mux.HandleFunc("/api/kea/dhcpv6/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	mux.HandleFunc("/api/kea/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &keaCollector{subsystem: KeaSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	var sawPool, sawService bool
	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "kea_dhcp4_pool_size") {
			sawPool = true
			labels := getMetricLabels(m)
			if labels["subnet"] != "10.0.0.0/24" || labels["interface"] != "LAN" || getMetricValue(m) != 131 {
				t.Errorf("bad pool_size: value=%v labels=%v", getMetricValue(m), labels)
			}
		}
		if strings.Contains(desc, "kea_service_running") {
			sawService = true
			if getMetricValue(m) != 1 {
				t.Errorf("expected service_running=1, got %v", getMetricValue(m))
			}
		}
	}
	if !sawPool || !sawService {
		t.Errorf("missing metrics: pool=%v service=%v", sawPool, sawService)
	}
}
