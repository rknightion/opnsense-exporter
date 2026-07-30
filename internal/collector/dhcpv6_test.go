package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

const dhcpv6LeasesCollectorFixture = `{
  "total": 2,
  "rowCount": 2,
  "current": 1,
  "rows": [
    {"address": "2001:db8::1000", "type": "dynamic", "lease_type": "ia-na",
     "iaid": "0", "duid": "00:01:00:01:aa:bb:cc:dd:ee:ff:00:11",
     "cltt": "2026/06/09 08:00:00", "ends": "2026/06/09 10:00:00", "descr": "",
     "if": "lan", "if_descr": "LAN", "state": "active", "status": "online",
     "mac": "ee:ff:00:11:22:33", "man": "ExampleCorp"},
    {"address": "2001:db8::53", "type": "static", "lease_type": "",
     "iaid": "", "duid": "00:03:00:01:aa:bb:cc:dd:ee:00", "cltt": "", "ends": "",
     "descr": "dns server", "if": "lan", "if_descr": "LAN",
     "state": "active", "status": "offline", "mac": "", "man": ""}
  ],
  "interfaces": {"lan": "LAN"}
}`

const dhcpv6PrefixesCollectorFixture = `{
  "total": 1,
  "rowCount": 1,
  "current": 1,
  "rows": [
    {"lease_type": "ia-pd", "iaid": "0", "duid": "00:01:00:01:aa:bb:cc:dd:ee:ff:00:11",
     "cltt": "2026/06/09 08:00:00", "prefix": "2001:db8:100::/56",
     "ends": "2026/06/09 10:00:00", "state": "active"}
  ]
}`

func dhcpv6TestMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/dhcpv6/leases/searchLease", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(dhcpv6LeasesCollectorFixture))
	})
	mux.HandleFunc("/api/dhcpv6/leases/searchPrefix", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(dhcpv6PrefixesCollectorFixture))
	})
	return mux
}

func TestDhcpv6Collector_Update_NoDetails(t *testing.T) {
	mux := dhcpv6TestMux(t)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &dhcpv6Collector{subsystem: Dhcpv6Subsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	// detailsEnabled is false by default

	metrics := collectMetrics(t, c, client)

	// leases_total + reserved_total + dynamic_total + 1×leases_by_interface (LAN) +
	// pd_prefixes_total + pd_prefixes_active = 6
	expectedCount := 6
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
		for _, m := range metrics {
			t.Logf("  metric: %s", m.Desc().String())
		}
	}

	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		value := getMetricValue(m)

		if strings.Contains(desc, "dhcpv6_leases_total") && !strings.Contains(desc, "reserved") && !strings.Contains(desc, "dynamic") {
			if labels["opnsense_instance"] == "test" && value != 2 {
				t.Errorf("expected leases_total=2, got %v", value)
			}
		}
		if strings.Contains(desc, "leases_reserved_total") && labels["opnsense_instance"] == "test" {
			if value != 1 {
				t.Errorf("expected leases_reserved_total=1, got %v", value)
			}
		}
		if strings.Contains(desc, "leases_dynamic_total") && labels["opnsense_instance"] == "test" {
			if value != 1 {
				t.Errorf("expected leases_dynamic_total=1, got %v", value)
			}
		}
		if strings.Contains(desc, "leases_by_interface") {
			if labels["interface"] != "LAN" {
				t.Errorf("expected interface=LAN, got %q", labels["interface"])
			}
			if value != 2 {
				t.Errorf("expected leases_by_interface=2, got %v", value)
			}
		}
		if strings.Contains(desc, "pd_prefixes_total") {
			if value != 1 {
				t.Errorf("expected pd_prefixes_total=1, got %v", value)
			}
		}
		if strings.Contains(desc, "pd_prefixes_active") {
			if value != 1 {
				t.Errorf("expected pd_prefixes_active=1, got %v", value)
			}
		}
	}

	// No lease_info metrics should be emitted when details are disabled
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "lease_info") {
			t.Error("expected no lease_info metrics when details disabled")
		}
	}
}

func TestDhcpv6Collector_Update_WithDetails(t *testing.T) {
	mux := dhcpv6TestMux(t)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &dhcpv6Collector{subsystem: Dhcpv6Subsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)

	// leases_total + reserved_total + dynamic_total + 1×leases_by_interface (LAN) +
	// pd_prefixes_total + pd_prefixes_active + 2×lease_info = 8
	expectedCount := 8
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Verify a lease_info metric for the dynamic lease
	foundDynDetail := false
	foundStatDetail := false
	for _, m := range metrics {
		if !strings.Contains(m.Desc().String(), "lease_info") {
			continue
		}
		labels := getMetricLabels(m)
		val := getMetricValue(m)
		if val != 1 {
			t.Errorf("expected lease_info value=1, got %v", val)
		}
		if labels["address"] == "2001:db8::1000" {
			foundDynDetail = true
			if labels["mac"] != "ee:ff:00:11:22:33" {
				t.Errorf("expected mac ee:ff:00:11:22:33, got %q", labels["mac"])
			}
			if labels["duid"] != "00:01:00:01:aa:bb:cc:dd:ee:ff:00:11" {
				t.Errorf("expected duid, got %q", labels["duid"])
			}
			if labels["if_descr"] != "LAN" {
				t.Errorf("expected if_descr LAN, got %q", labels["if_descr"])
			}
			if labels["state"] != "active" {
				t.Errorf("expected state active, got %q", labels["state"])
			}
			if labels["status"] != "online" {
				t.Errorf("expected status online, got %q", labels["status"])
			}
			if labels["type"] != "dynamic" {
				t.Errorf("expected type dynamic, got %q", labels["type"])
			}
			if labels["device"] != "lan" {
				t.Errorf("expected device 'lan', got %q", labels["device"])
			}
		}
		if labels["address"] == "2001:db8::53" {
			foundStatDetail = true
			if labels["type"] != "static" {
				t.Errorf("expected type static, got %q", labels["type"])
			}
		}
	}
	if !foundDynDetail {
		t.Error("expected lease_info for 2001:db8::1000")
	}
	if !foundStatDetail {
		t.Error("expected lease_info for 2001:db8::53")
	}
}

func TestDhcpv6Collector_Update_PluginAbsent(t *testing.T) {
	// No handlers: all requests 404 → plugin absent → 0 metrics
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &dhcpv6Collector{subsystem: Dhcpv6Subsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when plugin absent (all 404), got %d", len(metrics))
	}
}

func TestDhcpv6Collector_Update_PrefixFetchError(t *testing.T) {
	// Leases respond OK but prefixes return 500 → warn + return nil (lease metrics still emitted)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/dhcpv6/leases/searchLease", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(dhcpv6LeasesCollectorFixture))
	})
	mux.HandleFunc("/api/dhcpv6/leases/searchPrefix", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &dhcpv6Collector{subsystem: Dhcpv6Subsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	// Should not fail — prefix error is logged and skipped
	metrics := collectMetrics(t, c, client)

	// leases_total + reserved_total + dynamic_total + 1×leases_by_interface = 4
	// pd metrics are absent because fetch failed
	expectedCount := 4
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics when prefix fetch errors, got %d", expectedCount, len(metrics))
	}
}

func TestDhcpv6Collector_Name(t *testing.T) {
	c := &dhcpv6Collector{subsystem: Dhcpv6Subsystem}
	if c.Name() != Dhcpv6Subsystem {
		t.Errorf("expected %s, got %s", Dhcpv6Subsystem, c.Name())
	}
}
