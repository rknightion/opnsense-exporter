package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestNDPCollector_Update(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/diagnostics/interface/get_ndp", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[
			{
				"mac": "00:11:22:33:44:55",
				"ip": "fe80::1",
				"intf": "igb0",
				"intf_description": "LAN",
				"manufacturer": "Vendor Name",
				"expire": "23h59m50s",
				"type": "dynamic"
			},
			{
				"mac": "aa:bb:cc:dd:ee:ff",
				"ip": "2001:db8::1",
				"intf": "igb1",
				"intf_description": "WAN",
				"manufacturer": "Other Vendor",
				"expire": "permanent",
				"type": "static"
			}
		]`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &ndpCollector{subsystem: NDPSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)

	// aggregate (1) + 2 per-entry = 3 metrics with details on
	expectedCount := 3
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Verify labels on first metric
	found := false
	for _, m := range metrics {
		labels := getMetricLabels(m)
		if labels["ip"] == "fe80::1" {
			found = true
			if labels["mac"] != "00:11:22:33:44:55" {
				t.Errorf("expected mac '00:11:22:33:44:55', got %q", labels["mac"])
			}
			if labels["interface_description"] != "LAN" {
				t.Errorf("expected interface_description 'LAN', got %q", labels["interface_description"])
			}
			if labels["type"] != "dynamic" {
				t.Errorf("expected type 'dynamic', got %q", labels["type"])
			}
			val := getMetricValue(m)
			if val != 1 {
				t.Errorf("expected value 1, got %v", val)
			}
		}
	}
	if !found {
		t.Error("could not find metric for fe80::1")
	}
}

func TestNDPCollector_Update_Empty(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/diagnostics/interface/get_ndp", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &ndpCollector{subsystem: NDPSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Details off (default) + empty table: only the aggregate (table_entries=0) is emitted.
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric (aggregate only), got %d", len(metrics))
	}
	if !hasFqName(metrics[0], "opnsense_ndp_table_entries") || getMetricValue(metrics[0]) != 0 {
		t.Errorf("expected opnsense_ndp_table_entries=0, got %s=%v",
			metrics[0].Desc().String(), getMetricValue(metrics[0]))
	}
}

// TestNDPCollector_DetailsGating covers #125 for NDP: default emits only the aggregate.
func TestNDPCollector_DetailsGating(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/interface/get_ndp", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`[{"ip":"fe80::1","mac":"00:11:22:33:44:55","intf_description":"LAN","type":"dynamic"}]`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	off := &ndpCollector{subsystem: NDPSubsystem}
	off.Register(namespace, "test", promslog.NewNopLogger())
	m := collectMetrics(t, off, client)
	if len(m) != 1 || !hasFqName(m[0], "opnsense_ndp_table_entries") {
		t.Errorf("details-off should emit only the aggregate, got %d metrics", len(m))
	}
}

func TestNDPCollector_Name(t *testing.T) {
	c := &ndpCollector{subsystem: NDPSubsystem}
	if c.Name() != NDPSubsystem {
		t.Errorf("expected %s, got %s", NDPSubsystem, c.Name())
	}
}

// #534 / #544: manufacturer and the raw device belong on the NDP entry series
// for the same reasons they do on ARP.
func TestNDPCollector_ManufacturerAndDeviceLabels(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`[
		 {"mac":"98:b7:85:21:af:f2","ip":"2001:db8::1","intf":"ixl0_vlan100",
		  "manufacturer":"Intel Corporate","intf_description":"MGMT"},
		 {"mac":"0e:40:69:ec:4d:9a","ip":"fe80::d6:761:6510:f3a6%ixl0","intf":"ixl0",
		  "manufacturer":"","intf_description":"LAN"}
		]`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &ndpCollector{subsystem: NDPSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	seen := 0
	for _, m := range collectMetrics(t, c, client) {
		if !hasFqName(m, "opnsense_ndp_entries") {
			continue
		}
		labels := getMetricLabels(m)
		switch labels["ip"] {
		case "2001:db8::1":
			seen++
			if labels["manufacturer"] != "Intel Corporate" {
				t.Errorf("manufacturer = %q", labels["manufacturer"])
			}
			if labels["device"] != "ixl0_vlan100" {
				t.Errorf("device = %q, want ixl0_vlan100", labels["device"])
			}
		case "fe80::d6:761:6510:f3a6%ixl0":
			seen++
			if labels["manufacturer"] != "" {
				t.Errorf("manufacturer = %q, want empty", labels["manufacturer"])
			}
			if labels["device"] != "ixl0" {
				t.Errorf("device = %q, want ixl0", labels["device"])
			}
		}
	}
	if seen != 2 {
		t.Fatalf("matched %d per-entry series, want 2", seen)
	}
}
