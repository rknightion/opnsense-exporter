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

	metrics := collectMetrics(t, c, client)

	// 2 NDP entries = 2 metrics
	expectedCount := 2
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

	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics, got %d", len(metrics))
	}
}

func TestNDPCollector_Name(t *testing.T) {
	c := &ndpCollector{subsystem: NDPSubsystem}
	if c.Name() != NDPSubsystem {
		t.Errorf("expected %s, got %s", NDPSubsystem, c.Name())
	}
}
