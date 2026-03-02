package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestNetflowCollector_Update(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/diagnostics/netflow/isEnabled", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"netflow": 1, "local": 1}`))
	})

	mux.HandleFunc("/api/diagnostics/netflow/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "active", "collectors": "12"}`))
	})

	mux.HandleFunc("/api/diagnostics/netflow/cacheStats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"netflow_igb0": {"Pkts": 2724171, "if": "igb0", "SrcIPaddresses": 539, "DstIPaddresses": 562},
			"netflow_pppoe0": {"Pkts": 0, "if": "pppoe0", "SrcIPaddresses": 0, "DstIPaddresses": 0},
			"ksocket_netflow_igb0": {"Pkts": 0, "if": "netflow_igb0", "SrcIPaddresses": 0, "DstIPaddresses": 0}
		}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &netflowCollector{subsystem: NetflowSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 2 isEnabled + 2 status + 2 interfaces * 3 cache = 10
	expectedCount := 10
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	for _, m := range metrics {
		labels := getMetricLabels(m)
		desc := m.Desc().String()

		if containsString(desc, "netflow_enabled") && !containsString(desc, "local") {
			val := getMetricValue(m)
			if val != 1 {
				t.Errorf("netflow_enabled = %v; want 1", val)
			}
		}

		if containsString(desc, "netflow_active") {
			val := getMetricValue(m)
			if val != 1 {
				t.Errorf("netflow_active = %v; want 1", val)
			}
		}

		if containsString(desc, "netflow_collectors_count") {
			val := getMetricValue(m)
			if val != 12 {
				t.Errorf("netflow_collectors_count = %v; want 12", val)
			}
		}

		if containsString(desc, "cache_packets_total") && labels["interface"] == "igb0" {
			val := getMetricValue(m)
			if val != 2724171 {
				t.Errorf("igb0 cache_packets_total = %v; want 2724171", val)
			}
		}
	}
}

func TestNetflowCollector_UpdateDisabled(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/diagnostics/netflow/isEnabled", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"netflow": 0, "local": 0}`))
	})

	mux.HandleFunc("/api/diagnostics/netflow/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "stopped", "collectors": "0"}`))
	})

	mux.HandleFunc("/api/diagnostics/netflow/cacheStats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &netflowCollector{subsystem: NetflowSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 2 isEnabled + 2 status + 0 cache = 4
	expectedCount := 4
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	for _, m := range metrics {
		desc := m.Desc().String()
		if containsString(desc, "netflow_enabled") && !containsString(desc, "local") {
			val := getMetricValue(m)
			if val != 0 {
				t.Errorf("netflow_enabled = %v; want 0", val)
			}
		}
		if containsString(desc, "netflow_active") {
			val := getMetricValue(m)
			if val != 0 {
				t.Errorf("netflow_active = %v; want 0", val)
			}
		}
	}
}

func TestNetflowCollector_Name(t *testing.T) {
	c := &netflowCollector{subsystem: NetflowSubsystem}
	if c.Name() != NetflowSubsystem {
		t.Errorf("expected %s, got %s", NetflowSubsystem, c.Name())
	}
}
