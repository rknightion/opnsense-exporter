package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestIPsecCollector_Update(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/ipsec/sessions/search_phase1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"phase1desc": "Site-to-Site Tunnel",
					"connected": true,
					"ikeid": "1",
					"name": "con1",
					"install-time": "120",
					"bytes-in": 10240,
					"bytes-out": 20480,
					"packets-in": 100,
					"packets-out": 200
				}
			],
			"rowCount": 1,
			"total": 1,
			"current": 1
		}`))
	})

	mux.HandleFunc("/api/ipsec/sessions/search_phase2", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"phase2desc": "Child SA 1",
					"name": "child-1",
					"spi-in": "c1234567",
					"spi-out": "c7654321",
					"install-time": "60",
					"rekey-time": "3200",
					"life-time": "3600",
					"bytes-in": "5120",
					"bytes-out": "10240",
					"packets-in": "50",
					"packets-out": "100"
				}
			]
		}`))
	})

	mux.HandleFunc("/api/ipsec/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "running"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &ipsecCollector{subsystem: IPsecSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Phase1: 6 metrics (status, install_time, bytes_in, bytes_out, packets_in, packets_out)
	// Phase2: 7 metrics (install_time, bytes_in, bytes_out, packets_in, packets_out, rekey_time, life_time)
	// 1 serviceRunning
	// Total: 6 + 7 + 1 = 14
	expectedCount := 14
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestIPsecCollector_Update_NoPhase2(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/ipsec/sessions/search_phase1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"phase1desc": "Disconnected Tunnel",
					"connected": false,
					"ikeid": "2",
					"name": "con2",
					"install-time": "0",
					"bytes-in": 0,
					"bytes-out": 0,
					"packets-in": 0,
					"packets-out": 0
				}
			],
			"rowCount": 1,
			"total": 1,
			"current": 1
		}`))
	})

	mux.HandleFunc("/api/ipsec/sessions/search_phase2", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": []
		}`))
	})

	mux.HandleFunc("/api/ipsec/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "running"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &ipsecCollector{subsystem: IPsecSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Phase1 only: 6 metrics + 1 serviceRunning
	expectedCount := 7
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Verify connected=0
	foundConnected := false
	for _, m := range metrics {
		if getMetricValue(m) == 0 {
			foundConnected = true
			break
		}
	}
	if !foundConnected {
		t.Error("expected to find a metric with value 0 for disconnected tunnel")
	}
}

func TestIPsecCollector_Update_NoSPILabels(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/ipsec/sessions/search_phase1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"phase1desc": "Site-to-Site Tunnel",
					"connected": true,
					"ikeid": "1",
					"name": "con1",
					"install-time": "120",
					"bytes-in": 10240,
					"bytes-out": 20480,
					"packets-in": 100,
					"packets-out": 200
				}
			],
			"rowCount": 1,
			"total": 1,
			"current": 1
		}`))
	})

	mux.HandleFunc("/api/ipsec/sessions/search_phase2", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"phase2desc": "Child SA 1",
					"name": "child-1",
					"spi-in": "c1234567",
					"spi-out": "c7654321",
					"install-time": "60",
					"rekey-time": "3200",
					"life-time": "3600",
					"bytes-in": "5120",
					"bytes-out": "10240",
					"packets-in": "50",
					"packets-out": "100"
				}
			]
		}`))
	})

	mux.HandleFunc("/api/ipsec/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "running"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &ipsecCollector{subsystem: IPsecSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	phase2Seen := false
	for _, m := range metrics {
		labels := getMetricLabels(m)
		if _, ok := labels["spi_in"]; ok {
			t.Errorf("metric %s carries forbidden spi_in label", m.Desc().String())
		}
		if _, ok := labels["spi_out"]; ok {
			t.Errorf("metric %s carries forbidden spi_out label", m.Desc().String())
		}
		if labels["phase1_name"] == "con1" {
			phase2Seen = true
		}
	}
	if !phase2Seen {
		t.Error("expected phase2 metrics with phase1_name label to be emitted")
	}
}

func TestIPsecCollector_Update_DedupeRekeyOverlap(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/ipsec/sessions/search_phase1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"phase1desc": "Site-to-Site Tunnel",
					"connected": true,
					"ikeid": "1",
					"name": "con1",
					"install-time": "120",
					"bytes-in": 10240,
					"bytes-out": 20480,
					"packets-in": 100,
					"packets-out": 200
				}
			],
			"rowCount": 1,
			"total": 1,
			"current": 1
		}`))
	})

	// Two SAs for the same child (rekey overlap: old SA still installed) plus
	// one distinct child. Without dedupe this would emit duplicate label sets.
	mux.HandleFunc("/api/ipsec/sessions/search_phase2", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"phase2desc": "Child SA 1",
					"name": "child-1",
					"spi-in": "cOLD1111",
					"spi-out": "cOLD2222",
					"install-time": "7200",
					"rekey-time": "100",
					"life-time": "400",
					"bytes-in": "1000",
					"bytes-out": "2000",
					"packets-in": "10",
					"packets-out": "20"
				},
				{
					"phase2desc": "Child SA 1",
					"name": "child-1",
					"spi-in": "cNEW1111",
					"spi-out": "cNEW2222",
					"install-time": "60",
					"rekey-time": "3200",
					"life-time": "3600",
					"bytes-in": "5120",
					"bytes-out": "10240",
					"packets-in": "50",
					"packets-out": "100"
				},
				{
					"phase2desc": "Child SA 2",
					"name": "child-2",
					"spi-in": "cAAA1111",
					"spi-out": "cAAA2222",
					"install-time": "30",
					"rekey-time": "3300",
					"life-time": "3700",
					"bytes-in": "999",
					"bytes-out": "888",
					"packets-in": "9",
					"packets-out": "8"
				}
			]
		}`))
	})

	mux.HandleFunc("/api/ipsec/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "running"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &ipsecCollector{subsystem: IPsecSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Phase1: 6, Phase2: 7 per unique (desc, name) child (2 children), serviceRunning: 1.
	expectedCount := 6 + 7*2 + 1
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Exactly one install_time series per child; child-1 values must come from the
	// row with the smallest install-time (newest SA).
	installTimes := metricsByDesc(metrics, "opnsense_ipsec_phase2_install_time")
	if len(installTimes) != 2 {
		t.Fatalf("expected 2 phase2_install_time metrics, got %d", len(installTimes))
	}
	for _, m := range installTimes {
		labels := getMetricLabels(m)
		if labels["name"] == "child-1" {
			if v := getMetricValue(m); v != 60 {
				t.Errorf("expected child-1 install_time from newest SA (60), got %v", v)
			}
		}
	}

	bytesIn := metricsByDesc(metrics, "opnsense_ipsec_phase2_bytes_in")
	if len(bytesIn) != 2 {
		t.Fatalf("expected 2 phase2_bytes_in metrics, got %d", len(bytesIn))
	}
	for _, m := range bytesIn {
		labels := getMetricLabels(m)
		switch labels["name"] {
		case "child-1":
			if v := getMetricValue(m); v != 5120 {
				t.Errorf("expected child-1 bytes_in from newest SA (5120), got %v", v)
			}
		case "child-2":
			if v := getMetricValue(m); v != 999 {
				t.Errorf("expected child-2 bytes_in 999, got %v", v)
			}
		}
	}
}

func TestIPsecCollector_Name(t *testing.T) {
	c := &ipsecCollector{subsystem: IPsecSubsystem}
	if c.Name() != IPsecSubsystem {
		t.Errorf("expected %s, got %s", IPsecSubsystem, c.Name())
	}
}

func TestIPsecCollector_Update_Pools(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/ipsec/sessions/search_phase1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"phase1desc": "Site-to-Site Tunnel",
					"connected": true,
					"ikeid": "1",
					"name": "con1",
					"install-time": "120",
					"bytes-in": 10240,
					"bytes-out": 20480,
					"packets-in": 100,
					"packets-out": 200
				}
			],
			"rowCount": 1,
			"total": 1,
			"current": 1
		}`))
	})

	mux.HandleFunc("/api/ipsec/sessions/search_phase2", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows": []}`))
	})

	mux.HandleFunc("/api/ipsec/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "running"}`))
	})

	mux.HandleFunc("/api/ipsec/leases/pools", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"pools": {
				"defaultv4": {"name": "defaultv4", "net": "10.18.0.0/24", "online": 1, "offline": 2, "size": 254}
			},
			"leases": []
		}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &ipsecCollector{subsystem: IPsecSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Phase1: 6 metrics + serviceRunning: 1 + pools: 3 (online, offline, size)
	// No phase2 rows => 0 phase2 metrics
	expectedCount := 6 + 1 + 3
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Spot-check pool metrics
	foundOnline, foundOffline, foundSize := false, false, false
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		val := getMetricValue(m)
		switch {
		case strings.Contains(desc, "ipsec_pool_leases_online"):
			foundOnline = true
			if labels["pool"] != "defaultv4" || labels["net"] != "10.18.0.0/24" || val != 1 {
				t.Errorf("pool_leases_online wrong: labels=%v val=%v", labels, val)
			}
		case strings.Contains(desc, "ipsec_pool_leases_offline"):
			foundOffline = true
			if labels["pool"] != "defaultv4" || val != 2 {
				t.Errorf("pool_leases_offline wrong: labels=%v val=%v", labels, val)
			}
		case strings.Contains(desc, "ipsec_pool_size"):
			foundSize = true
			if labels["pool"] != "defaultv4" || val != 254 {
				t.Errorf("pool_size wrong: labels=%v val=%v", labels, val)
			}
		}
	}
	if !foundOnline {
		t.Error("expected ipsec_pool_leases_online metric to be emitted")
	}
	if !foundOffline {
		t.Error("expected ipsec_pool_leases_offline metric to be emitted")
	}
	if !foundSize {
		t.Error("expected ipsec_pool_size metric to be emitted")
	}
}

func TestIPsecCollector_Update_PoolsUnconfigured(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/ipsec/sessions/search_phase1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows": [], "rowCount": 0, "total": 0, "current": 1}`))
	})

	mux.HandleFunc("/api/ipsec/sessions/search_phase2", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows": []}`))
	})

	mux.HandleFunc("/api/ipsec/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "running"}`))
	})

	// Pools endpoint returns unconfigured (array) response
	mux.HandleFunc("/api/ipsec/leases/pools", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"pools": []}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &ipsecCollector{subsystem: IPsecSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// No phase1, no phase2, no pools; only serviceRunning
	expectedCount := 1
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics (serviceRunning only), got %d", expectedCount, len(metrics))
	}
}
