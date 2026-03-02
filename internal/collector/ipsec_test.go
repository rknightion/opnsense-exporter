package collector

import (
	"net/http"
	"net/http/httptest"
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

func TestIPsecCollector_Name(t *testing.T) {
	c := &ipsecCollector{subsystem: IPsecSubsystem}
	if c.Name() != IPsecSubsystem {
		t.Errorf("expected %s, got %s", IPsecSubsystem, c.Name())
	}
}
