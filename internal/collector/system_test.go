package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/common/promslog"
)

func TestSystemCollector_Update(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/diagnostics/system/systemResources", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"memory": {
				"total": "8589934592",
				"used": 4294967296,
				"arc": "1073741824"
			}
		}`))
	})

	bootTime := time.Now().Add(-24 * time.Hour).Format("Mon Jan 2 15:04:05 MST 2006")
	configTime := time.Now().Add(-1 * time.Hour).Format("Mon Jan 2 15:04:05 MST 2006")

	mux.HandleFunc("/api/diagnostics/system/systemTime", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"uptime": "1 day",
			"datetime": "` + time.Now().Format("Mon Jan 2 15:04:05 MST 2006") + `",
			"boottime": "` + bootTime + `",
			"config": "` + configTime + `",
			"loadavg": "0.12, 0.34, 0.56"
		}`))
	})

	mux.HandleFunc("/api/diagnostics/system/systemDisk", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"devices": [
				{
					"device": "/dev/da0s1a",
					"type": "ufs",
					"blocks": "20G",
					"used": "5G",
					"available": "15G",
					"used_pct": 25,
					"mountpoint": "/"
				}
			]
		}`))
	})

	mux.HandleFunc("/api/diagnostics/system/systemSwap", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"swap": [
				{
					"device": "/dev/da0s1b",
					"total": "2097152",
					"used": "1024"
				}
			]
		}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &systemCollector{subsystem: SystemSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Memory: 3 metrics (total, used, arc)
	// Time: 1 uptime + 3 loadAverage + 1 configLastChange = 5
	// Disk: 3 per device (total, used, usageRatio) * 1 device = 3
	// Swap: 2 per device (total, used) * 1 device = 2
	// Total: 3 + 5 + 3 + 2 = 13
	expectedCount := 13
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestSystemCollector_Update_NoArc(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/diagnostics/system/systemResources", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"memory": {
				"total": "4294967296",
				"used": 2147483648,
				"arc": ""
			}
		}`))
	})

	bootTime := time.Now().Add(-1 * time.Hour).Format("Mon Jan 2 15:04:05 MST 2006")

	mux.HandleFunc("/api/diagnostics/system/systemTime", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"uptime": "1 hour",
			"datetime": "` + time.Now().Format("Mon Jan 2 15:04:05 MST 2006") + `",
			"boottime": "` + bootTime + `",
			"config": "",
			"loadavg": "0.10, 0.20, 0.30"
		}`))
	})

	mux.HandleFunc("/api/diagnostics/system/systemDisk", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"devices": []}`))
	})

	mux.HandleFunc("/api/diagnostics/system/systemSwap", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"swap": []}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &systemCollector{subsystem: SystemSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Memory: 2 metrics (total, used) - no arc
	// Time: 1 uptime + 3 loadAverage = 4 (no configLastChange since config is "")
	// Disk: 0 (no devices)
	// Swap: 0 (no swap)
	// Total: 2 + 4 + 0 + 0 = 6
	expectedCount := 6
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestSystemCollector_Name(t *testing.T) {
	c := &systemCollector{subsystem: SystemSubsystem}
	if c.Name() != SystemSubsystem {
		t.Errorf("expected %s, got %s", SystemSubsystem, c.Name())
	}
}
