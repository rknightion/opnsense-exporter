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

	mux.HandleFunc("/api/diagnostics/system/system_information", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"name": "fw01.example.com",
			"versions": [
				"OPNsense 24.1.3_1",
				"FreeBSD 14.0-CURRENT",
				"OpenSSL 3.0.12 24 Oct 2023"
			],
			"updates": "0"
		}`))
	})

	mux.HandleFunc("/api/diagnostics/cpu_usage/getCPUType", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`["Intel(R) Xeon(R) CPU E3-1265L v3 @ 2.50GHz (4 cores, 8 threads)"]`))
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
	// Info: 1 metric
	// Total: 3 + 5 + 3 + 2 + 1 = 14
	expectedCount := 14
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Find and verify the system_info metric
	found := false
	for _, m := range metrics {
		labels := getMetricLabels(m)
		if hostname, ok := labels["hostname"]; ok && hostname == "fw01.example.com" {
			found = true
			if labels["opnsense_version"] != "24.1.3_1" {
				t.Errorf("expected opnsense_version='24.1.3_1', got %q", labels["opnsense_version"])
			}
			if labels["freebsd_version"] != "14.0-CURRENT" {
				t.Errorf("expected freebsd_version='14.0-CURRENT', got %q", labels["freebsd_version"])
			}
			if labels["openssl_version"] != "3.0.12 24 Oct 2023" {
				t.Errorf("expected openssl_version='3.0.12 24 Oct 2023', got %q", labels["openssl_version"])
			}
			if labels["cpu_model"] != "Intel(R) Xeon(R) CPU E3-1265L v3 @ 2.50GHz" {
				t.Errorf("expected cpu_model='Intel(R) Xeon(R) CPU E3-1265L v3 @ 2.50GHz', got %q", labels["cpu_model"])
			}
			if labels["cpu_cores"] != "4" {
				t.Errorf("expected cpu_cores='4', got %q", labels["cpu_cores"])
			}
			if labels["cpu_threads"] != "8" {
				t.Errorf("expected cpu_threads='8', got %q", labels["cpu_threads"])
			}
			if v := getMetricValue(m); v != 1 {
				t.Errorf("expected system_info value=1, got %f", v)
			}
			break
		}
	}
	if !found {
		t.Error("system_info metric not found in output")
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

	mux.HandleFunc("/api/diagnostics/system/system_information", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"name": "fw01",
			"versions": ["OPNsense 24.1"],
			"updates": "0"
		}`))
	})

	mux.HandleFunc("/api/diagnostics/cpu_usage/getCPUType", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`["Generic CPU (2 cores, 2 threads)"]`))
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
	// Info: 1 metric
	// Total: 2 + 4 + 0 + 0 + 1 = 7
	expectedCount := 7
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
