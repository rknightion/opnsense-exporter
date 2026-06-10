package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

// monitRunningCollectorFixture is the full monit status body used for collector
// tests. Two services: $HOST (type 5 = system, status 0 = ok) and nginx
// (type 3 = process, status 512 = error).
const monitRunningCollectorFixture = `{
  "result": "ok",
  "status": {
    "@attributes": {"id": "abc123", "incarnation": "1700000000", "version": "5.33.0"},
    "service": [
      {"@attributes": {"type": "5"}, "name": "$HOST",
       "status": "0", "monitor": "1", "monitormode": "0", "pendingaction": "0"},
      {"@attributes": {"type": "3"}, "name": "nginx",
       "status": "512", "monitor": "1", "monitormode": "0", "pendingaction": "0"}
    ]
  }
}`

// monitDownCollectorFixture matches the live-validated "monit not running" response.
const monitDownCollectorFixture = `{"result": "failed",
 "status": "\nEither the file /var/run/monit.sock does not exists or it is not a unix socket.\nPlease check if the Monit service is running.\n\nIf you have started Monit recently, wait for StartDelay seconds and refresh this page."}`

func monitCollectorMux(t *testing.T, statusBody, serviceStatus string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/monit/status/get/xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(statusBody))
	})
	mux.HandleFunc("/api/monit/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(serviceStatus))
	})
	return mux
}

func TestMonitCollector_Update_Running(t *testing.T) {
	server := httptest.NewServer(monitCollectorMux(t,
		monitRunningCollectorFixture, `{"status":"running"}`))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &monitCollector{subsystem: MonitSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Expected:
	//   1  service_running
	//   1  status_ok
	//   1  checks_total
	//   2× check_status  (one per service)
	//   2× check_monitored (one per service)
	// Total = 7
	if len(metrics) != 7 {
		t.Errorf("expected 7 metrics, got %d", len(metrics))
		for _, m := range metrics {
			t.Logf("  %s", m.Desc().String())
		}
	}

	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		val := getMetricValue(m)

		switch {
		case strings.Contains(desc, "monit_service_running"):
			if val != 1 {
				t.Errorf("service_running: expected 1, got %v", val)
			}
		case strings.Contains(desc, "monit_status_ok"):
			if val != 1 {
				t.Errorf("status_ok: expected 1, got %v", val)
			}
		case strings.Contains(desc, "monit_checks_total"):
			if val != 2 {
				t.Errorf("checks_total: expected 2, got %v", val)
			}
		case strings.Contains(desc, "monit_check_status"):
			switch labels["name"] {
			case "$HOST":
				if val != 1 {
					t.Errorf("check_status $HOST: expected 1 (ok), got %v", val)
				}
				if labels["type"] != "system" {
					t.Errorf("check_status $HOST: expected type=system, got %q", labels["type"])
				}
			case "nginx":
				if val != 0 {
					t.Errorf("check_status nginx: expected 0 (error, status=512), got %v", val)
				}
				if labels["type"] != "process" {
					t.Errorf("check_status nginx: expected type=process, got %q", labels["type"])
				}
			default:
				t.Errorf("unexpected check_status label name=%q", labels["name"])
			}
		}
	}
}

func TestMonitCollector_Update_MonitStopped(t *testing.T) {
	// monit is installed but not running: status endpoint returns "failed" envelope.
	// The OPNsense service/status endpoint reports "stopped".
	server := httptest.NewServer(monitCollectorMux(t,
		monitDownCollectorFixture, `{"status":"stopped"}`))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &monitCollector{subsystem: MonitSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Expected:
	//   1 service_running (=0, stopped)
	//   1 status_ok (=0, monit not reachable)
	// No per-check metrics.
	if len(metrics) != 2 {
		t.Errorf("expected 2 metrics when monit stopped, got %d", len(metrics))
		for _, m := range metrics {
			t.Logf("  %s", m.Desc().String())
		}
	}

	for _, m := range metrics {
		desc := m.Desc().String()
		val := getMetricValue(m)
		switch {
		case strings.Contains(desc, "monit_service_running"):
			if val != 0 {
				t.Errorf("service_running: expected 0 (stopped), got %v", val)
			}
		case strings.Contains(desc, "monit_status_ok"):
			if val != 0 {
				t.Errorf("status_ok: expected 0, got %v", val)
			}
		}
	}
}

func TestMonitCollector_Name(t *testing.T) {
	c := &monitCollector{subsystem: MonitSubsystem}
	if c.Name() != MonitSubsystem {
		t.Errorf("expected %s, got %s", MonitSubsystem, c.Name())
	}
}
