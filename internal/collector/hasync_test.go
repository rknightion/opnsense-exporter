package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

// hasyncVersionConfigured and hasyncServicesFixture mirror the opnsense-package
// fixtures; they are repeated here so the collector package has no test-only
// dependency on the opnsense package's private constants.
const hasyncCollectorVersionFixture = `{
  "response": {
    "firmware": {"version": "26.1.3", "_my_version": "26.1.3"},
    "base":     {"version": "26.1"},
    "kernel":   {"version": "26.1"}
  }
}`

const hasyncCollectorServicesFixture = `{
  "total": 2, "rowCount": 2, "current": 1,
  "rows": [
    {"name": "openssh",  "description": "Secure Shell Daemon", "status": true,  "uid": "openssh"},
    {"name": "openvpn",  "description": "OpenVPN server",      "status": false, "id": "1", "uid": "openvpn_1"}
  ]
}`

func hasyncCollectorMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/core/hasync_status/version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(hasyncCollectorVersionFixture))
	})
	mux.HandleFunc("/api/core/hasync_status/services", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(hasyncCollectorServicesFixture))
	})
	return mux
}

// TestHasyncCollector_Update_Configured asserts the configured/reachable path
// emits exactly 6 metrics:
//   - remote_reachable (1)
//   - remote_version_match (1)
//   - remote_version_info (1)
//   - remote_services_total (1)
//   - remote_service_running × 2 (2)
//
// Total = 6.
func TestHasyncCollector_Update_Configured(t *testing.T) {
	server := httptest.NewServer(hasyncCollectorMux(t))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &hasyncCollector{subsystem: HasyncSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// reachable + match + info + total + 2 services = 6
	expected := 6
	if len(metrics) != expected {
		t.Errorf("expected %d metrics, got %d", expected, len(metrics))
		for _, m := range metrics {
			t.Logf("  metric: %s", m.Desc().String())
		}
	}

	// Spot-check key metric values.
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		val := getMetricValue(m)

		switch {
		case strings.Contains(desc, "hasync_remote_reachable"):
			if val != 1 {
				t.Errorf("remote_reachable: got %v, want 1", val)
			}
		case strings.Contains(desc, "hasync_remote_version_match"):
			if val != 1 {
				t.Errorf("remote_version_match: got %v, want 1 (versions match)", val)
			}
		case strings.Contains(desc, "hasync_remote_version_info"):
			if val != 1 {
				t.Errorf("remote_version_info value: got %v, want 1", val)
			}
			if labels["remote_version"] != "26.1.3" || labels["local_version"] != "26.1.3" {
				t.Errorf("remote_version_info labels: got remote=%q local=%q",
					labels["remote_version"], labels["local_version"])
			}
		case strings.Contains(desc, "hasync_remote_services_total"):
			if val != 2 {
				t.Errorf("remote_services_total: got %v, want 2", val)
			}
		case strings.Contains(desc, "hasync_remote_service_running"):
			switch labels["service"] {
			case "openssh":
				if val != 1 {
					t.Errorf("openssh service_running: got %v, want 1", val)
				}
			case "openvpn":
				if val != 0 {
					t.Errorf("openvpn service_running: got %v, want 0", val)
				}
				if labels["id"] != "1" {
					t.Errorf("openvpn id label: got %q, want %q", labels["id"], "1")
				}
			default:
				t.Errorf("unexpected service label: %q", labels["service"])
			}
		}
	}
}

// TestHasyncCollector_Update_Unconfigured asserts that an unconfigured/
// unreachable peer (error envelope) results in 0 metrics — the collector
// is completely silent (it is opt-in for this exact reason).
func TestHasyncCollector_Update_Unconfigured(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/core/hasync_status/version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"error","message":"unable to connect to peer"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &hasyncCollector{subsystem: HasyncSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics for unconfigured peer, got %d", len(metrics))
	}
}

// TestHasyncCollector_Name validates the Name() method returns HasyncSubsystem.
func TestHasyncCollector_Name(t *testing.T) {
	c := &hasyncCollector{subsystem: HasyncSubsystem}
	if c.Name() != HasyncSubsystem {
		t.Errorf("Name(): got %q, want %q", c.Name(), HasyncSubsystem)
	}
}
