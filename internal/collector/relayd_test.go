package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

func relaydTestMux(t *testing.T, response string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/relayd/status/sum", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(response))
	})
	return mux
}

func TestRelaydCollector_Update_Populated(t *testing.T) {
	// Real dev-box capture shape (issue #202): one redirect + one 2-host table,
	// both hosts up at 100.00% availability.
	response := `{
		"result": "ok",
		"rows": [
			{
				"id": "1",
				"type": "redirect",
				"name": "relay-vs",
				"status": "active",
				"tables": {
					"1": {
						"name": "relay-table:8080",
						"status": "active (2 hosts)",
						"hosts": {
							"1": {
								"properties": [{"uuid": "u1", "name": "relay-h1", "enabled": "1"}],
								"name": "172.16.9.99",
								"avlblty": "100.00%",
								"status": "up"
							},
							"2": {
								"properties": [{"uuid": "u2", "name": "relay-h2", "enabled": "1"}],
								"name": "172.16.9.98",
								"avlblty": "100.00%",
								"status": "up"
							}
						}
					}
				}
			}
		]
	}`

	mux := relaydTestMux(t, response)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &relaydCollector{subsystem: RelaydSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	// 1 virtualserver_status + 1 table_active + 2 host_up + 2 host_availability_percent = 6
	expectedCount := 6
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		val := getMetricValue(m)

		switch {
		case strings.Contains(desc, "virtualserver_status"):
			if labels["name"] != "relay-vs" || labels["type"] != "redirect" {
				t.Errorf("unexpected virtualserver labels: %+v", labels)
			}
			if val != 1 {
				t.Errorf("expected virtualserver_status=1, got %v", val)
			}
		case strings.Contains(desc, "table_active"):
			if labels["virtualserver"] != "relay-vs" || labels["table"] != "relay-table" {
				t.Errorf("unexpected table labels: %+v", labels)
			}
			if val != 1 {
				t.Errorf("expected table_active=1, got %v", val)
			}
		case strings.Contains(desc, "host_availability_percent"):
			if val != 100 {
				t.Errorf("expected host_availability_percent=100, got %v", val)
			}
		case strings.Contains(desc, "host_up"):
			if val != 1 {
				t.Errorf("expected host_up=1, got %v", val)
			}
			if labels["table"] != "relay-table" {
				t.Errorf("expected table label 'relay-table', got %q", labels["table"])
			}
		}
	}
}

// TestRelaydCollector_Update_StoppedNoTopology guards the dev-box-confirmed
// baseline: relayd present but with no topology configured yet answers
// {"result":"failed"} — the collector must stay silent, not emit zeros.
func TestRelaydCollector_Update_StoppedNoTopology(t *testing.T) {
	mux := relaydTestMux(t, `{"result":"failed"}`)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &relaydCollector{subsystem: RelaydSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics for result:\"failed\" (present but no data), got %d", len(metrics))
	}
}

// TestRelaydCollector_Update_PluginAbsent guards the os-relayd-not-installed
// case: the collector must emit nothing rather than any all-zero shape.
func TestRelaydCollector_Update_PluginAbsent(t *testing.T) {
	mux := http.NewServeMux() // no handlers: all requests 404 → plugin absent
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &relaydCollector{subsystem: RelaydSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when plugin absent (404), got %d", len(metrics))
	}
}

// TestRelaydCollector_Update_AvailabilityOmittedWhenNull guards the disabled/
// backfilled-host shape: avlblty is JSON null when a host is configured into
// the table but wasn't reported live by relayd, so the availability metric
// must not be emitted for it — a fabricated 0% would misreport "0% up" for a
// host relayd simply hasn't checked, distinct from a genuine 0.00%.
func TestRelaydCollector_Update_AvailabilityOmittedWhenNull(t *testing.T) {
	response := `{
		"result": "ok",
		"rows": [
			{
				"id": "1", "type": "redirect", "name": "relay-vs", "status": "active",
				"tables": {
					"1": {
						"name": "relay-table:8080",
						"status": "active (1 hosts)",
						"hosts": {
							"1": {
								"properties": [{"uuid": "u1", "name": "relay-h1", "enabled": "0"}],
								"name": "172.16.9.99",
								"avlblty": null,
								"status": "disabled"
							}
						}
					}
				}
			}
		]
	}`

	mux := relaydTestMux(t, response)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &relaydCollector{subsystem: RelaydSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 1 virtualserver_status + 1 table_active + 1 host_up = 3, NO availability metric.
	expectedCount := 3
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics (availability omitted), got %d", expectedCount, len(metrics))
	}
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "host_availability_percent") {
			t.Errorf("expected no host_availability_percent metric when avlblty is null, got: %s", m.Desc().String())
		}
	}
}

func TestRelaydCollector_Name(t *testing.T) {
	c := &relaydCollector{subsystem: RelaydSubsystem}
	if c.Name() != RelaydSubsystem {
		t.Errorf("expected %s, got %s", RelaydSubsystem, c.Name())
	}
}
