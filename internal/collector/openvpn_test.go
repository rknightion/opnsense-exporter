package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
)

func openVPNTestServer(t *testing.T, sessionsJSON string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/api/openvpn/instances/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"uuid": "vpn-uuid-1",
					"description": "Site-to-Site VPN",
					"role": "Server",
					"dev_type": "tun",
					"enabled": "1"
				},
				{
					"uuid": "vpn-uuid-2",
					"description": "Road Warrior",
					"role": "Client",
					"dev_type": "tun",
					"enabled": "0"
				}
			],
			"rowCount": 2,
			"total": 2,
			"current": 1
		}`))
	})

	mux.HandleFunc("/api/openvpn/service/search_sessions", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sessionsJSON))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

const openVPNTestSessions = `{
	"rows": [
		{
			"description": "Site-to-Site VPN",
			"username": "user1",
			"real_address": "203.0.113.10:51820",
			"virtual_address": "10.0.0.2",
			"status": "ok",
			"is_client": true
		},
		{
			"description": "Site-to-Site VPN",
			"username": "user2",
			"real_address": "203.0.113.11:51820",
			"virtual_address": "10.0.0.3",
			"status": "ok",
			"is_client": true
		},
		{
			"description": "Road Warrior",
			"username": "user3",
			"real_address": "198.51.100.7:1194",
			"virtual_address": "10.0.1.2",
			"status": "ok",
			"is_client": true
		}
	],
	"rowCount": 3,
	"total": 3,
	"current": 1
}`

// metricsByDesc groups collected metrics by exact fqName.
func metricsByDesc(metrics []prometheus.Metric, fqName string) []prometheus.Metric {
	var out []prometheus.Metric
	needle := `fqName: "` + fqName + `"`
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), needle) {
			out = append(out, m)
		}
	}
	return out
}

func TestOpenVPNCollector_Update_DefaultNoSessionDetails(t *testing.T) {
	server := openVPNTestServer(t, openVPNTestSessions)
	client := newCollectorTestClient(t, server)

	c := &openVPNCollector{subsystem: OpenVPNSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Per-session series must NOT be emitted by default.
	if got := metricsByDesc(metrics, "opnsense_openvpn_sessions"); len(got) != 0 {
		t.Errorf("expected no per-session metrics by default, got %d", len(got))
	}

	totals := metricsByDesc(metrics, "opnsense_openvpn_sessions_total")
	if len(totals) != 1 {
		t.Fatalf("expected 1 sessions_total metric, got %d", len(totals))
	}
	if v := getMetricValue(totals[0]); v != 3 {
		t.Errorf("expected sessions_total = 3, got %v", v)
	}

	byInstance := metricsByDesc(metrics, "opnsense_openvpn_sessions_by_instance")
	if len(byInstance) != 2 {
		t.Fatalf("expected 2 sessions_by_instance metrics, got %d", len(byInstance))
	}
	counts := map[string]float64{}
	for _, m := range byInstance {
		counts[getMetricLabels(m)["description"]] = getMetricValue(m)
	}
	if counts["Site-to-Site VPN"] != 2 {
		t.Errorf("expected 2 sessions for Site-to-Site VPN, got %v", counts["Site-to-Site VPN"])
	}
	if counts["Road Warrior"] != 1 {
		t.Errorf("expected 1 session for Road Warrior, got %v", counts["Road Warrior"])
	}

	// 2 instances + 1 sessions_total + 2 sessions_by_instance = 5
	if expectedCount := 5; len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestOpenVPNCollector_Update_DetailsEnabled(t *testing.T) {
	server := openVPNTestServer(t, openVPNTestSessions)
	client := newCollectorTestClient(t, server)

	c := &openVPNCollector{subsystem: OpenVPNSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)

	sessions := metricsByDesc(metrics, "opnsense_openvpn_sessions")
	if len(sessions) != 3 {
		t.Fatalf("expected 3 per-session metrics with details enabled, got %d", len(sessions))
	}
	found := false
	for _, m := range sessions {
		labels := getMetricLabels(m)
		if labels["username"] == "user1" &&
			labels["virtual_address"] == "10.0.0.2" &&
			labels["real_address"] == "203.0.113.10:51820" {
			found = true
		}
	}
	if !found {
		t.Error("expected a per-session metric with username=user1, virtual_address=10.0.0.2 and real_address=203.0.113.10:51820")
	}

	// Aggregates still emitted alongside details.
	if got := metricsByDesc(metrics, "opnsense_openvpn_sessions_total"); len(got) != 1 {
		t.Errorf("expected 1 sessions_total metric, got %d", len(got))
	}

	// 2 instances + 1 sessions_total + 2 sessions_by_instance + 3 sessions = 8
	if expectedCount := 8; len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestOpenVPNCollector_Update_NoSessions(t *testing.T) {
	server := openVPNTestServer(t, `{
		"rows": [],
		"rowCount": 0,
		"total": 0,
		"current": 1
	}`)
	client := newCollectorTestClient(t, server)

	c := &openVPNCollector{subsystem: OpenVPNSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// sessions_total must be emitted even when there are zero sessions.
	totals := metricsByDesc(metrics, "opnsense_openvpn_sessions_total")
	if len(totals) != 1 {
		t.Fatalf("expected 1 sessions_total metric, got %d", len(totals))
	}
	if v := getMetricValue(totals[0]); v != 0 {
		t.Errorf("expected sessions_total = 0, got %v", v)
	}

	// 2 instances + 1 sessions_total = 3
	if expectedCount := 3; len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

// TestOpenVPNCollector_Update_ExcludesNonClientRows guards #88: idle running-
// instance rows and enabled-but-stopped stub rows must not inflate sessions_total,
// sessions_by_instance, or the per-session detail metric.
func TestOpenVPNCollector_Update_ExcludesNonClientRows(t *testing.T) {
	sessions := `{
		"rows": [
			{"description":"Site-to-Site VPN","username":"user1","real_address":"203.0.113.10:1194","virtual_address":"10.0.0.2","status":"ok","is_client":true},
			{"description":"Idle Server","username":"","real_address":"","virtual_address":"","status":"connected"},
			{"description":"Stopped Server","username":"","real_address":"","virtual_address":"","status":"failed"}
		],
		"rowCount": 3, "total": 3, "current": 1
	}`
	server := openVPNTestServer(t, sessions)
	client := newCollectorTestClient(t, server)

	c := &openVPNCollector{subsystem: OpenVPNSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)

	totals := metricsByDesc(metrics, "opnsense_openvpn_sessions_total")
	if len(totals) != 1 {
		t.Fatalf("expected 1 sessions_total metric, got %d", len(totals))
	}
	if v := getMetricValue(totals[0]); v != 1 {
		t.Errorf("expected sessions_total = 1 (only the client row), got %v", v)
	}

	byInstance := metricsByDesc(metrics, "opnsense_openvpn_sessions_by_instance")
	if len(byInstance) != 1 {
		t.Errorf("expected 1 sessions_by_instance series (idle/stopped excluded), got %d", len(byInstance))
	}
	for _, m := range byInstance {
		if d := getMetricLabels(m)["description"]; d != "Site-to-Site VPN" {
			t.Errorf("unexpected sessions_by_instance for %q; non-client rows should be excluded", d)
		}
	}

	detail := metricsByDesc(metrics, "opnsense_openvpn_sessions")
	if len(detail) != 1 {
		t.Errorf("expected 1 per-session detail metric (only the client row), got %d", len(detail))
	}
}

func TestOpenVPNCollector_Name(t *testing.T) {
	c := &openVPNCollector{subsystem: OpenVPNSubsystem}
	if c.Name() != OpenVPNSubsystem {
		t.Errorf("expected %s, got %s", OpenVPNSubsystem, c.Name())
	}
}
