package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestFirewallRulesCollector_Update_NoDetails(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/firewall/filter_util/rule_stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"stats": {
				"uuid-1": {
					"pf_rules": 2,
					"evaluations": 1000,
					"packets": 500,
					"bytes": 65536,
					"states": 10
				},
				"uuid-2": {
					"pf_rules": 1,
					"evaluations": 200,
					"packets": 100,
					"bytes": 8192,
					"states": 5
				}
			}
		}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &firewallRulesCollector{subsystem: FirewallRulesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	// detailsEnabled is false by default

	metrics := collectMetrics(t, c, client)

	// Without details: only rulesTotal = 1
	expectedCount := 1
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// rulesTotal should be 2
	if getMetricValue(metrics[0]) != 2 {
		t.Errorf("expected rulesTotal=2, got %f", getMetricValue(metrics[0]))
	}
}

func TestFirewallRulesCollector_Update_WithDetails(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/firewall/filter_util/rule_stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"stats": {
				"uuid-1": {
					"pf_rules": 2,
					"evaluations": 1000,
					"packets": 500,
					"bytes": 65536,
					"states": 10
				}
			}
		}`))
	})

	mux.HandleFunc("/api/firewall/filter/search_rule", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1,
			"rowCount": 1,
			"current": 1,
			"rows": [
				{
					"uuid": "uuid-1",
					"description": "Allow LAN to WAN",
					"action": "pass",
					"interface": "igb0",
					"%interface": "LAN",
					"direction": "in",
					"protocol": "any",
					"enabled": "1"
				}
			]
		}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &firewallRulesCollector{subsystem: FirewallRulesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)

	// With details: 1 rulesTotal + 5 per-rule metrics (evaluations, packets, bytes, states, pfRules) * 1 rule = 6
	expectedCount := 6
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestFirewallRulesCollector_Name(t *testing.T) {
	c := &firewallRulesCollector{subsystem: FirewallRulesSubsystem}
	if c.Name() != FirewallRulesSubsystem {
		t.Errorf("expected %s, got %s", FirewallRulesSubsystem, c.Name())
	}
}
