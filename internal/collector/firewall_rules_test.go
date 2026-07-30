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

	// With details: 1 rulesTotal + 2 configured_rules (true/false) + 5 per-rule metrics (evaluations, packets, bytes, states, pfRules) * 1 rule = 8
	expectedCount := 8
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// #558: the fixture's protocol "any" must surface as the "protocol" label
	// on every per-rule metric.
	evals := metricsByDesc(metrics, "opnsense_firewall_rule_evaluations_total")
	if len(evals) != 1 {
		t.Fatalf("expected 1 evaluations_total series, got %d", len(evals))
	}
	if got := getMetricLabels(evals[0])["protocol"]; got != "any" {
		t.Errorf("expected protocol=any, got %q", got)
	}
}

// TestFirewallRulesCollector_Update_ProtocolSentinel covers #558: a rule
// found in the search results with a mixed-case protocol is lowercased, and a
// stats entry with no matching search row (the "system" case) gets the
// "unknown" sentinel rather than an empty label value.
func TestFirewallRulesCollector_Update_ProtocolSentinel(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/firewall/filter_util/rule_stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"stats": {
				"uuid-1": {"pf_rules": 1, "evaluations": 1, "packets": 1, "bytes": 1, "states": 1},
				"uuid-system": {"pf_rules": 1, "evaluations": 1, "packets": 1, "bytes": 1, "states": 1}
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
					"description": "Allow HTTP",
					"action": "pass",
					"interface": "igb0",
					"%interface": "LAN",
					"direction": "in",
					"protocol": "TCP",
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

	states := metricsByDesc(metrics, "opnsense_firewall_rule_states")
	if len(states) != 2 {
		t.Fatalf("expected 2 states series, got %d", len(states))
	}

	protoByUUID := map[string]string{}
	for _, m := range states {
		labels := getMetricLabels(m)
		protoByUUID[labels["uuid"]] = labels["protocol"]
	}
	if protoByUUID["uuid-1"] != "tcp" {
		t.Errorf("expected uuid-1 protocol=tcp, got %q", protoByUUID["uuid-1"])
	}
	if protoByUUID["uuid-system"] != "unknown" {
		t.Errorf("expected uuid-system protocol=unknown, got %q", protoByUUID["uuid-system"])
	}
}

// TestFirewallRulesCollector_Update_EmptyArrayStats reproduces #481 at the
// collector level: a box with no rule statistics returns "stats":[] (PHP's
// empty-array encoding, not an object), and the collector must report zero
// rules rather than erroring the whole collection out.
func TestFirewallRulesCollector_Update_EmptyArrayStats(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/firewall/filter_util/rule_stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","stats":[]}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &firewallRulesCollector{subsystem: FirewallRulesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	expectedCount := 1
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	if getMetricValue(metrics[0]) != 0 {
		t.Errorf("expected rulesTotal=0, got %f", getMetricValue(metrics[0]))
	}
}

func TestFirewallRulesCollector_Name(t *testing.T) {
	c := &firewallRulesCollector{subsystem: FirewallRulesSubsystem}
	if c.Name() != FirewallRulesSubsystem {
		t.Errorf("expected %s, got %s", FirewallRulesSubsystem, c.Name())
	}
}

func TestFirewallRulesCollector_ConfiguredRules(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/firewall/filter_util/rule_stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"stats": {
				"uuid-1": {"pf_rules": 1, "evaluations": 10, "packets": 5, "bytes": 500, "states": 2}
			}
		}`))
	})
	mux.HandleFunc("/api/firewall/filter/search_rule", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 4, "rowCount": 4, "current": 1,
			"rows": [
				{"uuid": "uuid-1", "description": "allow lan", "action": "pass", "interface": "lan", "%interface": "LAN", "direction": "in", "protocol": "any", "enabled": "1"},
				{"uuid": "uuid-2", "description": "old rule", "action": "block", "interface": "wan", "%interface": "WAN", "direction": "in", "protocol": "any", "enabled": "0"},
				{"uuid": "uuid-3", "description": "allow mgmt", "action": "pass", "interface": "opt3", "%interface": "MGMT", "direction": "in", "protocol": "any", "enabled": "1"},
				{"uuid": "uuid-4", "description": "no enabled field", "action": "pass", "interface": "lan", "%interface": "LAN", "direction": "in", "protocol": "any", "enabled": ""}
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

	configured := metricsByDesc(metrics, "opnsense_firewall_rule_configured_rules")
	if len(configured) != 2 {
		t.Fatalf("expected 2 configured_rules series (true/false), got %d", len(configured))
	}
	vals := map[string]float64{}
	for _, m := range configured {
		vals[getMetricLabels(m)["enabled"]] = getMetricValue(m)
	}
	if vals["true"] != 2 {
		t.Errorf("expected enabled=true count 2, got %v", vals["true"])
	}
	// "0" and empty enabled both count as disabled (explicit == "1" check).
	if vals["false"] != 2 {
		t.Errorf("expected enabled=false count 2, got %v", vals["false"])
	}
}

func TestFirewallRulesCollector_NoConfiguredRulesByDefault(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/firewall/filter_util/rule_stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "ok", "stats": {}}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &firewallRulesCollector{subsystem: FirewallRulesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, client)

	if got := metricsByDesc(metrics, "opnsense_firewall_rule_configured_rules"); len(got) != 0 {
		t.Errorf("expected no configured_rules series without details, got %d", len(got))
	}
}
