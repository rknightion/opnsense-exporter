package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchFirewallRuleStats_DetailsDisabled(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"status": "ok",
			"stats": {
				"uuid-rule-1": {
					"pf_rules": 1,
					"evaluations": 100,
					"packets": 5000,
					"bytes": 2000000,
					"states": 25
				},
				"uuid-rule-2": {
					"pf_rules": 2,
					"evaluations": 200,
					"packets": 10000,
					"bytes": 4000000,
					"states": 50
				}
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchFirewallRuleStats(false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(data.Rules))
	}

	// When details disabled, Description should be "system"
	for _, rule := range data.Rules {
		if rule.Description != "system" {
			t.Errorf("expected Description='system' when details disabled, got %q", rule.Description)
		}
		// Action, Interface, Direction should be empty
		if rule.Action != "" {
			t.Errorf("expected empty Action when details disabled, got %q", rule.Action)
		}
		if rule.Interface != "" {
			t.Errorf("expected empty Interface when details disabled, got %q", rule.Interface)
		}
	}

	// Find rule by UUID
	var rule1 *FirewallRuleStats
	for i := range data.Rules {
		if data.Rules[i].UUID == "uuid-rule-1" {
			rule1 = &data.Rules[i]
		}
	}
	if rule1 == nil {
		t.Fatal("uuid-rule-1 not found")
	}
	if rule1.PfRules != 1 {
		t.Errorf("expected PfRules=1, got %d", rule1.PfRules)
	}
	if rule1.Evaluations != 100 {
		t.Errorf("expected Evaluations=100, got %d", rule1.Evaluations)
	}
	if rule1.Packets != 5000 {
		t.Errorf("expected Packets=5000, got %d", rule1.Packets)
	}
	if rule1.Bytes != 2000000 {
		t.Errorf("expected Bytes=2000000, got %d", rule1.Bytes)
	}
	if rule1.States != 25 {
		t.Errorf("expected States=25, got %d", rule1.States)
	}
}

func TestFetchFirewallRuleStats_DetailsEnabled(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	// Register stats endpoint (GET)
	mux.HandleFunc("/api/firewall/filter_util/rule_stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"stats": {
				"uuid-rule-1": {
					"pf_rules": 1,
					"evaluations": 100,
					"packets": 5000,
					"bytes": 2000000,
					"states": 25
				},
				"uuid-rule-2": {
					"pf_rules": 2,
					"evaluations": 200,
					"packets": 10000,
					"bytes": 4000000,
					"states": 50
				},
				"uuid-system-rule": {
					"pf_rules": 3,
					"evaluations": 300,
					"packets": 15000,
					"bytes": 6000000,
					"states": 75
				}
			}
		}`))
	})

	// Register rules search endpoint (POST)
	mux.HandleFunc("/api/firewall/filter/search_rule", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST for search_rule, got %s", r.Method)
		}
		w.Write([]byte(`{
			"total": 2,
			"rowCount": 2,
			"current": 1,
			"rows": [
				{
					"uuid": "uuid-rule-1",
					"description": "Allow HTTP",
					"action": "pass",
					"interface": "igb0_raw",
					"%interface": "LAN",
					"direction": "in",
					"protocol": "TCP",
					"enabled": "1"
				},
				{
					"uuid": "uuid-rule-2",
					"description": "Block SSH",
					"action": "block",
					"interface": "igb1_raw",
					"%interface": "WAN",
					"direction": "in",
					"protocol": "TCP",
					"enabled": "1"
				}
			]
		}`))
	})

	data, err := client.FetchFirewallRuleStats(true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(data.Rules))
	}

	// Find rules by UUID
	ruleMap := make(map[string]FirewallRuleStats)
	for _, r := range data.Rules {
		ruleMap[r.UUID] = r
	}

	// uuid-rule-1 should have details merged
	rule1, ok := ruleMap["uuid-rule-1"]
	if !ok {
		t.Fatal("uuid-rule-1 not found")
	}
	if rule1.Description != "Allow HTTP" {
		t.Errorf("expected Description='Allow HTTP', got %q", rule1.Description)
	}
	if rule1.Action != "pass" {
		t.Errorf("expected Action='pass', got %q", rule1.Action)
	}
	if rule1.Interface != "LAN" {
		t.Errorf("expected Interface='LAN' (from %%interface), got %q", rule1.Interface)
	}
	if rule1.Direction != "in" {
		t.Errorf("expected Direction='in', got %q", rule1.Direction)
	}
	if rule1.Packets != 5000 {
		t.Errorf("expected Packets=5000, got %d", rule1.Packets)
	}

	// uuid-system-rule should have "system" description (not in search results)
	sysRule, ok := ruleMap["uuid-system-rule"]
	if !ok {
		t.Fatal("uuid-system-rule not found")
	}
	if sysRule.Description != "system" {
		t.Errorf("expected Description='system' for unmatched rule, got %q", sysRule.Description)
	}
	if sysRule.Action != "" {
		t.Errorf("expected empty Action for unmatched rule, got %q", sysRule.Action)
	}
}

func TestFetchFirewallRuleStats_StatsEndpointError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchFirewallRuleStats(false)
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestFetchFirewallRuleStats_RulesEndpointError(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	// Stats endpoint succeeds
	mux.HandleFunc("/api/firewall/filter_util/rule_stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"stats": {
				"uuid-rule-1": {"pf_rules": 1, "evaluations": 100, "packets": 5000, "bytes": 2000000, "states": 25}
			}
		}`))
	})

	// Rules search endpoint fails
	mux.HandleFunc("/api/firewall/filter/search_rule", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})

	_, err := client.FetchFirewallRuleStats(true)
	if err == nil {
		t.Fatal("expected error when rules endpoint fails with details enabled")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
