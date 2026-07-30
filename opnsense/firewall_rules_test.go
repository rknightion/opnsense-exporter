package opnsense

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestFirewallRuleStatsResponse_StatsShape covers the PHP empty-array-vs-object
// quirk from #481: OPNsense serializes "stats" as a JSON object when populated
// and as a bare "[]" when there is nothing to report (a freshly-stripped box).
// The populated case is derived from TestFetchFirewallRuleStats_DetailsDisabled's
// fixture above; the empty case is the exact body captured live and quoted in #481.
func TestFirewallRuleStatsResponse_StatsShape(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantLen   int
		wantErr   bool
		wantEval1 int64 // evaluations for "uuid-rule-1", when present
	}{
		{
			name: "populated object form",
			body: `{
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
			}`,
			wantLen:   2,
			wantEval1: 100,
		},
		{
			name:    "empty array form (live capture, #481)",
			body:    `{"status":"ok","stats":[]}`,
			wantLen: 0,
		},
		{
			name:    "non-empty array is an error, not silently absorbed",
			body:    `{"status":"ok","stats":[{"pf_rules":1}]}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp firewallRuleStatsResponse
			err := json.Unmarshal([]byte(tt.body), &resp)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error for non-empty array stats, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(resp.Stats) != tt.wantLen {
				t.Fatalf("expected %d stats entries, got %d", tt.wantLen, len(resp.Stats))
			}
			if tt.wantEval1 != 0 {
				stat, ok := resp.Stats["uuid-rule-1"]
				if !ok {
					t.Fatal("uuid-rule-1 not found in decoded stats")
				}
				if stat.Evaluations != tt.wantEval1 {
					t.Errorf("expected Evaluations=%d, got %d", tt.wantEval1, stat.Evaluations)
				}
			}
		})
	}
}

// TestFetchFirewallRuleStats_EmptyArrayStats reproduces the live failure from
// #481 end-to-end through FetchFirewallRuleStats: a freshly-stripped box returns
// "stats":[] and the collector must report zero rules, not an error.
func TestFetchFirewallRuleStats_EmptyArrayStats(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","stats":[]}`))
	})
	defer server.Close()

	data, err := client.FetchFirewallRuleStats(false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(data.Rules))
	}
}

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
		if rule.Protocol != "unknown" {
			t.Errorf("expected Protocol='unknown' when details disabled, got %q", rule.Protocol)
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

// TestFetchFirewallRuleStats_ProtocolNormalization covers #558: Protocol is
// decoded from the search_rule payload and normalized to a bounded, lowercase
// label. Mixed-case API values ("TCP") must compare equal to their lowercase
// form, and a rule with no search-result match (or an empty/whitespace
// protocol) must get the "unknown" sentinel rather than an empty label.
func TestFetchFirewallRuleStats_ProtocolNormalization(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/firewall/filter_util/rule_stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"stats": {
				"uuid-tcp": {"pf_rules": 1, "evaluations": 1, "packets": 1, "bytes": 1, "states": 1},
				"uuid-any": {"pf_rules": 1, "evaluations": 1, "packets": 1, "bytes": 1, "states": 1},
				"uuid-blank": {"pf_rules": 1, "evaluations": 1, "packets": 1, "bytes": 1, "states": 1},
				"uuid-system": {"pf_rules": 1, "evaluations": 1, "packets": 1, "bytes": 1, "states": 1}
			}
		}`))
	})
	mux.HandleFunc("/api/firewall/filter/search_rule", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 3, "rowCount": 3, "current": 1,
			"rows": [
				{"uuid": "uuid-tcp", "description": "d", "action": "pass", "interface": "lan", "%interface": "LAN", "direction": "in", "protocol": "TCP", "enabled": "1"},
				{"uuid": "uuid-any", "description": "d", "action": "pass", "interface": "lan", "%interface": "LAN", "direction": "in", "protocol": "any", "enabled": "1"},
				{"uuid": "uuid-blank", "description": "d", "action": "pass", "interface": "lan", "%interface": "LAN", "direction": "in", "protocol": "  ", "enabled": "1"}
			]
		}`))
	})

	data, err := client.FetchFirewallRuleStats(true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	byUUID := make(map[string]FirewallRuleStats, len(data.Rules))
	for _, r := range data.Rules {
		byUUID[r.UUID] = r
	}

	tests := []struct {
		uuid string
		want string
	}{
		{"uuid-tcp", "tcp"},        // mixed-case API value lowercased
		{"uuid-any", "any"},        // genuine "any" value passed through
		{"uuid-blank", "unknown"},  // whitespace-only protocol -> sentinel
		{"uuid-system", "unknown"}, // no search-result match at all -> sentinel
	}
	for _, tt := range tests {
		rule, ok := byUUID[tt.uuid]
		if !ok {
			t.Fatalf("%s not found in decoded rules", tt.uuid)
		}
		if rule.Protocol != tt.want {
			t.Errorf("%s: expected Protocol=%q, got %q", tt.uuid, tt.want, rule.Protocol)
		}
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

func TestFetchFirewallRuleStats_ConfiguredCounts(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

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

	data, err := client.FetchFirewallRuleStats(true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.ConfiguredRulesEnabled != 2 {
		t.Errorf("expected 2 enabled configured rules, got %d", data.ConfiguredRulesEnabled)
	}
	// uuid-2 (enabled "0") AND uuid-4 (empty enabled): only an explicit "1"
	// counts as enabled — parseStringToBool("") would wrongly return true.
	if data.ConfiguredRulesDisabled != 2 {
		t.Errorf("expected 2 disabled configured rules, got %d", data.ConfiguredRulesDisabled)
	}
}

func TestFetchFirewallRuleStats_NoConfiguredCountsWithoutDetails(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/firewall/filter_util/rule_stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "ok", "stats": {}}`))
	})
	mux.HandleFunc("/api/firewall/filter/search_rule", func(w http.ResponseWriter, r *http.Request) {
		t.Error("search_rule must not be called when details are disabled")
	})

	data, err := client.FetchFirewallRuleStats(false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.ConfiguredRulesEnabled != 0 || data.ConfiguredRulesDisabled != 0 {
		t.Errorf("expected zero configured counts without details, got %+v", data)
	}
}
