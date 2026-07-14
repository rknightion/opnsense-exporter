package opnsense

import (
	"net/http"
	"testing"
)

// ruleIDsRows are the rule-id entries as OPNsense's `filter list rule_ids`
// configd command emits them: ids are EITHER an undashed 32-hex content hash
// (auto/system rules: anti-lockout, default-deny, bogons) OR a dashed rule UUID
// (user-authored rules). filterlog's "rid" can be either, so both must survive.
const ruleIDsRows = `
  {"id":"60533d555322b9f6a009f71c1c471480","descr":"anti-lockout rule"},
  {"id":"66ae5388-c7b8-4ccc-a1ae-da7803f57158","descr":"TESTLAN allow all"}
`

func assertRuleIDs(t *testing.T, ids []FirewallRuleID) {
	t.Helper()
	if len(ids) != 2 {
		t.Fatalf("got %d rule ids, want 2", len(ids))
	}
	if ids[0].ID != "60533d555322b9f6a009f71c1c471480" || ids[0].Descr != "anti-lockout rule" {
		t.Errorf("system rule mis-parsed: %+v", ids[0])
	}
	if ids[1].ID != "66ae5388-c7b8-4ccc-a1ae-da7803f57158" || ids[1].Descr != "TESTLAN allow all" {
		t.Errorf("user rule mis-parsed: %+v", ids[1])
	}
}

// The documented shape: OPNsense core's listRuleIdsAction wraps the configd
// output as {"items": [...]} on both releases in the support window.
func TestFetchFirewallRuleIDs_Enveloped(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items": [` + ruleIDsRows + `]}`))
	})
	defer server.Close()

	ids, err := client.FetchFirewallRuleIDs()
	if err != nil {
		t.Fatalf("FetchFirewallRuleIDs: %v", err)
	}
	assertRuleIDs(t, ids)
}

// The tolerant path: a bare top-level array (the unwrapped configd output) must
// parse too, rather than silently leaving every log line unlabelled.
func TestFetchFirewallRuleIDs_BareArray(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[` + ruleIDsRows + `]`))
	})
	defer server.Close()

	ids, err := client.FetchFirewallRuleIDs()
	if err != nil {
		t.Fatalf("FetchFirewallRuleIDs: %v", err)
	}
	assertRuleIDs(t, ids)
}

// An empty ruleset is an empty slice, not an error — in either shape.
func TestFetchFirewallRuleIDs_Empty(t *testing.T) {
	for name, payload := range map[string]string{
		"enveloped": `{"items": []}`,
		"bare":      `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(payload))
			})
			defer server.Close()

			ids, err := client.FetchFirewallRuleIDs()
			if err != nil {
				t.Fatalf("FetchFirewallRuleIDs: %v", err)
			}
			if len(ids) != 0 {
				t.Fatalf("got %d rule ids, want 0", len(ids))
			}
		})
	}
}

func TestFetchFirewallRuleIDs_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("error"))
	})
	defer server.Close()

	if _, err := client.FetchFirewallRuleIDs(); err == nil {
		t.Fatal("expected error for server error response")
	} else if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
