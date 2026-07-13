package opnsense

import (
	"net/http"
	"testing"
)

// TestFetchFirewallNATRuleCounts_Mixed exercises all four endpoints in one
// pass against sanitised shapes captured from a live OPNsense 26.7-devel box
// (#221): source_nat carries 5 enabled + 1 disabled rows (the "enabled"
// field), d_nat carries 3 enabled (lockout rules) + 1 disabled row (the
// inverted "disabled" field), one_to_one carries a single enabled row, and
// npt carries a single enabled row.
func TestFetchFirewallNATRuleCounts_Mixed(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		switch r.URL.Path {
		case "/api/firewall/source_nat/search_rule":
			w.Write([]byte(`{"total":6,"rowCount":6,"current":1,"rows":[
				{"uuid":"a","enabled":"1"},
				{"uuid":"b","enabled":"0"},
				{"uuid":"automatic_isakmp_wan","enabled":"1"},
				{"uuid":"automatic_wan","enabled":"1"},
				{"uuid":"automatic_isakmp_lan","enabled":"1"},
				{"uuid":"automatic_lan","enabled":"1"}
			]}`))
		case "/api/firewall/d_nat/search_rule":
			w.Write([]byte(`{"rows":[
				{"uuid":"lockout_2","disabled":"0"},
				{"uuid":"lockout_1","disabled":"0"},
				{"uuid":"lockout_0","disabled":"0"},
				{"uuid":"c","disabled":"1"}
			],"rowCount":1,"total":1,"current":1}`))
		case "/api/firewall/one_to_one/search_rule":
			w.Write([]byte(`{"rows":[{"uuid":"d","enabled":"1"}],"rowCount":1,"total":1,"current":1}`))
		case "/api/firewall/npt/search_rule":
			w.Write([]byte(`{"rows":[{"uuid":"e","enabled":"1"}],"rowCount":1,"total":1,"current":1}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})
	defer server.Close()

	counts, err := client.FetchFirewallNATRuleCounts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(counts) != 4 {
		t.Fatalf("expected 4 NAT types, got %d", len(counts))
	}

	byType := make(map[string]NATRuleCounts, len(counts))
	for _, c := range counts {
		byType[c.Type] = c
	}

	want := map[string]NATRuleCounts{
		"source_nat": {Type: "source_nat", Enabled: 5, Disabled: 1},
		"d_nat":      {Type: "d_nat", Enabled: 3, Disabled: 1},
		"one_to_one": {Type: "one_to_one", Enabled: 1, Disabled: 0},
		"npt":        {Type: "npt", Enabled: 1, Disabled: 0},
	}

	for typeName, wantCounts := range want {
		got, ok := byType[typeName]
		if !ok {
			t.Fatalf("missing NAT type %q in result", typeName)
		}
		if got != wantCounts {
			t.Errorf("type %q: expected %+v, got %+v", typeName, wantCounts, got)
		}
	}
}

// TestFetchFirewallNATRuleCounts_Empty covers every endpoint returning no
// rows (no NAT rules of that type configured at all).
func TestFetchFirewallNATRuleCounts_Empty(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	defer server.Close()

	counts, err := client.FetchFirewallNATRuleCounts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(counts) != 4 {
		t.Fatalf("expected 4 NAT types, got %d", len(counts))
	}
	for _, c := range counts {
		if c.Enabled != 0 || c.Disabled != 0 {
			t.Errorf("type %q: expected zero counts, got %+v", c.Type, c)
		}
	}
}

// TestFetchFirewallNATRuleCounts_ServerError covers a mid-fanout failure: the
// first endpoint (source_nat) fails, and the fetch must bail out with that
// error rather than silently returning partial counts.
func TestFetchFirewallNATRuleCounts_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchFirewallNATRuleCounts()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
