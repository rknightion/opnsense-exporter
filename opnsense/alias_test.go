package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchAliasTables_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/firewall/alias/get_table_size", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"status": "ok",
			"size": 10000000,
			"used": 664955,
			"details": {
				"GeoIP_UK": {"count":48827,"updated":"2026-06-06T02:33:02.425908","eval_nomatch":67332,"eval_match":152366,"in_block_p":210,"in_block_b":13304,"in_pass_p":1246181,"in_pass_b":84159393,"out_block_p":0,"out_block_b":0,"out_pass_p":14249422,"out_pass_b":21206874727},
				"bogons":   {"count":2945,"updated":null,"eval_nomatch":1035290,"eval_match":3272,"in_block_p":3272,"in_block_b":104704,"in_pass_p":0,"in_pass_b":0,"out_block_p":0,"out_block_b":0,"out_pass_p":0,"out_pass_b":0},
				"__lan_network": {"count":2,"updated":null,"eval_nomatch":0,"eval_match":0,"in_block_p":0,"in_block_b":0,"in_pass_p":0,"in_pass_b":0,"out_block_p":0,"out_block_b":0,"out_pass_p":0,"out_pass_b":0}
			}
		}`))
	})

	data, err := client.FetchAliasTables()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Used != 664955 || data.Limit != 10000000 {
		t.Errorf("unexpected used/limit: %v/%v", data.Used, data.Limit)
	}
	if len(data.Tables) != 3 {
		t.Fatalf("expected 3 tables, got %d", len(data.Tables))
	}
	byName := map[string]AliasTable{}
	for _, tb := range data.Tables {
		byName[tb.Name] = tb
	}
	g := byName["GeoIP_UK"]
	if g.Entries != 48827 || g.EvalMatch != 152366 || g.EvalNomatch != 67332 {
		t.Errorf("unexpected GeoIP_UK counts: %+v", g)
	}
	if g.InBlockP != 210 || g.InBlockB != 13304 || g.OutPassB != 21206874727 {
		t.Errorf("unexpected GeoIP_UK pf counters: %+v", g)
	}
	if _, ok := byName["__lan_network"]; !ok {
		t.Error("internal __ tables must be kept")
	}
}

// TestFetchAliasTables_Updated pins the #583 per-table last-refresh decode.
//
// Wire evidence: OPNsense core src/opnsense/scripts/filter/pftablecount.py:69-82
// (identical on stable/26.1 and stable/26.7) sets
//
//	table_updated = None
//	if os.path.isfile("/var/db/aliastables/<table>.txt"):
//	    table_updated = datetime.fromtimestamp(os.path.getmtime(filename)).isoformat()
//	result['details'][table]['updated'] = table_updated
//
// so the key is ALWAYS present but is JSON null for every table with no
// persisted file (i.e. every table that is not a DNS- or URL-backed alias),
// and a naive local-time ISO-8601 string — microseconds included, because
// getmtime returns a float — otherwise.
func TestFetchAliasTables_Updated(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok", "size": 1000000, "used": 12,
			"details": {
				"threatfeed":  {"count": 10, "updated": "2026-07-30T04:15:03.123456"},
				"wholesecond": {"count": 1,  "updated": "2026-07-30T04:15:03"},
				"static":      {"count": 1,  "updated": null},
				"nokey":       {"count": 0},
				"garbage":     {"count": 0,  "updated": "not-a-timestamp"}
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchAliasTables()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	byName := map[string]AliasTable{}
	for _, tb := range data.Tables {
		byName[tb.Name] = tb
	}
	if len(byName) != 5 {
		t.Fatalf("expected 5 tables, got %d", len(byName))
	}

	// 2026-07-30T04:15:03 read as UTC.
	const wantEpoch = 1785384903

	if tb := byName["threatfeed"]; !tb.HasUpdated || tb.UpdatedTimestamp != wantEpoch {
		t.Errorf("threatfeed: got %v/%v, want %v/true", tb.UpdatedTimestamp, tb.HasUpdated, float64(wantEpoch))
	}
	if tb := byName["wholesecond"]; !tb.HasUpdated || tb.UpdatedTimestamp != wantEpoch {
		t.Errorf("wholesecond: got %v/%v, want %v/true", tb.UpdatedTimestamp, tb.HasUpdated, float64(wantEpoch))
	}
	// null / absent / unparseable must all read as "no refresh time known".
	// Emitting epoch 0 here would make every static table look 56 years stale
	// and false-fire a not-refreshed-recently alert on data that has no
	// refresh cycle at all.
	for _, name := range []string{"static", "nokey", "garbage"} {
		if tb := byName[name]; tb.HasUpdated {
			t.Errorf("%s: expected HasUpdated=false, got %v (%v)", name, tb.HasUpdated, tb.UpdatedTimestamp)
		}
	}
}
