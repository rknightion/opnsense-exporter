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
