package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchVnstat_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/vnstat/service/interface_list", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET for interface_list, got %s", r.Method)
		}
		_, _ = w.Write([]byte(`{"interfaces":["vtnet1","vtnet2"]}`))
	})

	mux.HandleFunc("/api/vnstat/service/get_json_data", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET for get_json_data, got %s", r.Method)
		}
		iface := r.URL.Query().Get("iface")
		switch iface {
		case "vtnet1":
			// Real WAN capture (#215 dev-box, 2026-07-13).
			_, _ = w.Write([]byte(`{"vnstatversion":"2.13","jsonversion":"2","interfaces":[{"name":"vtnet1","alias":"","updated":{"date":{"year":2026,"month":7,"day":13},"time":{"hour":18,"minute":31},"timestamp":1783963860},"traffic":{"total":{"rx":4820720,"tx":5762},"day":[{"id":4,"date":{"year":2026,"month":7,"day":13},"timestamp":1783897200,"rx":4820720,"tx":5762}],"month":[{"id":4,"date":{"year":2026,"month":7},"timestamp":1782860400,"rx":4820720,"tx":5762}]}}]}`))
		case "vtnet2":
			// Real TESTLAN capture (#215 dev-box, 2026-07-13).
			_, _ = w.Write([]byte(`{"vnstatversion":"2.13","jsonversion":"2","interfaces":[{"name":"vtnet2","alias":"","updated":{"date":{"year":2026,"month":7,"day":13},"time":{"hour":18,"minute":31},"timestamp":1783963860},"traffic":{"total":{"rx":41070,"tx":130480},"day":[{"id":3,"date":{"year":2026,"month":7,"day":13},"timestamp":1783897200,"rx":41070,"tx":130480}],"month":[{"id":3,"date":{"year":2026,"month":7},"timestamp":1782860400,"rx":41070,"tx":130480}]}}]}`))
		default:
			t.Errorf("unexpected iface %q in get_json_data request", iface)
			w.WriteHeader(http.StatusBadRequest)
		}
	})

	data, err := client.FetchVnstat()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if len(data.Interfaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(data.Interfaces))
	}

	byName := map[string]VnstatInterface{}
	for _, iface := range data.Interfaces {
		byName[iface.Name] = iface
	}

	wan, ok := byName["vtnet1"]
	if !ok {
		t.Fatal("expected vtnet1 in results")
	}
	if wan.TotalRXBytes != 4820720 || wan.TotalTXBytes != 5762 {
		t.Errorf("vtnet1 total = rx=%d tx=%d, want rx=4820720 tx=5762", wan.TotalRXBytes, wan.TotalTXBytes)
	}
	if wan.CurrentDayRXBytes != 4820720 || wan.CurrentDayTXBytes != 5762 {
		t.Errorf("vtnet1 day = rx=%d tx=%d, want rx=4820720 tx=5762", wan.CurrentDayRXBytes, wan.CurrentDayTXBytes)
	}
	if wan.CurrentMonthRXBytes != 4820720 || wan.CurrentMonthTXBytes != 5762 {
		t.Errorf("vtnet1 month = rx=%d tx=%d, want rx=4820720 tx=5762", wan.CurrentMonthRXBytes, wan.CurrentMonthTXBytes)
	}

	testlan, ok := byName["vtnet2"]
	if !ok {
		t.Fatal("expected vtnet2 in results")
	}
	if testlan.TotalRXBytes != 41070 || testlan.TotalTXBytes != 130480 {
		t.Errorf("vtnet2 total = rx=%d tx=%d, want rx=41070 tx=130480", testlan.TotalRXBytes, testlan.TotalTXBytes)
	}
}

// The day/month arrays can hold multiple historical buckets; FetchVnstat must
// pick the one matching vnstat's own "updated" date rather than assuming the
// array's last element is the current one.
func TestFetchVnstat_PicksCurrentBucketByDate_NotArrayOrder(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/vnstat/service/interface_list", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"interfaces":["vtnet1"]}`))
	})

	// "updated" says 2026-07-13, but the day/month arrays deliberately list an
	// out-of-order/older-looking entry last, to prove the match is by date
	// rather than by trusting the final array element.
	mux.HandleFunc("/api/vnstat/service/get_json_data", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"vnstatversion":"2.13","jsonversion":"2",
			"interfaces":[{
				"name":"vtnet1",
				"updated":{"date":{"year":2026,"month":7,"day":13}},
				"traffic":{
					"total":{"rx":999,"tx":888},
					"day":[
						{"date":{"year":2026,"month":7,"day":13},"rx":500,"tx":600},
						{"date":{"year":2026,"month":7,"day":12},"rx":100,"tx":200}
					],
					"month":[
						{"date":{"year":2026,"month":7},"rx":700,"tx":800},
						{"date":{"year":2026,"month":6},"rx":10,"tx":20}
					]
				}
			}]
		}`))
	})

	data, err := client.FetchVnstat()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Interfaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(data.Interfaces))
	}
	got := data.Interfaces[0]
	if got.CurrentDayRXBytes != 500 || got.CurrentDayTXBytes != 600 {
		t.Errorf("day bucket = rx=%d tx=%d, want the 07-13 entry (rx=500 tx=600), not the last array element",
			got.CurrentDayRXBytes, got.CurrentDayTXBytes)
	}
	if got.CurrentMonthRXBytes != 700 || got.CurrentMonthTXBytes != 800 {
		t.Errorf("month bucket = rx=%d tx=%d, want the 07 entry (rx=700 tx=800), not the last array element",
			got.CurrentMonthRXBytes, got.CurrentMonthTXBytes)
	}
}

// A freshly created vnstat DB entry (no traffic recorded yet) reports zeroed
// totals and empty day/month arrays. FetchVnstat must not error or panic, and
// should simply report zeros.
func TestFetchVnstat_EmptyDB(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/vnstat/service/interface_list", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"interfaces":["vtnet3"]}`))
	})
	mux.HandleFunc("/api/vnstat/service/get_json_data", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"vnstatversion":"2.13","jsonversion":"2",
			"interfaces":[{
				"name":"vtnet3",
				"updated":{"date":{"year":2026,"month":7,"day":13}},
				"traffic":{"total":{"rx":0,"tx":0},"day":[],"month":[]}
			}]
		}`))
	})

	data, err := client.FetchVnstat()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Interfaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(data.Interfaces))
	}
	got := data.Interfaces[0]
	if got.TotalRXBytes != 0 || got.TotalTXBytes != 0 ||
		got.CurrentDayRXBytes != 0 || got.CurrentDayTXBytes != 0 ||
		got.CurrentMonthRXBytes != 0 || got.CurrentMonthTXBytes != 0 {
		t.Errorf("expected all-zero figures for an empty DB entry, got %+v", got)
	}
}

// os-vnstat plugin not installed: interface_list 404s. FetchVnstat must treat
// this as feature-absent (Present=false, no error), matching every other
// plugin-gated Fetch* in this package.
func TestFetchVnstat_PluginAbsent(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/vnstat/service/interface_list", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	mux.HandleFunc("/api/vnstat/service/get_json_data", func(w http.ResponseWriter, _ *http.Request) {
		t.Error("get_json_data must not be called when interface_list 404s")
	})

	data, err := client.FetchVnstat()
	if err != nil {
		t.Fatalf("expected no error for an absent plugin, got %v", err)
	}
	if data.Present {
		t.Error("expected Present=false")
	}
	if len(data.Interfaces) != 0 {
		t.Errorf("expected no interfaces, got %d", len(data.Interfaces))
	}
}

// One interface's get_json_data call failing (e.g. a transient 500, or an
// interface vnstat's DB no longer recognizes) must only skip that interface,
// not abort the whole fetch — mirroring FetchSMARTDevices's per-device
// tolerance.
func TestFetchVnstat_PerInterfaceFailureIsSkipped(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/vnstat/service/interface_list", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"interfaces":["good0","bad0"]}`))
	})
	mux.HandleFunc("/api/vnstat/service/get_json_data", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("iface") {
		case "good0":
			_, _ = w.Write([]byte(`{
				"interfaces":[{
					"name":"good0",
					"updated":{"date":{"year":2026,"month":7,"day":13}},
					"traffic":{"total":{"rx":10,"tx":20},"day":[{"date":{"year":2026,"month":7,"day":13},"rx":10,"tx":20}],"month":[{"date":{"year":2026,"month":7},"rx":10,"tx":20}]}
				}]
			}`))
		case "bad0":
			http.Error(w, "boom", http.StatusInternalServerError)
		}
	})

	data, err := client.FetchVnstat()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true (list succeeded)")
	}
	if len(data.Interfaces) != 1 {
		t.Fatalf("expected 1 interface (bad0 skipped), got %d", len(data.Interfaces))
	}
	if data.Interfaces[0].Name != "good0" {
		t.Errorf("expected good0 to survive, got %q", data.Interfaces[0].Name)
	}
}
