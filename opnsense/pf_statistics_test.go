package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchPFStatistics_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/diagnostics/firewall/pf_statistics/info", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"info": {
				"state-table": {
					"current-entries": {"total": 14132},
					"searches": {"total": 28296058526, "rate": 13020.3},
					"inserts": {"total": 85139478, "rate": 39.2},
					"removals": {"total": 85126962, "rate": 39.2}
				},
				"source-tracking-table": {
					"current-entries": {"total": 0},
					"searches": {"total": 0, "rate": 0},
					"inserts": {"total": 0, "rate": 0},
					"removals": {"total": 0, "rate": 0}
				},
				"counters": {
					"match": {"total": 108547746, "rate": 49.9},
					"bad-offset": {"total": 0, "rate": 0},
					"fragment": {"total": 62, "rate": 0},
					"short": {"total": 0, "rate": 0},
					"normalize": {"total": 22, "rate": 0},
					"memory": {"total": 0, "rate": 0},
					"bad-timestamp": {"total": 0, "rate": 0},
					"congestion": {"total": 0, "rate": 0},
					"ip-option": {"total": 23528, "rate": 0},
					"proto-cksum": {"total": 0, "rate": 0},
					"state-mismatch": {"total": 875943, "rate": 0.4},
					"state-insert": {"total": 1623, "rate": 0},
					"state-limit": {"total": 0, "rate": 0},
					"src-limit": {"total": 0, "rate": 0},
					"synproxy": {"total": 0, "rate": 0},
					"map-failed": {"total": 52804, "rate": 0}
				},
				"limit-counters": {
					"max-states-per-rule": {"total": 0, "rate": 0},
					"max-src-states": {"total": 0, "rate": 0},
					"max-src-nodes": {"total": 0, "rate": 0},
					"max-src-conn": {"total": 0, "rate": 0},
					"max-src-conn-rate": {"total": 0, "rate": 0},
					"overload-table-insertion": {"total": 0, "rate": 0},
					"overload-flush-states": {"total": 0, "rate": 0},
					"synfloods-detected": {"total": 0, "rate": 0},
					"syncookies-sent": {"total": 0, "rate": 0},
					"syncookies-validated": {"total": 0, "rate": 0}
				}
			}
		}`))
	})

	mux.HandleFunc("/api/diagnostics/firewall/pf_statistics/memory", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{"memory": {"states": 3257500, "src-nodes": 3257500, "frags": 5000, "table-entries": 10000000}}`))
	})

	mux.HandleFunc("/api/diagnostics/firewall/pf_statistics/timeouts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{"timeouts": {
			"tcp.first": "3600s",
			"tcp.opening": "900s",
			"tcp.established": "432000s",
			"tcp.closing": "3600s",
			"tcp.finwait": "600s",
			"tcp.closed": "180s",
			"tcp.tsdiff": "60s",
			"sctp.first": "120s",
			"sctp.opening": "30s",
			"sctp.established": "86400s",
			"sctp.closing": "900s",
			"sctp.closed": "90s",
			"udp.first": "300s",
			"udp.single": "150s",
			"udp.multiple": "900s",
			"icmp.first": "20s",
			"icmp.error": "10s",
			"other.first": "60s",
			"other.single": "30s",
			"other.multiple": "60s",
			"frag": "30s",
			"interval": "10s",
			"adaptive.start": "0 states",
			"adaptive.end": "0 states",
			"src.track": "0s"
		}}`))
	})

	data, err := client.FetchPFStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// State table
	if data.StateTableEntries != 14132 {
		t.Errorf("expected StateTableEntries=14132, got %d", data.StateTableEntries)
	}
	if data.StateTableSearches != 28296058526 {
		t.Errorf("expected StateTableSearches=28296058526, got %f", data.StateTableSearches)
	}
	if data.StateTableInserts != 85139478 {
		t.Errorf("expected StateTableInserts=85139478, got %f", data.StateTableInserts)
	}
	if data.StateTableRemovals != 85126962 {
		t.Errorf("expected StateTableRemovals=85126962, got %f", data.StateTableRemovals)
	}

	// Source tracking table
	if data.SourceTrackingEntries != 0 {
		t.Errorf("expected SourceTrackingEntries=0, got %d", data.SourceTrackingEntries)
	}

	// Counters
	if len(data.Counters) != 16 {
		t.Errorf("expected 16 counters, got %d", len(data.Counters))
	}
	expectedCounters := map[string]float64{
		"match":          108547746,
		"bad-offset":     0,
		"fragment":       62,
		"short":          0,
		"normalize":      22,
		"memory":         0,
		"bad-timestamp":  0,
		"congestion":     0,
		"ip-option":      23528,
		"proto-cksum":    0,
		"state-mismatch": 875943,
		"state-insert":   1623,
		"state-limit":    0,
		"src-limit":      0,
		"synproxy":       0,
		"map-failed":     52804,
	}
	for name, want := range expectedCounters {
		if got := data.Counters[name]; got != want {
			t.Errorf("Counters[%q] = %f; want %f", name, got, want)
		}
	}

	// Limit counters
	if len(data.LimitCounters) != 10 {
		t.Errorf("expected 10 limit counters, got %d", len(data.LimitCounters))
	}
	expectedLimitCounters := map[string]float64{
		"max-states-per-rule":      0,
		"max-src-states":           0,
		"max-src-nodes":            0,
		"max-src-conn":             0,
		"max-src-conn-rate":        0,
		"overload-table-insertion": 0,
		"overload-flush-states":    0,
		"synfloods-detected":       0,
		"syncookies-sent":          0,
		"syncookies-validated":     0,
	}
	for name, want := range expectedLimitCounters {
		if got := data.LimitCounters[name]; got != want {
			t.Errorf("LimitCounters[%q] = %f; want %f", name, got, want)
		}
	}

	// Memory limits
	if len(data.MemoryLimits) != 4 {
		t.Errorf("expected 4 memory limits, got %d", len(data.MemoryLimits))
	}
	expectedMemory := map[string]int{
		"states":        3257500,
		"src-nodes":     3257500,
		"frags":         5000,
		"table-entries": 10000000,
	}
	for name, want := range expectedMemory {
		if got := data.MemoryLimits[name]; got != want {
			t.Errorf("MemoryLimits[%q] = %d; want %d", name, got, want)
		}
	}

	// Timeouts - should have 23 entries (25 total minus 2 " states" entries)
	if len(data.Timeouts) != 23 {
		t.Errorf("expected 23 timeouts, got %d", len(data.Timeouts))
	}
	expectedTimeouts := map[string]float64{
		"tcp.first":        3600,
		"tcp.opening":      900,
		"tcp.established":  432000,
		"tcp.closing":      3600,
		"tcp.finwait":      600,
		"tcp.closed":       180,
		"tcp.tsdiff":       60,
		"sctp.first":       120,
		"sctp.opening":     30,
		"sctp.established": 86400,
		"sctp.closing":     900,
		"sctp.closed":      90,
		"udp.first":        300,
		"udp.single":       150,
		"udp.multiple":     900,
		"icmp.first":       20,
		"icmp.error":       10,
		"other.first":      60,
		"other.single":     30,
		"other.multiple":   60,
		"frag":             30,
		"interval":         10,
		"src.track":        0,
	}
	for name, want := range expectedTimeouts {
		if got := data.Timeouts[name]; got != want {
			t.Errorf("Timeouts[%q] = %f; want %f", name, got, want)
		}
	}

	// Verify "states" entries are skipped
	if _, exists := data.Timeouts["adaptive.start"]; exists {
		t.Error("expected adaptive.start to be skipped (ends with ' states')")
	}
	if _, exists := data.Timeouts["adaptive.end"]; exists {
		t.Error("expected adaptive.end to be skipped (ends with ' states')")
	}
}

func TestFetchPFStatistics_PartialFailure(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	// Info endpoint fails
	mux.HandleFunc("/api/diagnostics/firewall/pf_statistics/info", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})

	// Memory endpoint succeeds
	mux.HandleFunc("/api/diagnostics/firewall/pf_statistics/memory", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"memory": {"states": 1000, "src-nodes": 2000, "frags": 500, "table-entries": 5000}}`))
	})

	// Timeouts endpoint succeeds
	mux.HandleFunc("/api/diagnostics/firewall/pf_statistics/timeouts", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"timeouts": {"tcp.first": "3600s", "udp.first": "300s"}}`))
	})

	data, err := client.FetchPFStatistics()
	if err != nil {
		t.Fatalf("expected no error for partial failure, got: %v", err)
	}

	// Memory data should still be populated
	if data.MemoryLimits["states"] != 1000 {
		t.Errorf("expected MemoryLimits[states]=1000, got %d", data.MemoryLimits["states"])
	}
	if data.MemoryLimits["src-nodes"] != 2000 {
		t.Errorf("expected MemoryLimits[src-nodes]=2000, got %d", data.MemoryLimits["src-nodes"])
	}

	// Timeouts should still be populated
	if data.Timeouts["tcp.first"] != 3600 {
		t.Errorf("expected Timeouts[tcp.first]=3600, got %f", data.Timeouts["tcp.first"])
	}
	if data.Timeouts["udp.first"] != 300 {
		t.Errorf("expected Timeouts[udp.first]=300, got %f", data.Timeouts["udp.first"])
	}

	// Info data should be zero-valued (nil maps, zero ints)
	if data.StateTableEntries != 0 {
		t.Errorf("expected StateTableEntries=0, got %d", data.StateTableEntries)
	}
	if data.Counters != nil {
		t.Errorf("expected Counters to be nil when info endpoint fails")
	}
}

func TestFetchPFStatistics_AllFail(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	failHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	}

	mux.HandleFunc("/api/diagnostics/firewall/pf_statistics/info", failHandler)
	mux.HandleFunc("/api/diagnostics/firewall/pf_statistics/memory", failHandler)
	mux.HandleFunc("/api/diagnostics/firewall/pf_statistics/timeouts", failHandler)

	_, err := client.FetchPFStatistics()
	if err == nil {
		t.Fatal("expected error when all sub-calls fail")
	}
}
