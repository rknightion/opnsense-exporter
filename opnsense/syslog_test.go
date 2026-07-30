package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchSyslogStats_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/syslog/service/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"total": 6,
			"rowCount": 6,
			"current": 1,
			"rows": [
				{"#":"e4a8a66","Description":"","SourceName":"destination","SourceId":"d_local_firewall","SourceInstance":"","State":"a","Type":"processed","Number":"180"},
				{"#":"211e4c1","Description":"","SourceName":"global","SourceId":"internal_source","SourceInstance":"","State":"a","Type":"dropped","Number":"0"},
				{"#":"92b5447","Description":"","SourceName":"global","SourceId":"scratch_buffers_count","SourceInstance":"","State":"a","Type":"queued","Number":"3"},
				{"#":"fbf008d","Description":"","SourceName":"dst.program","SourceId":"d_config_changed_event#0","SourceInstance":"/usr/local/sbin/configctl -e -t 0.5 system event config_changed","State":"a","Type":"truncated_count","Number":"0"},
				{"#":"aa11bb2","Description":"","SourceName":"center","SourceId":"","SourceInstance":"received","State":"a","Type":"eps_last_1h","Number":"12"},
				{"#":"cc33dd4","Description":"","SourceName":"global","SourceId":"msg_clones","SourceInstance":"","State":"a","Type":"stamp","Number":"1765320000"}
			]
		}`))
	})

	data, err := client.FetchSyslogStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Total != 6 {
		t.Errorf("expected Total=6, got %d", data.Total)
	}
	// "stamp" row is skipped -> 5 stats
	if len(data.Stats) != 5 {
		t.Fatalf("expected 5 stats, got %d", len(data.Stats))
	}
	s0 := data.Stats[0]
	if s0.SourceName != "destination" || s0.SourceID != "d_local_firewall" || s0.Type != "processed" || s0.Value != 180 {
		t.Errorf("unexpected first stat: %+v", s0)
	}
	s3 := data.Stats[3]
	if s3.SourceInstance != "/usr/local/sbin/configctl -e -t 0.5 system event config_changed" {
		t.Errorf("expected SourceInstance preserved, got %q", s3.SourceInstance)
	}

	// Every row in the fixture (including the skipped "stamp" row) carries
	// State "a" -> canonicalized "active", and target states are deduped by
	// (SourceName, SourceID, SourceInstance) -- 6 distinct rows, 6 distinct
	// targets.
	if len(data.TargetStates) != 6 {
		t.Fatalf("expected 6 target states (one per distinct source), got %d: %+v", len(data.TargetStates), data.TargetStates)
	}
	for _, ts := range data.TargetStates {
		if ts.State != "active" {
			t.Errorf("target %+v: State = %q, want active", ts, ts.State)
		}
	}
}

// TestFetchSyslogStats_TargetStateCanonicalization proves the raw single-char
// syslog-ng state codes are canonicalized to a bounded, descriptive
// vocabulary, and anything unrecognized collapses to "unknown" rather than
// passing a raw code (or an empty string) through as a label.
func TestFetchSyslogStats_TargetStateCanonicalization(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/syslog/service/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 4,
			"rowCount": 4,
			"current": 1,
			"rows": [
				{"Description":"","SourceName":"a-src","SourceId":"1","SourceInstance":"","State":"a","Type":"processed","Number":"1"},
				{"Description":"","SourceName":"d-src","SourceId":"2","SourceInstance":"","State":"d","Type":"processed","Number":"1"},
				{"Description":"","SourceName":"o-src","SourceId":"3","SourceInstance":"","State":"o","Type":"processed","Number":"1"},
				{"Description":"","SourceName":"weird-src","SourceId":"4","SourceInstance":"","State":"?","Type":"processed","Number":"1"}
			]
		}`))
	})

	data, err := client.FetchSyslogStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := map[string]string{}
	for _, ts := range data.TargetStates {
		got[ts.SourceName] = ts.State
	}
	want := map[string]string{
		"a-src":     "active",
		"d-src":     "dynamic",
		"o-src":     "orphaned",
		"weird-src": "unknown",
	}
	for src, wantState := range want {
		if got[src] != wantState {
			t.Errorf("target %q: State = %q, want %q", src, got[src], wantState)
		}
	}
}

// TestFetchSyslogStats_TargetStateNeverEmpty proves an empty raw State never
// reaches the label as an empty string -- it must collapse to "unknown".
func TestFetchSyslogStats_TargetStateNeverEmpty(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/syslog/service/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1,
			"rowCount": 1,
			"current": 1,
			"rows": [
				{"Description":"","SourceName":"blank-src","SourceId":"1","SourceInstance":"","State":"","Type":"processed","Number":"1"}
			]
		}`))
	})

	data, err := client.FetchSyslogStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.TargetStates) != 1 || data.TargetStates[0].State != "unknown" {
		t.Errorf("expected a single target state = unknown, got %+v", data.TargetStates)
	}
}
