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
}
