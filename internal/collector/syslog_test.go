package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestSyslogCollector_Update(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/syslog/service/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 7, "rowCount": 7, "current": 1,
			"rows": [
				{"#":"a1","SourceName":"destination","SourceId":"d_local_firewall","SourceInstance":"","State":"a","Type":"processed","Number":"180"},
				{"#":"a2","SourceName":"global","SourceId":"internal_source","SourceInstance":"","State":"a","Type":"dropped","Number":"2"},
				{"#":"a3","SourceName":"global","SourceId":"scratch_buffers_count","SourceInstance":"","State":"a","Type":"queued","Number":"3"},
				{"#":"a4","SourceName":"dst.file","SourceId":"d_local_system","SourceInstance":"/var/log/system.log","State":"a","Type":"written","Number":"42"},
				{"#":"a5","SourceName":"center","SourceId":"","SourceInstance":"received","State":"a","Type":"eps_last_1h","Number":"12"},
				{"#":"a6","SourceName":"global","SourceId":"payload_reallocs","SourceInstance":"","State":"a","Type":"msg_size_avg","Number":"128"},
				{"#":"a7","SourceName":"global","SourceId":"x","SourceInstance":"","State":"a","Type":"some_future_type","Number":"9"}
			]
		}`))
	})
	mux.HandleFunc("/api/syslog/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &syslogCollector{subsystem: SyslogSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 6 stat rows emitted (unknown type skipped) + service_running = 7
	if len(metrics) != 7 {
		t.Fatalf("expected 7 metrics, got %d", len(metrics))
	}

	var sawProcessed, sawEPS, sawMsgSize, sawRunning bool
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		switch {
		case strings.Contains(desc, "syslog_processed_total"):
			sawProcessed = true
			if getMetricValue(m) != 180 || labels["source_id"] != "d_local_firewall" {
				t.Errorf("bad processed metric: value=%v labels=%v", getMetricValue(m), labels)
			}
		case strings.Contains(desc, "syslog_events_per_second"):
			sawEPS = true
			if labels["window"] != "1h" {
				t.Errorf("expected window=1h, got %v", labels)
			}
		case strings.Contains(desc, "syslog_message_size_bytes"):
			sawMsgSize = true
			if labels["stat"] != "avg" {
				t.Errorf("expected stat=avg, got %v", labels)
			}
		case strings.Contains(desc, "syslog_service_running"):
			sawRunning = true
			if getMetricValue(m) != 1 {
				t.Errorf("expected service_running=1, got %v", getMetricValue(m))
			}
		}
	}
	if !sawProcessed || !sawEPS || !sawMsgSize || !sawRunning {
		t.Errorf("missing expected metrics: processed=%v eps=%v msgsize=%v running=%v",
			sawProcessed, sawEPS, sawMsgSize, sawRunning)
	}
}
