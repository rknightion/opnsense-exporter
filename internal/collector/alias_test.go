package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

func aliasTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/firewall/alias/get_table_size", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok", "size": 10000000, "used": 664955,
			"details": {
				"GeoIP_UK": {"count":48827,"updated":null,"eval_nomatch":67332,"eval_match":152366,"in_block_p":210,"in_block_b":13304,"in_pass_p":1246181,"in_pass_b":84159393,"out_block_p":0,"out_block_b":0,"out_pass_p":14249422,"out_pass_b":21206874727},
				"bogons":   {"count":2945,"updated":null,"eval_nomatch":1035290,"eval_match":3272,"in_block_p":3272,"in_block_b":104704,"in_pass_p":0,"in_pass_b":0,"out_block_p":0,"out_block_b":0,"out_pass_p":0,"out_pass_b":0}
			}
		}`))
	})
	return httptest.NewServer(mux)
}

func TestAliasCollector_Update_Default(t *testing.T) {
	server := aliasTestServer(t)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &aliasCollector{subsystem: AliasSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	// tables_total + used + limit + 2×table_entries = 5
	if len(metrics) != 5 {
		t.Fatalf("expected 5 metrics without details, got %d", len(metrics))
	}
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		if strings.Contains(desc, "alias_table_entries_limit") && getMetricValue(m) != 10000000 {
			t.Errorf("expected limit 10000000, got %v", getMetricValue(m))
		}
		if strings.Contains(desc, "alias_table_entries\"") && labels["table"] == "GeoIP_UK" &&
			getMetricValue(m) != 48827 {
			t.Errorf("expected GeoIP_UK entries 48827, got %v", getMetricValue(m))
		}
	}
}

func TestAliasCollector_Update_Details(t *testing.T) {
	server := aliasTestServer(t)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &aliasCollector{subsystem: AliasSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)
	// 5 default + per table: 2 evaluations + 4 packets + 4 bytes = 10 → 5 + 2×10 = 25
	if len(metrics) != 25 {
		t.Fatalf("expected 25 metrics with details, got %d", len(metrics))
	}
	var sawInBlock bool
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "alias_table_packets_total") {
			labels := getMetricLabels(m)
			if labels["table"] == "GeoIP_UK" && labels["direction"] == "in" && labels["action"] == "block" {
				sawInBlock = true
				if getMetricValue(m) != 210 {
					t.Errorf("expected in/block packets 210, got %v", getMetricValue(m))
				}
			}
		}
	}
	if !sawInBlock {
		t.Error("missing packets_total{table=GeoIP_UK,direction=in,action=block}")
	}
}
