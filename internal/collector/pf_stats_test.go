package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestPFStatsCollector_Update(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/diagnostics/firewall/pf_statistics/info", func(w http.ResponseWriter, r *http.Request) {
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
		w.Write([]byte(`{"memory": {"states": 3257500, "src-nodes": 3257500, "frags": 5000, "table-entries": 10000000}}`))
	})

	mux.HandleFunc("/api/diagnostics/firewall/pf_statistics/timeouts", func(w http.ResponseWriter, r *http.Request) {
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

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &pfStatsCollector{subsystem: PFStatsSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Expected metric count:
	// 5 scalar metrics (stateTableEntries, stateTableSearches, stateTableInserts, stateTableRemovals, sourceTrackingEntries)
	// 16 counters (one per counter name)
	// 10 limit counters (one per limit counter name)
	// 4 memory limits (states, src-nodes, frags, table-entries)
	// 23 timeouts (25 total minus 2 "states" entries)
	// Total: 5 + 16 + 10 + 4 + 23 = 58
	expectedCount := 58
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestPFStatsCollector_Name(t *testing.T) {
	c := &pfStatsCollector{subsystem: PFStatsSubsystem}
	if c.Name() != PFStatsSubsystem {
		t.Errorf("expected %s, got %s", PFStatsSubsystem, c.Name())
	}
}
