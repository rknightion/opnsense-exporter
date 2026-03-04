package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestFirewallCollector_Update(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/diagnostics/firewall/pf_statistics/interfaces", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"interfaces": {
				"igb0": {
					"references": 1,
					"in4_pass_packets": 1000,
					"in4_block_packets": 50,
					"out4_pass_packets": 900,
					"out4_block_packets": 10,
					"in6_pass_packets": 200,
					"in6_block_packets": 5,
					"out6_pass_packets": 180,
					"out6_block_packets": 2,
					"in4_pass_bytes": 1048576,
					"in4_block_bytes": 5120,
					"out4_pass_bytes": 921600,
					"out4_block_bytes": 1024,
					"in6_pass_bytes": 204800,
					"in6_block_bytes": 512,
					"out6_pass_bytes": 184320,
					"out6_block_bytes": 256
				}
			}
		}`))
	})

	mux.HandleFunc("/api/diagnostics/firewall/pf_states/1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"current": "12345",
			"limit": "200000"
		}`))
	})

	mux.HandleFunc("/api/diagnostics/firewall/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[
			{"label": "igb0", "value": 5000},
			{"label": "lo0", "value": 100}
		]`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &firewallCollector{subsystem: FirewallSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 16 metrics per interface (8 packet types + 8 byte types) + 2 pfStates (current + limit) + 2 firewallStats = 20
	expectedCount := 20
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestFirewallCollector_Update_MultipleInterfaces(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/diagnostics/firewall/pf_statistics/interfaces", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"interfaces": {
				"igb0": {
					"references": 1,
					"in4_pass_packets": 100,
					"in4_block_packets": 10,
					"out4_pass_packets": 90,
					"out4_block_packets": 5,
					"in6_pass_packets": 20,
					"in6_block_packets": 1,
					"out6_pass_packets": 18,
					"out6_block_packets": 0,
					"in4_pass_bytes": 10000,
					"in4_block_bytes": 1000,
					"out4_pass_bytes": 9000,
					"out4_block_bytes": 500,
					"in6_pass_bytes": 2000,
					"in6_block_bytes": 100,
					"out6_pass_bytes": 1800,
					"out6_block_bytes": 0
				},
				"igb1": {
					"references": 1,
					"in4_pass_packets": 50,
					"in4_block_packets": 5,
					"out4_pass_packets": 45,
					"out4_block_packets": 2,
					"in6_pass_packets": 10,
					"in6_block_packets": 0,
					"out6_pass_packets": 9,
					"out6_block_packets": 0,
					"in4_pass_bytes": 5000,
					"in4_block_bytes": 500,
					"out4_pass_bytes": 4500,
					"out4_block_bytes": 200,
					"in6_pass_bytes": 1000,
					"in6_block_bytes": 0,
					"out6_pass_bytes": 900,
					"out6_block_bytes": 0
				}
			}
		}`))
	})

	mux.HandleFunc("/api/diagnostics/firewall/pf_states/1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"current": "500",
			"limit": "100000"
		}`))
	})

	mux.HandleFunc("/api/diagnostics/firewall/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[
			{"label": "igb0", "value": 1000},
			{"label": "igb1", "value": 2000}
		]`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &firewallCollector{subsystem: FirewallSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 16 metrics per interface * 2 interfaces + 2 pfStates + 2 firewallStats = 36
	expectedCount := 36
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestFirewallCollector_Name(t *testing.T) {
	c := &firewallCollector{subsystem: FirewallSubsystem}
	if c.Name() != FirewallSubsystem {
		t.Errorf("expected %s, got %s", FirewallSubsystem, c.Name())
	}
}
