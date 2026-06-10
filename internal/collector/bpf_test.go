package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

const bpfCollectorNormalFixture = `{
  "bpf-statistics": {
    "bpf-entry": [
      {"pid": 12706, "interface-name": "igb0_vlan50", "direction": "bidirectional",
       "received-packets": 11442, "dropped-packets": 11424, "filter-packets": 11442,
       "store-buffer-length": 4028, "hold-buffer-length": 3236, "process": "dnsmasq"},
      {"pid": 28395, "interface-name": "igb0", "direction": "bidirectional",
       "received-packets": 987654321, "dropped-packets": 0, "filter-packets": 987654321,
       "store-buffer-length": 32768, "hold-buffer-length": 32768, "process": "dhcpd"}
    ]
  }
}`

const bpfCollectorEmptyFixture = `{"bpf-statistics":{"bpf-entry":[]}}`

func TestBPFCollector_Update_Normal(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/interface/get_bpf_statistics", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(bpfCollectorNormalFixture))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &bpfCollector{subsystem: BPFSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Expected metrics:
	// listeners_total                    = 1
	// per listener (2 listeners × 5):
	//   received_packets_total           = 2
	//   dropped_packets_total            = 2
	//   matched_packets_total            = 2
	//   store_buffer_bytes               = 2
	//   hold_buffer_bytes                = 2
	// total = 1 + 2*5 = 11
	expected := 11
	if len(metrics) != expected {
		t.Errorf("expected %d metrics, got %d", expected, len(metrics))
	}

	// Verify listeners_total == 2 (raw entry count)
	for _, m := range metrics {
		desc := m.Desc().String()
		val := getMetricValue(m)
		if strings.Contains(desc, "bpf_listeners_total") {
			if val != 2 {
				t.Errorf("listeners_total: expected 2, got %v", val)
			}
		}
	}

	// Verify dhcpd/igb0 received packets
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		val := getMetricValue(m)
		if strings.Contains(desc, "bpf_received_packets_total") &&
			labels["process"] == "dhcpd" && labels["interface"] == "igb0" {
			if val != 987654321 {
				t.Errorf("dhcpd/igb0 received_packets_total: expected 987654321, got %v", val)
			}
		}
	}
}

func TestBPFCollector_Update_Empty(t *testing.T) {
	// Core endpoint always responds; empty means zero BPF listeners.
	// The collector must still emit listeners_total=0.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/interface/get_bpf_statistics", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(bpfCollectorEmptyFixture))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &bpfCollector{subsystem: BPFSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Only listeners_total should be emitted (value 0)
	if len(metrics) != 1 {
		t.Errorf("expected 1 metric (listeners_total), got %d", len(metrics))
	}
	if len(metrics) > 0 {
		val := getMetricValue(metrics[0])
		if val != 0 {
			t.Errorf("listeners_total: expected 0, got %v", val)
		}
	}
}

func TestBPFCollector_Name(t *testing.T) {
	c := &bpfCollector{subsystem: BPFSubsystem}
	if c.Name() != BPFSubsystem {
		t.Errorf("expected %s, got %s", BPFSubsystem, c.Name())
	}
}
