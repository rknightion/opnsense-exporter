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
	// per (listener, direction) row (2 rows × 4):
	//   direction_listeners              = 2
	//   direction_received_packets_total = 2
	//   direction_dropped_packets_total  = 2
	//   direction_matched_packets_total  = 2
	// total = 1 + 2*5 + 2*4 = 19
	expected := 19
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

// #544 item 3: direction was summed into the aggregation key and lost. The
// aggregate stays; the breakdown is a new family alongside it.
const bpfCollectorDirectionFixture = `{
  "bpf-statistics": {
    "bpf-entry": [
      {"pid": 2759, "interface-name": "pflog0", "direction": "bidirectional",
       "received-packets": 648272, "dropped-packets": 0, "filter-packets": 648272,
       "store-buffer-length": 13452, "hold-buffer-length": 0, "process": "filterlog"},
      {"pid": 41000, "interface-name": "ixl1", "direction": "input",
       "received-packets": 100, "dropped-packets": 3, "filter-packets": 50,
       "store-buffer-length": 0, "hold-buffer-length": 0, "process": "dhclient"},
      {"pid": 41001, "interface-name": "ixl1", "direction": "bidirectional",
       "received-packets": 200, "dropped-packets": 4, "filter-packets": 60,
       "store-buffer-length": 0, "hold-buffer-length": 0, "process": "dhclient"}
    ]
  }
}`

func TestBPFCollector_DirectionBreakdown(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/interface/get_bpf_statistics", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(bpfCollectorDirectionFixture))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &bpfCollector{subsystem: BPFSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	names := []string{
		"opnsense_bpf_direction_received_packets_total",
		"opnsense_bpf_direction_dropped_packets_total",
		"opnsense_bpf_direction_matched_packets_total",
		"opnsense_bpf_direction_listeners",
	}
	got := map[string]float64{}
	for _, m := range metrics {
		for _, n := range names {
			if !hasFqName(m, n) {
				continue
			}
			l := getMetricLabels(m)
			got[n+"|"+l["process"]+"|"+l["interface"]+"|"+l["direction"]] = getMetricValue(m)
		}
	}

	want := map[string]float64{
		"opnsense_bpf_direction_received_packets_total|dhclient|ixl1|input":            100,
		"opnsense_bpf_direction_received_packets_total|dhclient|ixl1|bidirectional":    200,
		"opnsense_bpf_direction_dropped_packets_total|dhclient|ixl1|input":             3,
		"opnsense_bpf_direction_matched_packets_total|dhclient|ixl1|bidirectional":     60,
		"opnsense_bpf_direction_listeners|dhclient|ixl1|input":                         1,
		"opnsense_bpf_direction_received_packets_total|filterlog|pflog0|bidirectional": 648272,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}

	// The pre-existing aggregate must be untouched in name, labels and value.
	for _, m := range metrics {
		if !hasFqName(m, "opnsense_bpf_received_packets_total") {
			continue
		}
		l := getMetricLabels(m)
		if _, hasDir := l["direction"]; hasDir {
			t.Fatal("direction leaked onto the existing aggregate's label set")
		}
		if l["process"] == "dhclient" && l["interface"] == "ixl1" && getMetricValue(m) != 300 {
			t.Errorf("aggregate dhclient/ixl1 = %v, want 300", getMetricValue(m))
		}
	}
}
