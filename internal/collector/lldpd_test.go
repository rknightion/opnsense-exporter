package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

func lldpdTestMux(t *testing.T, response string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/lldpd/service/neighbor", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(response))
	})
	return mux
}

// populatedLLDPResponse mirrors the sanitised production-shaped fixture in
// opnsense/lldpd_test.go: ixl0 has two neighbors (multi-neighbor-per-port),
// ixl2's Interface: line has no "alias:" token, igb0 is a single neighbor.
const populatedLLDPResponse = `{"response":"-------------------------------------------------------------------------------\nLLDP neighbors:\n-------------------------------------------------------------------------------\nInterface:    ixl0, alias: LAN (lan), via: LLDP, RID: 1, Time: 1 day, 04:56:36\n  Chassis:     \n    SysName:      test-firewall\n  Port:        \n    PortID:       ifname ixl0\n    PortDescr:    LAN (lan)\n    TTL:          120\n-------------------------------------------------------------------------------\nInterface:    ixl0, alias: LAN (lan), via: LLDP, RID: 2, Time: 1 day, 04:56:26\n  Chassis:     \n    SysName:      test-switch\n  Port:        \n    PortID:       local Port 1\n    PortDescr:    UPLINK\n    TTL:          120\n-------------------------------------------------------------------------------\nInterface:    ixl2, via: LLDP, RID: 2, Time: 1 day, 04:56:32\n  Chassis:     \n    SysName:      test-switch\n  Port:        \n    PortID:       local Port 5\n    PortDescr:    ONTBRIDGE\n    TTL:          120\n-------------------------------------------------------------------------------\nInterface:    igb0, alias: WAN (opt6), via: LLDP, RID: 2, Time: 1 day, 04:56:34\n  Chassis:     \n    SysName:      test-switch\n  Port:        \n    PortID:       local Port 3\n    PortDescr:    MODEM\n    TTL:          120\n-------------------------------------------------------------------------------\n\n\n"}`

const emptyLLDPResponse = `{"response":"-------------------------------------------------------------------------------\nLLDP neighbors:\n-------------------------------------------------------------------------------\n\n\n"}`

func TestLLDPCollector_Update_Populated(t *testing.T) {
	mux := lldpdTestMux(t, populatedLLDPResponse)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &lldpCollector{subsystem: LLDPSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 2 distinct interfaces (ixl0, ixl2, igb0 = 3) for the "neighbors" count
	// metric + 4 "neighbor_info" rows (one per neighbor) = 7.
	expectedCount := 7
	if len(metrics) != expectedCount {
		t.Fatalf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	neighborCounts := map[string]float64{}
	infoRows := 0
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		val := getMetricValue(m)
		switch {
		case strings.Contains(desc, "lldp_neighbors") && !strings.Contains(desc, "neighbor_info"):
			neighborCounts[labels["interface"]] = val
		case strings.Contains(desc, "neighbor_info"):
			infoRows++
			if val != 1 {
				t.Errorf("expected neighbor_info value=1, got %v", val)
			}
		}
	}

	if neighborCounts["ixl0"] != 2 {
		t.Errorf("expected 2 neighbors on ixl0, got %v", neighborCounts["ixl0"])
	}
	if neighborCounts["ixl2"] != 1 {
		t.Errorf("expected 1 neighbor on ixl2 (no-alias variant), got %v", neighborCounts["ixl2"])
	}
	if neighborCounts["igb0"] != 1 {
		t.Errorf("expected 1 neighbor on igb0, got %v", neighborCounts["igb0"])
	}
	if infoRows != 4 {
		t.Errorf("expected 4 neighbor_info rows, got %d", infoRows)
	}

	// Spot-check labels on one info row.
	found := false
	for _, m := range metrics {
		if !strings.Contains(m.Desc().String(), "neighbor_info") {
			continue
		}
		labels := getMetricLabels(m)
		if labels["interface"] == "ixl2" {
			found = true
			if labels["chassis_name"] != "test-switch" {
				t.Errorf("expected chassis_name=test-switch, got %q", labels["chassis_name"])
			}
			if labels["port_id"] != "local Port 5" {
				t.Errorf("expected port_id='local Port 5', got %q", labels["port_id"])
			}
			if labels["port_descr"] != "ONTBRIDGE" {
				t.Errorf("expected port_descr=ONTBRIDGE, got %q", labels["port_descr"])
			}
		}
	}
	if !found {
		t.Error("expected to find the ixl2 neighbor_info row")
	}
}

func TestLLDPCollector_Update_Empty(t *testing.T) {
	mux := lldpdTestMux(t, emptyLLDPResponse)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &lldpCollector{subsystem: LLDPSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when lldpd is running with zero neighbors, got %d", len(metrics))
	}
}

// TestLLDPCollector_Update_PluginAbsent guards the same pattern as ACME (#87):
// with os-lldpd absent (endpoint 404s) the collector must emit nothing.
func TestLLDPCollector_Update_PluginAbsent(t *testing.T) {
	mux := http.NewServeMux() // no handlers: all requests 404 → plugin absent
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &lldpCollector{subsystem: LLDPSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when plugin absent (404), got %d", len(metrics))
	}
}

// TestLLDPCollector_Update_DuplicateTupleSkipped guards against a
// MustNewConstMetric panic when two neighbor rows share the same
// (interface, chassis_name, port_id, port_descr) label tuple.
func TestLLDPCollector_Update_DuplicateTupleSkipped(t *testing.T) {
	dup := `{"response":"-------------------------------------------------------------------------------\nLLDP neighbors:\n-------------------------------------------------------------------------------\nInterface:    ixl0, alias: LAN (lan), via: LLDP, RID: 1, Time: 1 day, 04:56:36\n  Chassis:     \n    SysName:      test-switch\n  Port:        \n    PortID:       local Port 1\n    PortDescr:    UPLINK\n    TTL:          120\n-------------------------------------------------------------------------------\nInterface:    ixl0, alias: LAN (lan), via: LLDP, RID: 2, Time: 1 day, 04:56:26\n  Chassis:     \n    SysName:      test-switch\n  Port:        \n    PortID:       local Port 1\n    PortDescr:    UPLINK\n    TTL:          120\n-------------------------------------------------------------------------------\n\n\n"}`

	mux := lldpdTestMux(t, dup)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &lldpCollector{subsystem: LLDPSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	// Must not panic.
	metrics := collectMetrics(t, c, client)

	infoRows := 0
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "neighbor_info") {
			infoRows++
		}
	}
	if infoRows != 1 {
		t.Errorf("expected 1 neighbor_info row after dedup, got %d", infoRows)
	}
}

func TestLLDPCollector_Name(t *testing.T) {
	c := &lldpCollector{subsystem: LLDPSubsystem}
	if c.Name() != LLDPSubsystem {
		t.Errorf("expected %s, got %s", LLDPSubsystem, c.Name())
	}
}
