package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

// frrCollectorMux builds a ServeMux with all 6 quagga endpoints populated.
func frrCollectorMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/api/quagga/diagnostics/bgpsummary", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
  "response": {
    "ipv4Unicast": {
      "routerId": "10.0.0.1",
      "as": 65001,
      "ribCount": 42,
      "peerCount": 2,
      "peers": {
        "10.0.0.2": {
          "remoteAs": 65002,
          "msgRcvd": 1000,
          "msgSent": 900,
          "peerUptimeMsec": 93780000,
          "pfxRcd": 20,
          "pfxSnt": 15,
          "state": "Established"
        },
        "10.0.0.3": {
          "remoteAs": 65003,
          "msgRcvd": 5,
          "msgSent": 5,
          "peerUptimeMsec": 0,
          "pfxRcd": 0,
          "pfxSnt": 0,
          "state": "Active"
        }
      },
      "failedPeers": 1,
      "totalPeers": 2,
      "dynamicPeers": 0
    }
  }
}`))
	})

	mux.HandleFunc("/api/quagga/diagnostics/ospfoverview", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
  "response": {
    "areas": {
      "0.0.0.0": {
        "areaIfActiveCounter": 2,
        "nbrFullAdjacentCounter": 1,
        "lsaNumber": 7,
        "spfExecutedCounter": 12
      }
    }
  }
}`))
	})

	mux.HandleFunc("/api/quagga/diagnostics/searchOspfneighbor", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
  "total": 1,
  "rowCount": 1,
  "current": 1,
  "rows": [
    {
      "neighborid": "10.0.0.2",
      "state": "Full/DR",
      "address": "10.0.0.2",
      "ifaceName": "em0"
    }
  ]
}`))
	})

	mux.HandleFunc("/api/quagga/diagnostics/bfdneighbors", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
  "response": {
    "10.1.1.2": {
      "peer": "10.1.1.2",
      "local": "10.1.1.1",
      "interface": "em0",
      "status": "up",
      "uptime": 3600
    }
  }
}`))
	})

	mux.HandleFunc("/api/quagga/diagnostics/bfdcounters", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
  "response": {
    "10.1.1.2": {
      "peer": "10.1.1.2",
      "control-packet-input": 1000,
      "control-packet-output": 990,
      "echo-packet-input": 0,
      "echo-packet-output": 0,
      "session-up-events": 1,
      "session-down-events": 0,
      "zebra-notifications": 3
    }
  }
}`))
	})

	mux.HandleFunc("/api/quagga/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})

	return mux
}

func TestFRRCollector_Update_Normal(t *testing.T) {
	server := httptest.NewServer(frrCollectorMux(t))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &frrCollector{subsystem: FRRSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	if len(metrics) == 0 {
		t.Fatal("expected metrics but got none")
	}

	// Verify specific key metrics.
	var (
		sawServiceRunning bool
		sawBGPPeerUp      bool
		sawOSPFAdjacency  bool
		sawBFDPeerUp      bool
		serviceVal        float64
	)
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		val := getMetricValue(m)

		switch {
		case strings.Contains(desc, "frr_service_running"):
			sawServiceRunning = true
			serviceVal = val

		case strings.Contains(desc, "frr_bgp_peer_up\""):
			// Use trailing quote to avoid matching frr_bgp_peer_uptime_seconds.
			if labels["peer"] == "10.0.0.2" {
				sawBGPPeerUp = true
				if val != 1 {
					t.Errorf("bgp_peer_up{peer=10.0.0.2}: want 1, got %v", val)
				}
			}
			if labels["peer"] == "10.0.0.3" {
				if val != 0 {
					t.Errorf("bgp_peer_up{peer=10.0.0.3}: want 0 (Active state), got %v", val)
				}
			}

		case strings.Contains(desc, "frr_ospf_neighbor_adjacency"):
			if labels["neighbor_id"] == "10.0.0.2" {
				sawOSPFAdjacency = true
				if val != 1 {
					t.Errorf("ospf_neighbor_adjacency{neighbor_id=10.0.0.2}: want 1, got %v", val)
				}
			}

		case strings.Contains(desc, "frr_bfd_peer_up\""):
			// Use trailing quote to avoid matching frr_bfd_peer_uptime_seconds.
			if labels["peer"] == "10.1.1.2" {
				sawBFDPeerUp = true
				if val != 1 {
					t.Errorf("bfd_peer_up{peer=10.1.1.2}: want 1, got %v", val)
				}
			}
		}
	}

	if !sawServiceRunning {
		t.Error("expected frr_service_running metric")
	}
	if serviceVal != 1 {
		t.Errorf("frr_service_running: want 1, got %v", serviceVal)
	}
	if !sawBGPPeerUp {
		t.Error("expected frr_bgp_peer_up metric for peer 10.0.0.2")
	}
	if !sawOSPFAdjacency {
		t.Error("expected frr_ospf_neighbor_adjacency metric for neighbor 10.0.0.2")
	}
	if !sawBFDPeerUp {
		t.Error("expected frr_bfd_peer_up metric for peer 10.1.1.2")
	}

	// Verify BGP uptime metric skips peer 10.0.0.3 (peerUptimeMsec==0).
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "frr_bgp_peer_uptime_seconds") {
			labels := getMetricLabels(m)
			if labels["peer"] == "10.0.0.3" {
				t.Error("expected frr_bgp_peer_uptime_seconds to be skipped for peer with 0 uptime")
			}
		}
	}
}

func TestFRRCollector_Update_PluginAbsent(t *testing.T) {
	// All handlers return 404 → plugin absent → 0 metrics.
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &frrCollector{subsystem: FRRSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when plugin absent, got %d", len(metrics))
		for _, m := range metrics {
			t.Logf("  %s", m.Desc().String())
		}
	}
}

// TestFRRCollector_Update_DualSAFINoDuplicateSeries guards #162: a neighbor
// activated in both ipv4 unicast and multicast must not emit duplicate label
// tuples for bgp_peers_total/bgp_failed_peers/bgp_rib_entries (which would fail
// the whole scrape's Gather).
func TestFRRCollector_Update_DualSAFINoDuplicateSeries(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/quagga/diagnostics/bgpsummary", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
  "response": {
    "ipv4Unicast": {"ribCount": 42, "peerCount": 1, "failedPeers": 0,
      "peers": {"10.0.0.2": {"remoteAs": 65002, "msgRcvd": 1, "msgSent": 1, "peerUptimeMsec": 1000, "pfxRcd": 5, "pfxSnt": 3, "state": "Established"}}},
    "ipv4Multicast": {"ribCount": 7, "peerCount": 1, "failedPeers": 0,
      "peers": {"10.0.0.2": {"remoteAs": 65002, "msgRcvd": 1, "msgSent": 1, "peerUptimeMsec": 1000, "pfxRcd": 2, "pfxSnt": 1, "state": "Established"}}}
  }
}`))
	})
	mux.HandleFunc("/api/quagga/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &frrCollector{subsystem: FRRSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	// Both SAFIs must be represented as distinct af label values.
	afs := map[string]bool{}
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "bgp_peers_total") {
			afs[getMetricLabels(m)["af"]] = true
		}
	}
	if !afs["ipv4"] || !afs["ipv4multicast"] {
		t.Errorf("expected bgp_peers_total for both ipv4 and ipv4multicast, got %v", afs)
	}
}

func TestFRRCollector_Name(t *testing.T) {
	c := &frrCollector{subsystem: FRRSubsystem}
	if c.Name() != FRRSubsystem {
		t.Errorf("expected %s, got %s", FRRSubsystem, c.Name())
	}
}

func TestFRRCollector_Update_BGPUptimeEmittedForEstablished(t *testing.T) {
	// Verify that uptime IS emitted for the established peer.
	server := httptest.NewServer(frrCollectorMux(t))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &frrCollector{subsystem: FRRSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	found := false
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "frr_bgp_peer_uptime_seconds") {
			labels := getMetricLabels(m)
			if labels["peer"] == "10.0.0.2" {
				found = true
				if val := getMetricValue(m); val != 93780 {
					t.Errorf("bgp_peer_uptime_seconds for 10.0.0.2: want 93780, got %v", val)
				}
			}
		}
	}
	if !found {
		t.Error("expected frr_bgp_peer_uptime_seconds metric for established peer 10.0.0.2")
	}
}
