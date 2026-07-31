package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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
      "uptime": 3600,
      "diagnostic": "ok",
      "remote-diagnostic": "ok",
      "rtt-min": 500,
      "rtt-avg": 750,
      "rtt-max": 1200
    },
    "10.1.1.3": {
      "peer": "10.1.1.3",
      "local": "10.1.1.1",
      "interface": "em1",
      "status": "down",
      "downtime": 120,
      "diagnostic": "neighbor signaled session down",
      "remote-diagnostic": "control detection time expired",
      "rtt-min": 0,
      "rtt-avg": 0,
      "rtt-max": 0
    },
    "10.1.1.4": {
      "peer": "10.1.1.4",
      "local": "10.1.1.1",
      "interface": "em2",
      "status": "init",
      "diagnostic": "ok",
      "remote-diagnostic": "ok",
      "rtt-min": 0,
      "rtt-avg": 0,
      "rtt-max": 0
    }
  }
}`))
	})

	// session-up/session-down are FRR's real wire names (bfdd/bfdd_vty.c) — see
	// the CORRECTION banner in opnsense/frr.go (#480). Do not "restore" a
	// -events suffix; it appears nowhere in FRR.
	mux.HandleFunc("/api/quagga/diagnostics/bfdcounters", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
  "response": {
    "10.1.1.2": {
      "peer": "10.1.1.2",
      "control-packet-input": 1000,
      "control-packet-output": 990,
      "echo-packet-input": 0,
      "echo-packet-output": 0,
      "session-up": 1,
      "session-down": 0,
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

// TestFRRCollector_Update_BFDDiagnosticRTTAndDownDuration covers #484: the
// diagnostic/remote_diagnostic labelled info series, the RTT gauges, and
// down-duration modelling at the collector (metric-emission) layer.
//
// The critical case is peer 10.1.1.4, which frrCollectorMux's bfdneighbors
// fixture puts in FRR's "init" state — carrying neither "uptime" nor
// "downtime" on the wire (bfdd_vty.c:373-375). opnsense_frr_bfd_peer_downtime_seconds
// must be entirely ABSENT for that peer, not present with value 0: "0 seconds
// down" and "no information" are different answers, and this test is what
// pins that distinction at the metric-emission boundary (not just the
// opnsense/ decode layer).
func TestFRRCollector_Update_BFDDiagnosticRTTAndDownDuration(t *testing.T) {
	server := httptest.NewServer(frrCollectorMux(t))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &frrCollector{subsystem: FRRSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	diagLabelsByPeer := map[string]map[string]string{}
	rttMinByPeer := map[string]float64{}
	downtimePeersSeen := map[string]bool{}

	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		val := getMetricValue(m)

		switch {
		case strings.Contains(desc, "frr_bfd_peer_diagnostic_info"):
			diagLabelsByPeer[labels["peer"]] = labels
		case strings.Contains(desc, "frr_bfd_peer_rtt_min_microseconds"):
			rttMinByPeer[labels["peer"]] = val
		case strings.Contains(desc, "frr_bfd_peer_downtime_seconds"):
			downtimePeersSeen[labels["peer"]] = true
			if labels["peer"] == "10.1.1.3" && val != 120 {
				t.Errorf("bfd_peer_downtime_seconds{peer=10.1.1.3}: want 120, got %v", val)
			}
		}
	}

	// UP peer (10.1.1.2): diagnostic info present, RTT gauges present, no
	// downtime series.
	if labels, ok := diagLabelsByPeer["10.1.1.2"]; !ok {
		t.Error("expected frr_bfd_peer_diagnostic_info for peer 10.1.1.2")
	} else if labels["diagnostic"] != "ok" || labels["remote_diagnostic"] != "ok" {
		t.Errorf("peer 10.1.1.2 diagnostic labels: want ok/ok, got %s/%s",
			labels["diagnostic"], labels["remote_diagnostic"])
	}
	if val, ok := rttMinByPeer["10.1.1.2"]; !ok || val != 500 {
		t.Errorf("bfd_peer_rtt_min_microseconds{peer=10.1.1.2}: want 500, got %v (present=%v)", val, ok)
	}
	if downtimePeersSeen["10.1.1.2"] {
		t.Error("peer 10.1.1.2 (up): expected NO frr_bfd_peer_downtime_seconds series")
	}

	// DOWN peer (10.1.1.3): diagnostic carries the real down reason, downtime present.
	if labels, ok := diagLabelsByPeer["10.1.1.3"]; !ok {
		t.Error("expected frr_bfd_peer_diagnostic_info for peer 10.1.1.3")
	} else if labels["diagnostic"] != "neighbor signaled session down" {
		t.Errorf("peer 10.1.1.3 diagnostic: want %q, got %q",
			"neighbor signaled session down", labels["diagnostic"])
	}
	if !downtimePeersSeen["10.1.1.3"] {
		t.Error("peer 10.1.1.3 (down): expected frr_bfd_peer_downtime_seconds series")
	}

	// INIT peer (10.1.1.4): the load-bearing assertion. downtime must be
	// ABSENT, not present-with-zero.
	if downtimePeersSeen["10.1.1.4"] {
		t.Error("peer 10.1.1.4 (init): expected NO frr_bfd_peer_downtime_seconds series " +
			"(FRR emits neither uptime nor downtime for PTM_BFD_INIT) — absence must stay " +
			"absence, not become a zero")
	}
	// diagnostic/RTT are unconditional in FRR, so they ARE expected even for
	// the init peer.
	if _, ok := diagLabelsByPeer["10.1.1.4"]; !ok {
		t.Error("expected frr_bfd_peer_diagnostic_info for peer 10.1.1.4 (init) — " +
			"diagnostic is emitted unconditionally by FRR regardless of session state")
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

// frrDetailMux extends frrCollectorMux with the #197/#198/#199 endpoints, so
// tests can exercise the new metrics alongside the existing BGP/OSPF/BFD ones.
func frrDetailMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := frrCollectorMux(t)

	mux.HandleFunc("/api/quagga/diagnostics/bgpneighbors", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
  "response": {
    "10.0.0.2": {
      "remoteAs": 65002,
      "bgpState": "Established",
      "connectionsEstablished": 2,
      "connectionsDropped": 1,
      "lastResetTimerMsecs": 5000,
      "lastResetDueTo": "Peer closed the session",
      "messageStats": {
        "depthInq": 0, "depthOutq": 1,
        "opensSent": 1, "opensRecv": 1,
        "updatesSent": 2, "updatesRecv": 3,
        "keepalivesSent": 4, "keepalivesRecv": 4,
        "notificationsSent": 0, "notificationsRecv": 0,
        "routeRefreshSent": 0, "routeRefreshRecv": 0,
        "capabilitySent": 0, "capabilityRecv": 0
      },
      "addressFamilyInfo": {
        "ipv4Unicast": {"acceptedPrefixCounter": 20}
      }
    }
  }
}`))
	})

	mux.HandleFunc("/api/quagga/diagnostics/ospfinterface", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
  "response": {
    "interfaces": {
      "em0": {
        "ifUp": true, "ospfEnabled": true, "area": "0.0.0.0",
        "networkType": "BROADCAST", "cost": 10, "state": "DR",
        "priority": 1, "nbrCount": 1, "nbrAdjacentCount": 1
      }
    }
  }
}`))
	})

	mux.HandleFunc("/api/quagga/diagnostics/ospfv3overview", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response":[]}`))
	})
	mux.HandleFunc("/api/quagga/diagnostics/ospfv3interface", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response":[]}`))
	})

	mux.HandleFunc("/api/quagga/diagnostics/search_generalroute4", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":1,"rowCount":1,"current":1,"rows":[
			{"prefix": "0.0.0.0/0", "protocol": "kernel", "afi": "ipv4"}
		]}`))
	})
	mux.HandleFunc("/api/quagga/diagnostics/search_generalroute6", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	mux.HandleFunc("/api/quagga/diagnostics/search_ospfroute", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	mux.HandleFunc("/api/quagga/diagnostics/search_ospfv3route", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	mux.HandleFunc("/api/quagga/diagnostics/ospfdatabase", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response": {"areas": {"0.0.0.0": {"routerLinkStatesCount": 1}}, "asExternalLinkStatesCount": 0}}`))
	})
	mux.HandleFunc("/api/quagga/diagnostics/search_ospfv3database", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})

	return mux
}

func TestFRRCollector_Update_BGPNeighborDetail(t *testing.T) {
	server := httptest.NewServer(frrDetailMux(t))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &frrCollector{subsystem: FRRSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	var sawConnEstablished, sawConnDropped, sawLastReset, sawMessages, sawPrefixes, sawQueueDepth bool
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		if labels["peer"] != "10.0.0.2" {
			continue
		}
		switch {
		case strings.Contains(desc, "frr_bgp_peer_connections_established_total"):
			sawConnEstablished = true
			if v := getMetricValue(m); v != 2 {
				t.Errorf("connections_established_total: want 2, got %v", v)
			}
		case strings.Contains(desc, "frr_bgp_peer_connections_dropped_total"):
			sawConnDropped = true
			if v := getMetricValue(m); v != 1 {
				t.Errorf("connections_dropped_total: want 1, got %v", v)
			}
		case strings.Contains(desc, "frr_bgp_peer_last_reset_seconds"):
			sawLastReset = true
			if v := getMetricValue(m); v != 5 {
				t.Errorf("last_reset_seconds: want 5, got %v", v)
			}
		case strings.Contains(desc, "frr_bgp_peer_messages_by_type_total"):
			sawMessages = true
		case strings.Contains(desc, "frr_bgp_peer_prefixes_accepted"):
			sawPrefixes = true
			if labels["af"] == "ipv4" {
				if v := getMetricValue(m); v != 20 {
					t.Errorf("prefixes_accepted{af=ipv4}: want 20, got %v", v)
				}
			}
		case strings.Contains(desc, "frr_bgp_peer_queue_depth"):
			sawQueueDepth = true
		}
	}
	if !sawConnEstablished || !sawConnDropped || !sawLastReset || !sawMessages || !sawPrefixes || !sawQueueDepth {
		t.Errorf("missing BGP neighbor-detail metrics: established=%v dropped=%v lastReset=%v messages=%v prefixes=%v queueDepth=%v",
			sawConnEstablished, sawConnDropped, sawLastReset, sawMessages, sawPrefixes, sawQueueDepth)
	}
}

func TestFRRCollector_Update_OSPFInterfaceDetail(t *testing.T) {
	server := httptest.NewServer(frrDetailMux(t))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &frrCollector{subsystem: FRRSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	var sawUp, sawCost, sawNeighbors, sawAdjacent bool
	stateVals := map[string]float64{}
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		if labels["interface"] != "em0" {
			continue
		}
		switch {
		case strings.Contains(desc, "frr_ospf_interface_up"):
			sawUp = true
			if v := getMetricValue(m); v != 1 {
				t.Errorf("ospf_interface_up: want 1, got %v", v)
			}
		case strings.Contains(desc, "frr_ospf_interface_cost"):
			sawCost = true
			if v := getMetricValue(m); v != 10 {
				t.Errorf("ospf_interface_cost: want 10, got %v", v)
			}
		case strings.Contains(desc, "frr_ospf_interface_neighbors_adjacent"):
			sawAdjacent = true
		case strings.Contains(desc, "frr_ospf_interface_neighbors\""):
			sawNeighbors = true
		case strings.Contains(desc, "frr_ospf_interface_state"):
			stateVals[labels["state"]] = getMetricValue(m)
		}
	}
	if !sawUp || !sawCost || !sawNeighbors || !sawAdjacent {
		t.Errorf("missing OSPF interface-detail metrics: up=%v cost=%v neighbors=%v adjacent=%v",
			sawUp, sawCost, sawNeighbors, sawAdjacent)
	}
	if len(stateVals) != 6 {
		t.Fatalf("expected 6 enum-style state series, got %d: %v", len(stateVals), stateVals)
	}
	if stateVals["DR"] != 1 {
		t.Errorf("state=DR: want 1, got %v", stateVals["DR"])
	}
	for _, s := range []string{"BDR", "DROther", "PointToPoint", "Waiting", "Down"} {
		if stateVals[s] != 0 {
			t.Errorf("state=%s: want 0, got %v", s, stateVals[s])
		}
	}
}

// TestFRRCollector_Update_OSPFv3DisabledEmitsNoMetrics verifies that the
// captured OSPFv3 disabled/empty shape (`{"response":[]}`) results in no
// ospfv3_* series, mirroring the dev-box lab's environmental gap (no IPv6
// stack -> ospf6d disabled).
func TestFRRCollector_Update_OSPFv3DisabledEmitsNoMetrics(t *testing.T) {
	server := httptest.NewServer(frrDetailMux(t))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &frrCollector{subsystem: FRRSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "frr_ospfv3_") {
			t.Errorf("expected no ospfv3_* series when ospf6d is disabled, got %s", m.Desc().String())
		}
	}
}

// TestFRRCollector_Update_RoutesDisabledByDefault verifies the opt-in
// routing-state volume gauges (#199) are absent unless SetRoutesEnabled(true)
// is called, and that FetchFRRRouteVolumes' endpoints are never even hit when
// disabled (no handlers registered for them -> would 404 into a hard error if
// called, since they're not plugin-gated from this test's point of view).
func TestFRRCollector_Update_RoutesDisabledByDefault(t *testing.T) {
	// Deliberately does NOT register the search_*/ospfdatabase endpoints, so a
	// call to FetchFRRRouteVolumes while disabled would either 404 silently
	// (tolerated) or, if somehow miswired to be mandatory, surface as an error.
	mux := frrCollectorMux(t)
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &frrCollector{subsystem: FRRSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "frr_route_count") || strings.Contains(desc, "frr_route_nexthop_count") ||
			strings.Contains(desc, "frr_ospf_route_count") || strings.Contains(desc, "frr_ospfv3_route_count") ||
			strings.Contains(desc, "frr_ospf_lsa_count") || strings.Contains(desc, "frr_ospfv3_lsa_count") {
			t.Errorf("expected no routing-volume series when routes disabled (default), got %s", desc)
		}
	}
}

func TestFRRCollector_Update_RoutesEnabled(t *testing.T) {
	server := httptest.NewServer(frrDetailMux(t))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &frrCollector{subsystem: FRRSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetRoutesEnabled(true)

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	var sawRouteCount, sawOSPFLSA bool
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		switch {
		case strings.Contains(desc, "frr_route_count"):
			sawRouteCount = true
			if labels["af"] == "ipv4" && labels["protocol"] == "kernel" {
				if v := getMetricValue(m); v != 1 {
					t.Errorf("route_count{af=ipv4,protocol=kernel}: want 1, got %v", v)
				}
			}
		case strings.Contains(desc, "frr_ospf_lsa_count"):
			sawOSPFLSA = true
		}
	}
	if !sawRouteCount {
		t.Error("expected frr_route_count series when routes enabled")
	}
	if !sawOSPFLSA {
		t.Error("expected frr_ospf_lsa_count series when routes enabled")
	}
}

// TestFRRCollector_Update_MalformedOSPFOverviewFailsScrape pins the externally
// visible failure contract for #378. Before that fix, a corrupt embedded OSPF
// overview was swallowed and the collector reported partial success: the OSPF
// series were silently missing while the scrape looked healthy. The client now
// surfaces a contextual decode error, so the collector must propagate it and
// emit NOTHING rather than half a subsystem.
//
// The mux serves ONLY a malformed ospfoverview; every other quagga endpoint
// 404s, which FetchFRRBGP correctly reads as "plugin absent" and passes over.
// That isolates the overview decode as the sole failure. The payload starts
// with '{' on purpose — the daemon-disabled '[' fallback and the PHP
// empty-map-as-[] quirk on `areas` are both legitimate shapes that must NOT
// error, and each is covered in opnsense/frr_test.go.
func TestFRRCollector_Update_MalformedOSPFOverviewFailsScrape(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/quagga/diagnostics/ospfoverview", func(w http.ResponseWriter, r *http.Request) {
		// `areas` typed as a string: an object payload that cannot decode.
		w.Write([]byte(`{"response": {"areas": "not-an-object"}}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &frrCollector{subsystem: FRRSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	// Deliberately not collectMetrics(): that helper t.Fatalf's on any Update
	// error, and the error is precisely what this test asserts.
	ch := make(chan prometheus.Metric, 500)
	err := c.Update(context.Background(), client, ch)
	close(ch)

	if err == nil {
		t.Fatal("expected an APICallError from a malformed OSPF overview, got nil (the #378 partial-success bug)")
	}
	if err.Endpoint != "quaggaOspfOverview" {
		t.Errorf("expected the error to name the quaggaOspfOverview endpoint, got %q", err.Endpoint)
	}
	if !strings.Contains(err.Message, "decode") {
		t.Errorf("expected a contextual decode message, got %q", err.Message)
	}

	var emitted []prometheus.Metric
	for m := range ch {
		emitted = append(emitted, m)
	}
	if len(emitted) != 0 {
		t.Errorf("expected 0 metrics on a failed OSPF overview decode, got %d", len(emitted))
		for _, m := range emitted {
			t.Logf("  unexpectedly emitted: %s", m.Desc().String())
		}
	}
}

// TestFRRCollector_Update_OSPFNeighborAdjacencyStability covers #582 at the
// metric-emission layer: the NSM-state info series, the presence-gated
// uptime/dead-timer gauges, and the always-emitted LSA queue-depth gauges.
// Only ospfoverview and searchOspfneighbor are registered; every other quagga
// endpoint 404s via the mux's default handler, which every Fetch* in this
// package already reads as "plugin absent" — isolating these two neighbor
// rows as the only OSPF-relevant input, same technique as
// TestFRRCollector_Update_MalformedOSPFOverviewFailsScrape above.
func TestFRRCollector_Update_OSPFNeighborAdjacencyStability(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/quagga/diagnostics/ospfoverview", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response":{"areas":{}}}`))
	})
	mux.HandleFunc("/api/quagga/diagnostics/searchOspfneighbor", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
  "total": 2,
  "rowCount": 2,
  "current": 1,
  "rows": [
    {
      "neighborid": "10.0.0.2",
      "state": "Full/DR",
      "address": "10.0.0.2",
      "ifaceName": "em0",
      "converged": "Full",
      "upTimeInMsec": 93780000,
      "routerDeadIntervalTimerDueMsec": 32000,
      "databaseSummaryListCounter": 0,
      "linkStateRequestListCounter": 0,
      "linkStateRetransmissionListCounter": 2
    },
    {
      "neighborid": "10.0.0.3",
      "state": "Init/Other",
      "address": "10.0.0.3",
      "ifaceName": "em1",
      "converged": "Init",
      "routerDeadIntervalTimerDueMsec": "inactive",
      "databaseSummaryListCounter": 0,
      "linkStateRequestListCounter": 0,
      "linkStateRetransmissionListCounter": 0
    }
  ]
}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &frrCollector{subsystem: FRRSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	nsmStates := map[string]string{}    // neighbor_id -> nsm_state
	uptimeSeen := map[string]bool{}     // neighbor_id -> saw uptime series
	deadTimerSeen := map[string]bool{}  // neighbor_id -> saw dead-timer series
	queueDepths := map[string]float64{} // "neighbor_id/queue" -> value
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		nbr := labels["neighbor_id"]
		switch {
		case strings.Contains(desc, "frr_ospf_neighbor_nsm_state_info"):
			nsmStates[nbr] = labels["nsm_state"]
			if v := getMetricValue(m); v != 1 {
				t.Errorf("ospf_neighbor_nsm_state_info{neighbor_id=%s}: want 1, got %v", nbr, v)
			}
		case strings.Contains(desc, "frr_ospf_neighbor_uptime_seconds"):
			uptimeSeen[nbr] = true
			if nbr == "10.0.0.2" {
				if v := getMetricValue(m); v != 93780 {
					t.Errorf("ospf_neighbor_uptime_seconds{neighbor_id=10.0.0.2}: want 93780, got %v", v)
				}
			}
		case strings.Contains(desc, "frr_ospf_neighbor_dead_timer_seconds"):
			deadTimerSeen[nbr] = true
			if nbr == "10.0.0.2" {
				if v := getMetricValue(m); v != 32 {
					t.Errorf("ospf_neighbor_dead_timer_seconds{neighbor_id=10.0.0.2}: want 32, got %v", v)
				}
			}
		case strings.Contains(desc, "frr_ospf_neighbor_lsa_queue_depth"):
			queueDepths[nbr+"/"+labels["queue"]] = getMetricValue(m)
		}
	}

	if nsmStates["10.0.0.2"] != "Full" {
		t.Errorf("neighbor 10.0.0.2 nsm_state: want Full, got %q", nsmStates["10.0.0.2"])
	}
	if nsmStates["10.0.0.3"] != "Init" {
		t.Errorf("neighbor 10.0.0.3 nsm_state: want Init, got %q", nsmStates["10.0.0.3"])
	}

	if !uptimeSeen["10.0.0.2"] {
		t.Error("expected ospf_neighbor_uptime_seconds for neighbor 10.0.0.2 (upTimeInMsec present)")
	}
	if uptimeSeen["10.0.0.3"] {
		t.Error("expected NO ospf_neighbor_uptime_seconds for neighbor 10.0.0.3 (upTimeInMsec absent)")
	}
	if !deadTimerSeen["10.0.0.2"] {
		t.Error("expected ospf_neighbor_dead_timer_seconds for neighbor 10.0.0.2 (numeric reading)")
	}
	// GUARDS the exact bug this metric exists to avoid: a fabricated "0
	// seconds until dead" reading for the neighbor whose timer FRR reports as
	// the string "inactive", which would look identical to a neighbor on the
	// verge of dropping.
	if deadTimerSeen["10.0.0.3"] {
		t.Error(`expected NO ospf_neighbor_dead_timer_seconds for neighbor 10.0.0.3 (timer is "inactive")`)
	}

	if queueDepths["10.0.0.2/ls_retransmission"] != 2 {
		t.Errorf("neighbor 10.0.0.2 ls_retransmission queue depth: want 2, got %v", queueDepths["10.0.0.2/ls_retransmission"])
	}
	if queueDepths["10.0.0.3/ls_retransmission"] != 0 {
		t.Errorf("neighbor 10.0.0.3 ls_retransmission queue depth: want 0, got %v", queueDepths["10.0.0.3/ls_retransmission"])
	}
}

// TestFRRCollector_Update_OSPFSPFTiming covers #582's instance-level SPF-run
// timing gauges: present with the fixture's numbers, and absent entirely
// (never a fabricated 0) when the box hasn't run SPF yet.
func TestFRRCollector_Update_OSPFSPFTiming(t *testing.T) {
	cases := []struct {
		name         string
		overview     string
		wantPresent  bool
		wantDuration float64
	}{
		{
			name:         "spf_has_run",
			overview:     `{"response":{"areas":{},"spfLastExecutedMsecs":5000,"spfLastDurationMsecs":42}}`,
			wantPresent:  true,
			wantDuration: 0.042,
		},
		{
			name:        "spf_has_not_run",
			overview:    `{"response":{"areas":{},"spfHasNotRun":true}}`,
			wantPresent: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/api/quagga/diagnostics/ospfoverview", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.overview))
			})
			mux.HandleFunc("/api/quagga/diagnostics/searchOspfneighbor", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
			})
			server := httptest.NewServer(mux)
			defer server.Close()
			client := newCollectorTestClient(t, server)

			c := &frrCollector{subsystem: FRRSubsystem}
			c.Register(namespace, "test", promslog.NewNopLogger())

			metrics := collectMetrics(t, c, client)

			var sawTimestamp, sawDuration bool
			var durationVal float64
			for _, m := range metrics {
				desc := m.Desc().String()
				switch {
				case strings.Contains(desc, "frr_ospf_spf_last_executed_timestamp_seconds"):
					sawTimestamp = true
				case strings.Contains(desc, "frr_ospf_spf_last_duration_seconds"):
					sawDuration = true
					durationVal = getMetricValue(m)
				}
			}

			if sawTimestamp != tc.wantPresent {
				t.Errorf("frr_ospf_spf_last_executed_timestamp_seconds presence: want %v, got %v", tc.wantPresent, sawTimestamp)
			}
			if sawDuration != tc.wantPresent {
				t.Errorf("frr_ospf_spf_last_duration_seconds presence: want %v, got %v", tc.wantPresent, sawDuration)
			}
			if tc.wantPresent && durationVal != tc.wantDuration {
				t.Errorf("frr_ospf_spf_last_duration_seconds: want %v, got %v", tc.wantDuration, durationVal)
			}
		})
	}
}

// TestFRRCollector_Update_OSPFv3SPFTiming covers #582's OSPFv3 SPF-run timing
// pair, which is deliberately asymmetric: duration is instance-level, recency
// is per-area (see the FRROSPFv3Overview field docs in opnsense/frr.go for
// why there is no numeric instance-level recency reading on OSPFv3).
func TestFRRCollector_Update_OSPFv3SPFTiming(t *testing.T) {
	mux := http.NewServeMux()
	// ospfoverview/searchOspfneighbor 404 (OSPFv2 absent); only OSPFv3 is live.
	mux.HandleFunc("/api/quagga/diagnostics/ospfv3overview", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
  "response": {
    "spfLastDurationSecs": 1,
    "spfLastDurationMsecs": 500000,
    "areas": {
      "0.0.0.0": {
        "numberOfAreaScopedLsa": 4,
        "spfLastExecutedSecs": 10,
        "spfLastExecutedMicroSecs": 250000
      }
    }
  }
}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &frrCollector{subsystem: FRRSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	var sawDuration, sawAreaTimestamp bool
	var durationVal, areaTimestampVal float64
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		switch {
		case strings.Contains(desc, "frr_ospfv3_spf_last_duration_seconds"):
			sawDuration = true
			durationVal = getMetricValue(m)
		case strings.Contains(desc, "frr_ospfv3_area_spf_last_executed_timestamp_seconds"):
			if labels["area"] == "0.0.0.0" {
				sawAreaTimestamp = true
				areaTimestampVal = getMetricValue(m)
			}
		}
	}

	if !sawDuration {
		t.Fatal("expected frr_ospfv3_spf_last_duration_seconds")
	}
	if durationVal != 1.5 {
		t.Errorf("frr_ospfv3_spf_last_duration_seconds: want 1.5, got %v", durationVal)
	}
	if !sawAreaTimestamp {
		t.Fatal("expected frr_ospfv3_area_spf_last_executed_timestamp_seconds{area=0.0.0.0}")
	}
	wantTimestamp := float64(time.Now().Unix()) - 10.25
	if diff := areaTimestampVal - wantTimestamp; diff > 2 || diff < -2 {
		t.Errorf("frr_ospfv3_area_spf_last_executed_timestamp_seconds: want ~%v, got %v", wantTimestamp, areaTimestampVal)
	}
}
