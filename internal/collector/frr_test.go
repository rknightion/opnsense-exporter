package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
