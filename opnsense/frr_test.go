package opnsense

import (
	"net/http"
	"net/url"
	"testing"
)

// bgpSummaryFixture is derived from FRR `show ip bgp summary json` output
// as wrapped by api/quagga/diagnostics/bgpsummary.
const bgpSummaryFixture = `{
  "response": {
    "ipv4Unicast": {
      "routerId": "10.0.0.1",
      "as": 65001,
      "vrfName": "default",
      "tableVersion": 10,
      "ribCount": 42,
      "ribMemory": 7000,
      "peerCount": 2,
      "peerMemory": 40000,
      "peers": {
        "10.0.0.2": {
          "remoteAs": 65002,
          "version": 4,
          "msgRcvd": 1000,
          "msgSent": 900,
          "tableVersion": 10,
          "outq": 0,
          "inq": 0,
          "peerUptime": "1d02h03m",
          "peerUptimeMsec": 93780000,
          "peerUptimeEstablishedEpoch": 1700000000,
          "pfxRcd": 20,
          "pfxSnt": 15,
          "state": "Established",
          "connectionsEstablished": 1,
          "connectionsDropped": 0,
          "idType": "ipv4"
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
      "displayedPeers": 2,
      "totalPeers": 2,
      "dynamicPeers": 0
    },
    "ipv6Unicast": {
      "routerId": "10.0.0.1",
      "as": 65001,
      "ribCount": 10,
      "peerCount": 1,
      "peers": {
        "2001:db8::2": {
          "remoteAs": 65004,
          "msgRcvd": 200,
          "msgSent": 180,
          "peerUptimeMsec": 5000000,
          "pfxRcd": 5,
          "pfxSnt": 3,
          "state": "Established"
        }
      },
      "failedPeers": 0,
      "totalPeers": 1,
      "dynamicPeers": 0
    }
  }
}`

// bgpSummaryArrayResponse simulates the daemon-disabled configd fallback: `[]`.
const bgpSummaryArrayResponse = `{"response":[]}`

// bgpSummaryDualSAFIFixture activates a neighbor in both the ipv4 unicast and
// multicast SAFIs — two top-level blocks FRR returns separately (#162).
const bgpSummaryDualSAFIFixture = `{
  "response": {
    "ipv4Unicast": {
      "ribCount": 42, "peerCount": 1, "failedPeers": 0,
      "peers": {"10.0.0.2": {"remoteAs": 65002, "msgRcvd": 1, "msgSent": 1, "peerUptimeMsec": 1000, "pfxRcd": 5, "pfxSnt": 3, "state": "Established"}}
    },
    "ipv4Multicast": {
      "ribCount": 7, "peerCount": 1, "failedPeers": 0,
      "peers": {"10.0.0.2": {"remoteAs": 65002, "msgRcvd": 1, "msgSent": 1, "peerUptimeMsec": 1000, "pfxRcd": 2, "pfxSnt": 1, "state": "Established"}}
    }
  }
}`

// TestFrrAFLabel guards #162: distinct upstream SAFIs must not collapse onto the
// same label. Unicast keeps the short label for backward compatibility.
func TestFrrAFLabel(t *testing.T) {
	cases := map[string]string{
		"ipv4Unicast":   "ipv4",
		"ipv4Multicast": "ipv4multicast",
		"ipv6Unicast":   "ipv6",
		"ipv6Multicast": "ipv6multicast",
		"l2VpnEvpn":     "l2vpnevpn",
	}
	seen := map[string]string{}
	for key, want := range cases {
		got := frrAFLabel(key)
		if got != want {
			t.Errorf("frrAFLabel(%q) = %q, want %q", key, got, want)
		}
		if prev, ok := seen[got]; ok {
			t.Errorf("label %q produced by both %q and %q — not injective", got, prev, key)
		}
		seen[got] = key
	}
}

// TestFetchFRRBGP_DualSAFI guards #162: a neighbor activated in both ipv4 unicast
// and multicast must yield two families/peers with distinct AF labels, not a
// collision.
func TestFetchFRRBGP_DualSAFI(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/bgpsummary", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(bgpSummaryDualSAFIFixture))
	})

	data, err := client.FetchFRRBGP()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	afs := map[string]bool{}
	for _, f := range data.Families {
		if afs[f.AF] {
			t.Errorf("duplicate family AF label %q", f.AF)
		}
		afs[f.AF] = true
	}
	if !afs["ipv4"] || !afs["ipv4multicast"] {
		t.Errorf("expected both ipv4 and ipv4multicast families, got %v", afs)
	}
	// The same neighbor in two SAFIs must produce distinct peer label tuples.
	peerAFs := map[string]bool{}
	for _, p := range data.Peers {
		key := p.Peer + "/" + p.AF
		if peerAFs[key] {
			t.Errorf("duplicate peer label tuple %q", key)
		}
		peerAFs[key] = true
	}
}

// ospfOverviewFixture is derived from FRR `show ip ospf json` output.
const ospfOverviewFixture = `{
  "response": {
    "routerId": "10.0.0.1",
    "tosRoutesOnly": false,
    "rfc2328Conform": true,
    "spfScheduleDelayMsecs": 0,
    "holdtimeMinMsecs": 50,
    "holdtimeMaxMsecs": 5000,
    "lsaMinIntervalMsecs": 5000,
    "lsaArrivalMsecs": 1000,
    "areas": {
      "0.0.0.0": {
        "areaIfTotalCounter": 2,
        "areaIfActiveCounter": 2,
        "nbrCount": 2,
        "nbrFullAdjacencyCount": 1,
        "nbrFullAdjacentCounter": 1,
        "lsaNumber": 7,
        "spfExecutedCounter": 12,
        "lsaPerType": {}
      }
    }
  }
}`

// ospfNeighborsFixture is a bootgrid response with both old-style and
// new-style FRR field names to test coalescing.
const ospfNeighborsFixture = `{
  "total": 2,
  "rowCount": 2,
  "current": 1,
  "rows": [
    {
      "neighborid": "10.0.0.2",
      "priority": "1",
      "state": "Full/DR",
      "address": "10.0.0.2",
      "ifaceName": "em0"
    },
    {
      "neighborid": "10.0.0.3",
      "nbrPriority": "1",
      "nbrState": "Init/Other",
      "ifaceAddress": "10.0.0.3",
      "ifaceName": "em1"
    }
  ]
}`

// bfdNeighborsFixture is derived from FRR `show bfd peers json` as keyed by
// the quagga plugin's bfdTreeFetch helper.
const bfdNeighborsFixture = `{
  "response": {
    "10.1.1.2": {
      "peer": "10.1.1.2",
      "local": "10.1.1.1",
      "interface": "em0",
      "status": "up",
      "uptime": 3600,
      "diagnostic": "ok",
      "remote-diagnostic": "ok",
      "id": 1,
      "remote-id": 2
    },
    "10.1.1.3": {
      "peer": "10.1.1.3",
      "local": "10.1.1.1",
      "interface": "em1",
      "status": "down",
      "diagnostic": "no-diagnostic",
      "remote-diagnostic": "no-diagnostic",
      "id": 3,
      "remote-id": 4
    }
  }
}`

// bfdCountersFixture is derived from FRR `show bfd peers counters json`.
const bfdCountersFixture = `{
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
}`

func TestFetchFRRBGP_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/bgpsummary", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(bgpSummaryFixture))
	})

	data, err := client.FetchFRRBGP()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}

	// Check families: ipv4 and ipv6
	if len(data.Families) != 2 {
		t.Fatalf("expected 2 families, got %d", len(data.Families))
	}
	afMap := make(map[string]FRRBGPFamily)
	for _, f := range data.Families {
		afMap[f.AF] = f
	}
	ipv4 := afMap["ipv4"]
	if ipv4.PeerCount != 2 {
		t.Errorf("ipv4 PeerCount: want 2, got %v", ipv4.PeerCount)
	}
	if ipv4.FailedPeers != 1 {
		t.Errorf("ipv4 FailedPeers: want 1, got %v", ipv4.FailedPeers)
	}
	if ipv4.RibCount != 42 {
		t.Errorf("ipv4 RibCount: want 42, got %v", ipv4.RibCount)
	}
	ipv6 := afMap["ipv6"]
	if ipv6.PeerCount != 1 {
		t.Errorf("ipv6 PeerCount: want 1, got %v", ipv6.PeerCount)
	}

	// Check peers
	peerMap := make(map[string]FRRBGPPeer)
	for _, p := range data.Peers {
		key := p.Peer + "/" + p.AF
		peerMap[key] = p
	}
	p1 := peerMap["10.0.0.2/ipv4"]
	if p1.Up != 1 {
		t.Errorf("peer 10.0.0.2 Up: want 1, got %v", p1.Up)
	}
	if p1.PrefixesReceived != 20 {
		t.Errorf("peer 10.0.0.2 PrefixesReceived: want 20, got %v", p1.PrefixesReceived)
	}
	if p1.PrefixesSent != 15 {
		t.Errorf("peer 10.0.0.2 PrefixesSent: want 15, got %v", p1.PrefixesSent)
	}
	if p1.UptimeSeconds != 93780 {
		t.Errorf("peer 10.0.0.2 UptimeSeconds: want 93780, got %v", p1.UptimeSeconds)
	}
	if p1.RemoteAS != "65002" {
		t.Errorf("peer 10.0.0.2 RemoteAS: want 65002, got %v", p1.RemoteAS)
	}
	if p1.MessagesReceived != 1000 {
		t.Errorf("peer 10.0.0.2 MessagesReceived: want 1000, got %v", p1.MessagesReceived)
	}
	if p1.MessagesSent != 900 {
		t.Errorf("peer 10.0.0.2 MessagesSent: want 900, got %v", p1.MessagesSent)
	}

	p2 := peerMap["10.0.0.3/ipv4"]
	if p2.Up != 0 {
		t.Errorf("peer 10.0.0.3 Up: want 0, got %v", p2.Up)
	}
}

func TestFetchFRRBGP_DaemonDisabledArrayResponse(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/bgpsummary", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(bgpSummaryArrayResponse))
	})

	data, err := client.FetchFRRBGP()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Array response (daemon disabled) → Present=false
	if data.Present {
		t.Error("expected Present=false for array response (daemon disabled)")
	}
	if len(data.Families) != 0 {
		t.Errorf("expected 0 families, got %d", len(data.Families))
	}
	if len(data.Peers) != 0 {
		t.Errorf("expected 0 peers, got %d", len(data.Peers))
	}
}

func TestFetchFRRBGP_PluginAbsent404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchFRRBGP()
	if err != nil {
		t.Fatalf("expected nil error on 404, got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on plugin absent 404")
	}
}

func TestFetchFRROSPF_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/ospfoverview", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(ospfOverviewFixture))
	})
	mux.HandleFunc("/api/quagga/diagnostics/searchOspfneighbor", func(w http.ResponseWriter, r *http.Request) {
		// Verify it's a POST with rowCount=-1
		if r.Method != http.MethodPost {
			http.Error(w, "expected POST", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "parse error", http.StatusBadRequest)
			return
		}
		if r.FormValue("rowCount") != "-1" {
			http.Error(w, "expected rowCount=-1", http.StatusBadRequest)
			return
		}
		w.Write([]byte(ospfNeighborsFixture))
	})

	data, err := client.FetchFRROSPF()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}

	// Two neighbors
	if len(data.Neighbors) != 2 {
		t.Fatalf("expected 2 neighbors, got %d", len(data.Neighbors))
	}

	// Find by ID
	nbrMap := make(map[string]FRROSPFNeighbor)
	for _, n := range data.Neighbors {
		nbrMap[n.NeighborID] = n
	}

	n1 := nbrMap["10.0.0.2"]
	if n1.Adjacent != 1 {
		t.Errorf("neighbor 10.0.0.2 Adjacent: want 1, got %v", n1.Adjacent)
	}
	if n1.Interface != "em0" {
		t.Errorf("neighbor 10.0.0.2 Interface: want em0, got %q", n1.Interface)
	}

	n2 := nbrMap["10.0.0.3"]
	if n2.Adjacent != 0 {
		t.Errorf("neighbor 10.0.0.3 Adjacent: want 0 (Init state), got %v", n2.Adjacent)
	}
	if n2.Interface != "em1" {
		t.Errorf("neighbor 10.0.0.3 Interface: want em1, got %q", n2.Interface)
	}

	// Areas
	if len(data.Areas) != 1 {
		t.Fatalf("expected 1 area, got %d", len(data.Areas))
	}
	a := data.Areas[0]
	if a.Area != "0.0.0.0" {
		t.Errorf("area name: want 0.0.0.0, got %q", a.Area)
	}
	if a.InterfacesActive != 2 {
		t.Errorf("area InterfacesActive: want 2, got %v", a.InterfacesActive)
	}
	if a.NeighborsFullAdjacent != 1 {
		t.Errorf("area NeighborsFullAdjacent: want 1, got %v", a.NeighborsFullAdjacent)
	}
	if a.LSACount != 7 {
		t.Errorf("area LSACount: want 7, got %v", a.LSACount)
	}
	if a.SPFExecuted != 12 {
		t.Errorf("area SPFExecuted: want 12, got %v", a.SPFExecuted)
	}
}

func TestFetchFRROSPF_PluginAbsent404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchFRROSPF()
	if err != nil {
		t.Fatalf("expected nil error on 404, got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on plugin absent 404")
	}
}

func TestFetchFRRBFD_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/bfdneighbors", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(bfdNeighborsFixture))
	})
	mux.HandleFunc("/api/quagga/diagnostics/bfdcounters", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(bfdCountersFixture))
	})

	data, err := client.FetchFRRBFD()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if len(data.Peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(data.Peers))
	}

	peerMap := make(map[string]FRRBFDPeer)
	for _, p := range data.Peers {
		peerMap[p.Peer] = p
	}

	p1 := peerMap["10.1.1.2"]
	if p1.Up != 1 {
		t.Errorf("peer 10.1.1.2 Up: want 1, got %v", p1.Up)
	}
	if p1.UptimeSeconds != 3600 {
		t.Errorf("peer 10.1.1.2 UptimeSeconds: want 3600, got %v", p1.UptimeSeconds)
	}
	if p1.Interface != "em0" {
		t.Errorf("peer 10.1.1.2 Interface: want em0, got %q", p1.Interface)
	}
	if !p1.HasCounters {
		t.Error("peer 10.1.1.2: expected HasCounters=true")
	}
	if p1.ControlIn != 1000 {
		t.Errorf("peer 10.1.1.2 ControlIn: want 1000, got %v", p1.ControlIn)
	}
	if p1.ControlOut != 990 {
		t.Errorf("peer 10.1.1.2 ControlOut: want 990, got %v", p1.ControlOut)
	}
	if p1.SessionUpEvents != 1 {
		t.Errorf("peer 10.1.1.2 SessionUpEvents: want 1, got %v", p1.SessionUpEvents)
	}
	if p1.SessionDownEvents != 0 {
		t.Errorf("peer 10.1.1.2 SessionDownEvents: want 0, got %v", p1.SessionDownEvents)
	}

	p2 := peerMap["10.1.1.3"]
	if p2.Up != 0 {
		t.Errorf("peer 10.1.1.3 Up: want 0, got %v", p2.Up)
	}
	if p2.HasCounters {
		t.Error("peer 10.1.1.3: expected HasCounters=false (no counters entry)")
	}
}

func TestFetchFRRBFD_CountersMissing(t *testing.T) {
	// Neighbors endpoint returns data, but counters endpoint returns 404.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/bfdneighbors", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(bfdNeighborsFixture))
	})
	mux.HandleFunc("/api/quagga/diagnostics/bfdcounters", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})

	data, err := client.FetchFRRBFD()
	if err != nil {
		t.Fatalf("expected nil error when counters 404, got: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true (neighbors responded)")
	}
	if len(data.Peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(data.Peers))
	}
	for _, p := range data.Peers {
		if p.HasCounters {
			t.Errorf("peer %s: expected HasCounters=false when counters endpoint absent", p.Peer)
		}
	}
}

func TestFetchFRRBFD_PluginAbsent404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchFRRBFD()
	if err != nil {
		t.Fatalf("expected nil error on 404, got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on plugin absent 404")
	}
}

// TestFetchFRROSPF_NeighborSearchRowCount verifies the neighbors POST uses rowCount=-1.
func TestFetchFRROSPF_NeighborSearchRowCount(t *testing.T) {
	receivedForm := url.Values{}

	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/ospfoverview", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(ospfOverviewFixture))
	})
	mux.HandleFunc("/api/quagga/diagnostics/searchOspfneighbor", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err == nil {
			receivedForm = r.Form
		}
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})

	_, err := client.FetchFRROSPF()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := receivedForm.Get("rowCount"); got != "-1" {
		t.Errorf("neighbors POST rowCount: want -1, got %q", got)
	}
}

// --- BGP Neighbor Session Detail (#197) ---

// bgpNeighborsBouncedFixture is derived from the dev-box capture
// bgpneighbors_bounced.json (2026-07-13): a real eBGP session AS65001<->AS65002
// after being bounced once (connectionsEstablished=2, connectionsDropped=1).
const bgpNeighborsBouncedFixture = `{
  "response": {
    "172.16.9.99": {
      "neighborAddr": "172.16.9.99",
      "remoteAs": 65002,
      "bgpState": "Established",
      "bgpTimerUpMsec": 45000,
      "connectionsEstablished": 2,
      "connectionsDropped": 1,
      "lastResetTimerMsecs": 508000,
      "lastResetDueTo": "Peer closed the session",
      "lastResetCode": 15,
      "messageStats": {
        "depthInq": 0,
        "depthOutq": 0,
        "opensSent": 2,
        "opensRecv": 2,
        "notificationsSent": 0,
        "notificationsRecv": 0,
        "updatesSent": 4,
        "updatesRecv": 6,
        "keepalivesSent": 14,
        "keepalivesRecv": 12,
        "routeRefreshSent": 0,
        "routeRefreshRecv": 0,
        "capabilitySent": 0,
        "capabilityRecv": 0,
        "totalSent": 20,
        "totalRecv": 20
      },
      "addressFamilyInfo": {
        "ipv4Unicast": {
          "updateGroupId": 2,
          "subGroupId": 2,
          "packetQueueLength": 0,
          "acceptedPrefixCounter": 3,
          "sentPrefixCounter": 3
        }
      }
    }
  }
}`

func TestFetchFRRBGPNeighbors_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/bgpneighbors", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(bgpNeighborsBouncedFixture))
	})

	data, err := client.FetchFRRBGPNeighbors()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if len(data.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(data.Peers))
	}

	peer := data.Peers[0]
	if peer.Peer != "172.16.9.99" {
		t.Errorf("Peer: want 172.16.9.99, got %q", peer.Peer)
	}
	if peer.ConnectionsEstablished != 2 {
		t.Errorf("ConnectionsEstablished: want 2, got %v", peer.ConnectionsEstablished)
	}
	if peer.ConnectionsDropped != 1 {
		t.Errorf("ConnectionsDropped: want 1, got %v", peer.ConnectionsDropped)
	}
	if peer.LastResetSeconds != 508 {
		t.Errorf("LastResetSeconds: want 508, got %v", peer.LastResetSeconds)
	}
	if peer.LastResetDueTo != "Peer closed the session" {
		t.Errorf("LastResetDueTo: want %q, got %q", "Peer closed the session", peer.LastResetDueTo)
	}
	if peer.QueueDepthIn != 0 || peer.QueueDepthOut != 0 {
		t.Errorf("QueueDepth: want 0/0, got %v/%v", peer.QueueDepthIn, peer.QueueDepthOut)
	}

	if len(peer.Messages) != 12 {
		t.Fatalf("expected 12 message counters (6 types x 2 directions), got %d", len(peer.Messages))
	}
	var sawUpdateSent, sawKeepaliveRecv bool
	for _, m := range peer.Messages {
		if m.Type == "update" && m.Direction == "sent" {
			sawUpdateSent = true
			if m.Count != 4 {
				t.Errorf("update/sent count: want 4, got %v", m.Count)
			}
		}
		if m.Type == "keepalive" && m.Direction == "received" {
			sawKeepaliveRecv = true
			if m.Count != 12 {
				t.Errorf("keepalive/received count: want 12, got %v", m.Count)
			}
		}
	}
	if !sawUpdateSent || !sawKeepaliveRecv {
		t.Error("expected both update/sent and keepalive/received message counters")
	}

	if len(peer.Prefixes) != 1 {
		t.Fatalf("expected 1 AF prefix entry, got %d", len(peer.Prefixes))
	}
	if peer.Prefixes[0].AF != "ipv4" {
		t.Errorf("Prefixes[0].AF: want ipv4, got %q", peer.Prefixes[0].AF)
	}
	if peer.Prefixes[0].Count != 3 {
		t.Errorf("Prefixes[0].Count: want 3, got %v", peer.Prefixes[0].Count)
	}
}

func TestFetchFRRBGPNeighbors_PluginAbsent404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchFRRBGPNeighbors()
	if err != nil {
		t.Fatalf("expected nil error on 404, got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on plugin absent 404")
	}
}

func TestFetchFRRBGPNeighbors_DaemonDisabledArrayResponse(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/bgpneighbors", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response":[]}`))
	})

	data, err := client.FetchFRRBGPNeighbors()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false for daemon-disabled array response")
	}
}

// --- OSPF Interface Detail + OSPFv3 parity (#198) ---

// ospfInterfaceWrappedFixture is derived from the dev-box capture
// ospfinterface.json (2026-07-13): a real Full/DR adjacency on FRR 10.3, which
// uses the "interfaces"-wrapped (FRR>=8) shape.
const ospfInterfaceWrappedFixture = `{
  "response": {
    "interfaces": {
      "vtnet2": {
        "ifUp": true,
        "mtuBytes": 1500,
        "bandwidthMbit": 10000,
        "ospfEnabled": true,
        "area": "0.0.0.0",
        "networkType": "BROADCAST",
        "cost": 10,
        "state": "DR",
        "priority": 1,
        "nbrCount": 1,
        "nbrAdjacentCount": 1
      }
    }
  }
}`

// ospfInterfaceFlatFixture simulates the older, pre-FRR-8 top-level (unwrapped) shape.
const ospfInterfaceFlatFixture = `{
  "response": {
    "em0": {
      "ifUp": true,
      "mtuBytes": 1500,
      "bandwidthMbit": 1000,
      "ospfEnabled": true,
      "area": "0.0.0.0",
      "networkType": "BROADCAST",
      "cost": 1,
      "state": "BDR",
      "priority": 1,
      "nbrCount": 1,
      "nbrAdjacentCount": 1
    }
  }
}`

func TestFetchFRROSPFInterfaces_WrappedShape(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/ospfinterface", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(ospfInterfaceWrappedFixture))
	})

	data, err := client.FetchFRROSPFInterfaces()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if len(data.Interfaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(data.Interfaces))
	}
	iface := data.Interfaces[0]
	if iface.Interface != "vtnet2" {
		t.Errorf("Interface: want vtnet2, got %q", iface.Interface)
	}
	if iface.Area != "0.0.0.0" {
		t.Errorf("Area: want 0.0.0.0, got %q", iface.Area)
	}
	if iface.State != "DR" {
		t.Errorf("State: want DR, got %q", iface.State)
	}
	if iface.Up != 1 {
		t.Errorf("Up: want 1, got %v", iface.Up)
	}
	if iface.Cost != 10 {
		t.Errorf("Cost: want 10, got %v", iface.Cost)
	}
	if iface.NbrCount != 1 || iface.NbrAdjacentCount != 1 {
		t.Errorf("NbrCount/NbrAdjacentCount: want 1/1, got %v/%v", iface.NbrCount, iface.NbrAdjacentCount)
	}
}

func TestFetchFRROSPFInterfaces_FlatShape(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/ospfinterface", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(ospfInterfaceFlatFixture))
	})

	data, err := client.FetchFRROSPFInterfaces()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if len(data.Interfaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(data.Interfaces))
	}
	if data.Interfaces[0].Interface != "em0" {
		t.Errorf("Interface: want em0, got %q", data.Interfaces[0].Interface)
	}
	if data.Interfaces[0].State != "BDR" {
		t.Errorf("State: want BDR, got %q", data.Interfaces[0].State)
	}
}

func TestFetchFRROSPFInterfaces_PluginAbsent404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchFRROSPFInterfaces()
	if err != nil {
		t.Fatalf("expected nil error on 404, got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on plugin absent 404")
	}
}

func TestFetchFRROSPFv3Overview_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/ospfv3overview", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
  "response": {
    "routerId": "172.16.9.1",
    "numberOfAsScopedLsa": 0,
    "areas": {
      "0.0.0.0": {"numberOfAreaScopedLsa": 4}
    }
  }
}`))
	})

	data, err := client.FetchFRROSPFv3Overview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if len(data.Areas) != 1 {
		t.Fatalf("expected 1 area, got %d", len(data.Areas))
	}
	if data.Areas[0].Area != "0.0.0.0" {
		t.Errorf("Area: want 0.0.0.0, got %q", data.Areas[0].Area)
	}
	if data.Areas[0].LSACount != 4 {
		t.Errorf("LSACount: want 4, got %v", data.Areas[0].LSACount)
	}
}

// TestFetchFRROSPFv3Overview_DisabledEmptyShape uses the exact dev-box capture
// (ospfv3overview.json, 2026-07-13): `{"response":[]}` — ospf6d disabled since
// the lab LXC has no IPv6 stack. This is the only OSPFv3 shape confirmed live.
func TestFetchFRROSPFv3Overview_DisabledEmptyShape(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/ospfv3overview", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response":[]}`))
	})

	data, err := client.FetchFRROSPFv3Overview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false for the captured disabled/empty shape")
	}
}

func TestFetchFRROSPFv3Overview_PluginAbsent404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchFRROSPFv3Overview()
	if err != nil {
		t.Fatalf("expected nil error on 404, got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on plugin absent 404")
	}
}

func TestFetchFRROSPFv3Interfaces_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/ospfv3interface", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
  "response": {
    "vtnet2": {
      "status": "up",
      "type": "BROADCAST",
      "areaId": "0.0.0.0",
      "cost": 10,
      "priority": 1,
      "ospf6InterfaceState": "DR",
      "numberOfInterfaceScopedLsa": 2,
      "pendingLsaLsUpdateCount": 0,
      "pendingLsaLsAckCount": 0
    }
  }
}`))
	})

	data, err := client.FetchFRROSPFv3Interfaces()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if len(data.Interfaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(data.Interfaces))
	}
	iface := data.Interfaces[0]
	if iface.Interface != "vtnet2" {
		t.Errorf("Interface: want vtnet2, got %q", iface.Interface)
	}
	if iface.Area != "0.0.0.0" {
		t.Errorf("Area: want 0.0.0.0, got %q", iface.Area)
	}
	if iface.State != "DR" {
		t.Errorf("State: want DR, got %q", iface.State)
	}
	if iface.Up != 1 {
		t.Errorf("Up: want 1, got %v", iface.Up)
	}
}

// TestFetchFRROSPFv3Interfaces_DisabledEmptyShape uses the exact dev-box
// capture (ospfv3interface.json, 2026-07-13): `{"response":[]}`.
func TestFetchFRROSPFv3Interfaces_DisabledEmptyShape(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/ospfv3interface", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response":[]}`))
	})

	data, err := client.FetchFRROSPFv3Interfaces()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false for the captured disabled/empty shape")
	}
}

func TestFetchFRROSPFv3Interfaces_PluginAbsent404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchFRROSPFv3Interfaces()
	if err != nil {
		t.Fatalf("expected nil error on 404, got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on plugin absent 404")
	}
}

// --- Routing-state volume gauges (#199) ---

// generalRoute4Fixture mirrors the shape (not the size) of the dev-box capture
// search_generalroute4.json: two nexthop rows for the same kernel default
// route (ECMP-style duplicate prefix) plus one connected and one ospf route.
const generalRoute4Fixture = `{
  "total": 4,
  "rowCount": 4,
  "current": 1,
  "rows": [
    {"prefix": "0.0.0.0/0", "protocol": "kernel", "afi": "ipv4"},
    {"prefix": "0.0.0.0/0", "protocol": "kernel", "afi": "ipv4"},
    {"prefix": "172.16.9.0/24", "protocol": "connected", "afi": "ipv4"},
    {"prefix": "172.16.30.0/24", "protocol": "ospf", "afi": "ipv4"}
  ]
}`

func TestFetchFRRRouteVolumes_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/search_generalroute4", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(generalRoute4Fixture))
	})
	mux.HandleFunc("/api/quagga/diagnostics/search_generalroute6", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	mux.HandleFunc("/api/quagga/diagnostics/search_ospfroute", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":2,"rowCount":2,"current":1,"rows":[
			{"type": "N", "network": "172.16.9.0/24"},
			{"type": "N E2", "network": "172.16.30.0/24"}
		]}`))
	})
	mux.HandleFunc("/api/quagga/diagnostics/search_ospfv3route", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	mux.HandleFunc("/api/quagga/diagnostics/ospfdatabase", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
  "response": {
    "areas": {
      "0.0.0.0": {"routerLinkStatesCount": 2, "networkLinkStatesCount": 1}
    },
    "asExternalLinkStatesCount": 1
  }
}`))
	})
	mux.HandleFunc("/api/quagga/diagnostics/search_ospfv3database", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})

	data, err := client.FetchFRRRouteVolumes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}

	routeByProto := map[string]FRRRouteCount{}
	for _, r := range data.Routes {
		routeByProto[r.AF+"/"+r.Protocol] = r
	}
	kernel := routeByProto["ipv4/kernel"]
	if kernel.RouteCount != 1 {
		t.Errorf("ipv4/kernel RouteCount (dedup by prefix): want 1, got %v", kernel.RouteCount)
	}
	if kernel.NexthopCount != 2 {
		t.Errorf("ipv4/kernel NexthopCount: want 2, got %v", kernel.NexthopCount)
	}
	connected := routeByProto["ipv4/connected"]
	if connected.RouteCount != 1 || connected.NexthopCount != 1 {
		t.Errorf("ipv4/connected: want 1/1, got %v/%v", connected.RouteCount, connected.NexthopCount)
	}

	if len(data.OSPFRoutes) != 2 {
		t.Fatalf("expected 2 OSPF route types, got %d", len(data.OSPFRoutes))
	}
	if len(data.OSPFv3Routes) != 0 {
		t.Errorf("expected 0 OSPFv3 routes (empty capture), got %d", len(data.OSPFv3Routes))
	}

	lsaByKey := map[string]float64{}
	for _, l := range data.OSPFLSA {
		lsaByKey[l.Area+"/"+l.LSAType] = l.Count
	}
	if lsaByKey["0.0.0.0/router"] != 2 {
		t.Errorf("0.0.0.0/router LSA count: want 2, got %v", lsaByKey["0.0.0.0/router"])
	}
	if lsaByKey["0.0.0.0/network"] != 1 {
		t.Errorf("0.0.0.0/network LSA count: want 1, got %v", lsaByKey["0.0.0.0/network"])
	}
	if lsaByKey["/external"] != 1 {
		t.Errorf("external LSA count: want 1, got %v", lsaByKey["/external"])
	}

	if len(data.OSPFv3LSA) != 0 {
		t.Errorf("expected 0 OSPFv3 LSA scopes (empty capture), got %d", len(data.OSPFv3LSA))
	}
}

func TestFetchFRRRouteVolumes_PluginAbsent404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchFRRRouteVolumes()
	if err != nil {
		t.Fatalf("expected nil error on 404, got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false when every sub-endpoint 404s")
	}
	if len(data.Routes) != 0 || len(data.OSPFRoutes) != 0 || len(data.OSPFLSA) != 0 {
		t.Error("expected no data when plugin absent")
	}
}

// TestFetchFRRRouteVolumes_PartialAbsent verifies that an individual
// sub-endpoint 404 (e.g. ospfv3 daemons disabled/unsupported) only omits that
// slice rather than failing the whole fetch — mirroring the dev-box lab,
// where ospf6d has no IPv6 stack to run on but IPv4 RIB/OSPF data is real.
func TestFetchFRRRouteVolumes_PartialAbsent(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/search_generalroute4", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(generalRoute4Fixture))
	})
	// search_generalroute6, search_ospfroute, search_ospfv3route, ospfdatabase,
	// search_ospfv3database are left unregistered -> 404 from the mux.

	data, err := client.FetchFRRRouteVolumes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true: at least one sub-endpoint answered")
	}
	if len(data.Routes) == 0 {
		t.Error("expected ipv4 route counts from the one answering endpoint")
	}
	if len(data.OSPFRoutes) != 0 {
		t.Error("expected no OSPF route counts when search_ospfroute 404s")
	}
}
