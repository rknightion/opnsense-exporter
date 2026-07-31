package opnsense

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
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
// spfLastExecutedMsecs/spfLastDurationMsecs (#582) are genuine numeric FRR
// fields (ospf_vty.c ~3451-3463, verified against FRRouting/frr master) —
// 5000ms "ago" and a 42ms last-run duration.
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
    "spfLastExecutedMsecs": 5000,
    "spfLastDurationMsecs": 42,
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

// ospfOverviewMalformedFixture claims to be an object — so the daemon-disabled
// `[` fallback does not apply — but types `areas` as a string, which cannot be
// decoded into the per-area map. That is genuine corruption or drift, not an
// idle box, and must surface as an error rather than partial success (#378).
const ospfOverviewMalformedFixture = `{"response":{"routerId":"10.0.0.1","areas":"0.0.0.0"}}`

// ospfOverviewEmptyAreasArrayFixture is the PHP empty-map quirk applied to
// `areas`: the quagga controller json_decodes FRR's output into a PHP assoc
// array and the framework re-encodes it, so an OSPF instance with zero areas
// arrives as [] rather than {} (same quirk flexStringMap exists for). A
// legitimate wire shape, so it must stay error-free.
const ospfOverviewEmptyAreasArrayFixture = `{"response":{"routerId":"10.0.0.1","areas":[]}}`

// ospfOverviewArrayResponse is the daemon-disabled configd fallback: `[]`.
const ospfOverviewArrayResponse = `{"response":[]}`

// ospfNeighborsEmptyFixture is an empty bootgrid result set.
const ospfNeighborsEmptyFixture = `{"total":0,"rowCount":0,"current":1,"rows":[]}`

// ospfNeighborsFixture is a bootgrid response with both old-style and
// new-style FRR field names to test coalescing.
//
// #582 adjacency-stability fields, verified against FRRouting/frr master
// (ospfd/ospf_vty.c show_ip_ospf_neighbour_brief ~5180-5234): 10.0.0.2 (Full)
// carries the "active timer" shape — converged holds the raw NSM state name,
// upTimeInMsec/routerDeadIntervalTimerDueMsec are both genuine numbers, and
// the LSA queue-depth counters are a live nonzero retransmission backlog.
// 10.0.0.3 (Init) carries the "no inactivity timer scheduled" shape FRR sends
// for a neighbor that hasn't progressed: upTimeInMsec is omitted entirely and
// routerDeadIntervalTimerDueMsec is the literal string "inactive" rather than
// a number — both must decode to "no reading", never a fabricated 0.
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
      "nbrPriority": "1",
      "nbrState": "Init/Other",
      "ifaceAddress": "10.0.0.3",
      "ifaceName": "em1",
      "converged": "Init",
      "routerDeadIntervalTimerDueMsec": "inactive",
      "databaseSummaryListCounter": 0,
      "linkStateRequestListCounter": 0,
      "linkStateRetransmissionListCounter": 0
    }
  ]
}`

// bfdNeighborsFixture is derived from FRR `show bfd peers json` as keyed by
// the quagga plugin's bfdTreeFetch helper. It covers three of FRR's session
// states (bfdd_vty.c:364-385): PTM_BFD_UP (10.1.1.2, carries "uptime", no
// "downtime"), PTM_BFD_DOWN (10.1.1.3, carries "downtime", no "uptime"), and
// PTM_BFD_INIT (10.1.1.4, carries NEITHER — that absence is the point of
// TestFetchFRRBFD_DiagnosticRTTAndDownDuration below). diagnostic/
// remote-diagnostic values are real diag2str() strings (bfdd/bfd.c:1922-1946)
// — "ok" (diag 0), "neighbor signaled session down" (diag 3) and "control
// detection time expired" (diag 1) — not invented ones; rtt-min/avg/max are
// always present per bfdd_vty.c:433-436 (unconditional, not gated by state).
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
      "rtt-min": 500,
      "rtt-avg": 750,
      "rtt-max": 1200,
      "id": 1,
      "remote-id": 2
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
      "rtt-max": 0,
      "id": 3,
      "remote-id": 4
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
      "rtt-max": 0,
      "id": 5,
      "remote-id": 6
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
      "session-up": 1,
      "session-down": 0,
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

// TestFrrOSPFDeadIntervalDue_UnmarshalJSON guards #582's dead-timer decode
// directly: FRR sends this field as a JSON number OR the literal string
// "inactive" depending on neighbor state (ospf_vty.c ~5195-5219). A decode
// that coerced "inactive" (or any other unexpected shape) into 0 would be
// indistinguishable from a genuine "dead timer expires in 0s" reading.
func TestFrrOSPFDeadIntervalDue_UnmarshalJSON(t *testing.T) {
	cases := []struct {
		name        string
		json        string
		wantPresent bool
		wantMsec    float64
	}{
		{"number", `32000`, true, 32000},
		{"zero_is_a_real_reading", `0`, true, 0},
		{"inactive_string", `"inactive"`, false, 0},
		{"unexpected_string", `"unknown"`, false, 0},
		{"null", `null`, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var d frrOSPFDeadIntervalDue
			if err := json.Unmarshal([]byte(tc.json), &d); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d.Present != tc.wantPresent {
				t.Errorf("Present: want %v, got %v", tc.wantPresent, d.Present)
			}
			if tc.wantPresent && d.Msec != tc.wantMsec {
				t.Errorf("Msec: want %v, got %v", tc.wantMsec, d.Msec)
			}
		})
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
	// #582: n1 carries FRR's "active inactivity timer" shape — both timer
	// fields are genuine numbers.
	if n1.NSMState != "Full" {
		t.Errorf("neighbor 10.0.0.2 NSMState: want Full, got %q", n1.NSMState)
	}
	if !n1.HasUptime {
		t.Error("neighbor 10.0.0.2 HasUptime: want true (upTimeInMsec present)")
	}
	if n1.UptimeSeconds != 93780 {
		t.Errorf("neighbor 10.0.0.2 UptimeSeconds: want 93780, got %v", n1.UptimeSeconds)
	}
	if !n1.HasDeadTimer {
		t.Error("neighbor 10.0.0.2 HasDeadTimer: want true (routerDeadIntervalTimerDueMsec is numeric)")
	}
	if n1.DeadTimerSeconds != 32 {
		t.Errorf("neighbor 10.0.0.2 DeadTimerSeconds: want 32, got %v", n1.DeadTimerSeconds)
	}
	if n1.LinkStateRetransmissionQueueDepth != 2 {
		t.Errorf("neighbor 10.0.0.2 LinkStateRetransmissionQueueDepth: want 2, got %v", n1.LinkStateRetransmissionQueueDepth)
	}
	if n1.DatabaseSummaryQueueDepth != 0 || n1.LinkStateRequestQueueDepth != 0 {
		t.Errorf("neighbor 10.0.0.2 db_summary/ls_request queue depths: want 0/0, got %v/%v",
			n1.DatabaseSummaryQueueDepth, n1.LinkStateRequestQueueDepth)
	}

	n2 := nbrMap["10.0.0.3"]
	if n2.Adjacent != 0 {
		t.Errorf("neighbor 10.0.0.3 Adjacent: want 0 (Init state), got %v", n2.Adjacent)
	}
	if n2.Interface != "em1" {
		t.Errorf("neighbor 10.0.0.3 Interface: want em1, got %q", n2.Interface)
	}
	// #582: n2 carries FRR's "no inactivity timer scheduled" shape — upTimeInMsec
	// is omitted and routerDeadIntervalTimerDueMsec is the string "inactive".
	// GUARDS: a naive numeric decode of "inactive" (e.g. via flexInt, which
	// silently maps any unparseable value to 0) would turn "no dead timer" into
	// a fabricated "0 seconds until expiry" — indistinguishable from a neighbor
	// on the brink of dropping. HasDeadTimer must stay false here.
	if n2.NSMState != "Init" {
		t.Errorf("neighbor 10.0.0.3 NSMState: want Init, got %q", n2.NSMState)
	}
	if n2.HasUptime {
		t.Error("neighbor 10.0.0.3 HasUptime: want false (upTimeInMsec key absent)")
	}
	if n2.HasDeadTimer {
		t.Error(`neighbor 10.0.0.3 HasDeadTimer: want false (routerDeadIntervalTimerDueMsec is "inactive")`)
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

	// #582: instance-level SPF-run timing. SPFLastExecutedTimestamp is
	// computed from a fixed "5000ms ago" reading at call time, so assert it
	// lands within a generous window of time.Now() rather than an exact value.
	if !data.HasSPFLastExecuted {
		t.Error("expected HasSPFLastExecuted=true")
	}
	wantTimestamp := float64(time.Now().Unix()) - 5.0
	if diff := data.SPFLastExecutedTimestamp - wantTimestamp; diff > 2 || diff < -2 {
		t.Errorf("SPFLastExecutedTimestamp: want ~%v, got %v", wantTimestamp, data.SPFLastExecutedTimestamp)
	}
	if !data.HasSPFLastDuration {
		t.Error("expected HasSPFLastDuration=true")
	}
	if data.SPFLastDurationSeconds != 0.042 {
		t.Errorf("SPFLastDurationSeconds: want 0.042, got %v", data.SPFLastDurationSeconds)
	}
}

// TestFetchFRROSPF_SPFTimingAbsentBeforeFirstRun guards #582: FRR omits
// spfLastExecutedMsecs/spfLastDurationMsecs entirely (sending a bare
// "spfHasNotRun": true instead) until the OSPF instance's first SPF
// calculation. Both HasSPFLastExecuted/HasSPFLastDuration must stay false —
// never a fabricated "SPF ran 0ms ago" reading.
func TestFetchFRROSPF_SPFTimingAbsentBeforeFirstRun(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/ospfoverview", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response":{"routerId":"10.0.0.1","spfHasNotRun":true,"areas":{}}}`))
	})
	mux.HandleFunc("/api/quagga/diagnostics/searchOspfneighbor", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(ospfNeighborsEmptyFixture))
	})

	data, err := client.FetchFRROSPF()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.HasSPFLastExecuted {
		t.Error("expected HasSPFLastExecuted=false before the instance's first SPF run")
	}
	if data.HasSPFLastDuration {
		t.Error("expected HasSPFLastDuration=false before the instance's first SPF run")
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

// TestFetchFRROSPF_MalformedOverviewSurfacesDecodeError guards #378: the second
// decode stage of the ospfoverview payload used to swallow its error, so a
// corrupted or drifted overview produced partial-success metrics (Present=true,
// zero areas) while the collector looked healthy.
func TestFetchFRROSPF_MalformedOverviewSurfacesDecodeError(t *testing.T) {
	cases := []struct {
		name         string
		overview     string
		wantContains []string
	}{
		{"areas_wrong_type", ospfOverviewMalformedFixture, []string{"decode", "areas"}},
		{"area_value_wrong_type", `{"response":{"areas":{"0.0.0.0":"broken"}}}`, []string{"decode", "areas"}},
		{"response_not_an_object", `{"response":"quagga is not running"}`, []string{"decode"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			neighborsCalled := false

			server, mux, client := newTestClientWithMux(t)
			defer server.Close()

			mux.HandleFunc("/api/quagga/diagnostics/ospfoverview", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.overview))
			})
			mux.HandleFunc("/api/quagga/diagnostics/searchOspfneighbor", func(w http.ResponseWriter, r *http.Request) {
				neighborsCalled = true
				w.Write([]byte(ospfNeighborsEmptyFixture))
			})

			data, err := client.FetchFRROSPF()
			if err == nil {
				t.Fatal("expected an error for a malformed overview object, got nil")
			}
			if err.Endpoint != "quaggaOspfOverview" {
				t.Errorf("error Endpoint: want quaggaOspfOverview, got %q", err.Endpoint)
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(err.Message, want) {
					t.Errorf("error Message should mention %q, got %q", want, err.Message)
				}
			}
			if data.Present {
				t.Error("Present must stay false when the overview cannot be decoded")
			}
			if len(data.Areas) != 0 {
				t.Errorf("expected no areas from a malformed overview, got %d", len(data.Areas))
			}
			if len(data.Neighbors) != 0 {
				t.Errorf("expected no neighbors when the overview decode failed, got %d", len(data.Neighbors))
			}
			if neighborsCalled {
				t.Error("neighbors POST must not run after an overview decode failure (no partial data)")
			}
		})
	}
}

// TestFetchFRROSPF_BenignOverviewShapesRetainBehaviour pins the shapes that must
// keep their pre-#378 behaviour: a valid object, the daemon-disabled `[]`
// fallback, the PHP empty-map-as-[] quirk on `areas`, and empty/absent/null
// payloads. All are error-free with Present=true.
func TestFetchFRROSPF_BenignOverviewShapesRetainBehaviour(t *testing.T) {
	cases := []struct {
		name      string
		overview  string
		wantAreas int
	}{
		{"valid_object", ospfOverviewFixture, 1},
		{"daemon_disabled_array", ospfOverviewArrayResponse, 0},
		{"empty_areas_array", ospfOverviewEmptyAreasArrayFixture, 0},
		{"empty_response_object", `{"response":{}}`, 0},
		{"absent_response_key", `{}`, 0},
		{"null_response", `{"response":null}`, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, mux, client := newTestClientWithMux(t)
			defer server.Close()

			mux.HandleFunc("/api/quagga/diagnostics/ospfoverview", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.overview))
			})
			mux.HandleFunc("/api/quagga/diagnostics/searchOspfneighbor", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(ospfNeighborsEmptyFixture))
			})

			data, err := client.FetchFRROSPF()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !data.Present {
				t.Error("expected Present=true")
			}
			if len(data.Areas) != tc.wantAreas {
				t.Errorf("areas: want %d, got %d", tc.wantAreas, len(data.Areas))
			}
		})
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
	if len(data.Peers) != 3 {
		t.Fatalf("expected 3 peers, got %d", len(data.Peers))
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

// TestFetchFRRBFD_DiagnosticRTTAndDownDuration covers #484: diagnostic/
// remote-diagnostic labels, the rtt-min/avg/max gauges, and down-duration
// modelling. The critical assertion is on the INIT peer (10.1.1.4): FRR emits
// neither "uptime" nor "downtime" for PTM_BFD_INIT (bfdd_vty.c:373-375), so
// HasDowntime must be false there — absence must stay absence, never a
// silently-invented zero.
func TestFetchFRRBFD_DiagnosticRTTAndDownDuration(t *testing.T) {
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
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Peers) != 3 {
		t.Fatalf("expected 3 peers, got %d", len(data.Peers))
	}

	peerMap := make(map[string]FRRBFDPeer)
	for _, p := range data.Peers {
		peerMap[p.Peer] = p
	}

	// UP peer: diagnostic "ok", RTT populated, no downtime.
	up := peerMap["10.1.1.2"]
	if up.Diagnostic != "ok" {
		t.Errorf("up peer Diagnostic: want %q, got %q", "ok", up.Diagnostic)
	}
	if up.RemoteDiagnostic != "ok" {
		t.Errorf("up peer RemoteDiagnostic: want %q, got %q", "ok", up.RemoteDiagnostic)
	}
	if up.RTTMinUsec != 500 || up.RTTAvgUsec != 750 || up.RTTMaxUsec != 1200 {
		t.Errorf("up peer RTT: want 500/750/1200, got %v/%v/%v", up.RTTMinUsec, up.RTTAvgUsec, up.RTTMaxUsec)
	}
	if up.HasDowntime {
		t.Error("up peer: expected HasDowntime=false")
	}

	// DOWN peer: real diag2str reason strings, downtime present.
	down := peerMap["10.1.1.3"]
	if down.Diagnostic != "neighbor signaled session down" {
		t.Errorf("down peer Diagnostic: want %q, got %q", "neighbor signaled session down", down.Diagnostic)
	}
	if down.RemoteDiagnostic != "control detection time expired" {
		t.Errorf("down peer RemoteDiagnostic: want %q, got %q", "control detection time expired", down.RemoteDiagnostic)
	}
	if !down.HasDowntime {
		t.Fatal("down peer: expected HasDowntime=true")
	}
	if down.DowntimeSeconds != 120 {
		t.Errorf("down peer DowntimeSeconds: want 120, got %v", down.DowntimeSeconds)
	}

	// INIT peer: the whole point of #484 — neither uptime nor downtime is
	// present on the wire, so both must stay absent, not read as zero.
	init := peerMap["10.1.1.4"]
	if init.HasDowntime {
		t.Errorf("init peer: expected HasDowntime=false (FRR emits neither uptime nor downtime "+
			"for PTM_BFD_INIT), got HasDowntime=true DowntimeSeconds=%v", init.DowntimeSeconds)
	}
	if init.UptimeSeconds != 0 {
		t.Errorf("init peer UptimeSeconds: want 0 (absent on wire), got %v", init.UptimeSeconds)
	}
}

// bfdCountersFRRNamesFixture uses the field names FRR's bfdd actually emits.
//
// FRR builds this payload in bfdd/bfdd_vty.c with json_object_int_add(jo,
// "session-up", ...) / "session-down" — NOT "session-up-events" /
// "session-down-events", which appear nowhere in FRR on master or on any
// release in the support window (checked against stable/8.5, 9.1, 10.0 and
// 10.2). The OPNsense quagga plugin is a pure vtysh passthrough — actions_quagga.conf
// runs `show bfd peers counters json` and DiagnosticsController only re-keys the
// array by peer — so these are the names that arrive on the wire.
//
// Both counters are deliberately non-zero here: a zero expectation cannot tell a
// correctly-decoded field from one whose json tag matches nothing at all.
const bfdCountersFRRNamesFixture = `{
  "response": {
    "10.1.1.2": {
      "peer": "10.1.1.2",
      "control-packet-input": 1000,
      "control-packet-output": 990,
      "session-up": 7,
      "session-down": 6
    }
  }
}`

func TestFetchFRRBFD_CounterTagsMatchFRRWireNames(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/bfdneighbors", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(bfdNeighborsFixture))
	})
	mux.HandleFunc("/api/quagga/diagnostics/bfdcounters", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(bfdCountersFRRNamesFixture))
	})

	data, err := client.FetchFRRBFD()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var peer FRRBFDPeer
	for _, p := range data.Peers {
		if p.Peer == "10.1.1.2" {
			peer = p
		}
	}
	if !peer.HasCounters {
		t.Fatal("peer 10.1.1.2: expected HasCounters=true")
	}
	if peer.SessionUpEvents != 7 {
		t.Errorf("SessionUpEvents: want 7, got %v (json tag does not match FRR's \"session-up\")", peer.SessionUpEvents)
	}
	if peer.SessionDownEvents != 6 {
		t.Errorf("SessionDownEvents: want 6, got %v (json tag does not match FRR's \"session-down\")", peer.SessionDownEvents)
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
	if len(data.Peers) != 3 {
		t.Fatalf("expected 3 peers, got %d", len(data.Peers))
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

// TestFetchFRROSPFv3Overview_Normal's SPF-timing fields (#582) are verified
// against FRRouting/frr master: spfLastDurationSecs/spfLastDurationMsecs are
// instance-level and genuinely numeric (ospf6_top.c ~1309-1326) — note
// spfLastDurationMsecs is actually o->ts_spf_duration.tv_usec (MICROseconds
// despite the name), so 1 sec + 500000 "msec" here means a 1.5s SPF run, not
// a 1000.5s one. areas.*.spfLastExecutedSecs/MicroSecs are the per-area
// SPF-age pair (ospf6_area.c ~498-517) — the only level OSPFv3 reports SPF
// recency numerically; the instance-level "spfLastExecutedMsecs" sibling
// that ospf6_top.c also sends is a formatted STRING and is deliberately not
// decoded here (see frrOSPFv3OverviewBody's field doc in frr.go).
func TestFetchFRROSPFv3Overview_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/ospfv3overview", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
  "response": {
    "routerId": "172.16.9.1",
    "numberOfAsScopedLsa": 0,
    "spfLastExecutedMsecs": "00:00:10",
    "spfLastDurationSecs": 1,
    "spfLastDurationMsecs": 500000,
    "areas": {
      "0.0.0.0": {
        "numberOfAreaScopedLsa": 4,
        "spfHasRun": true,
        "spfLastExecutedSecs": 10,
        "spfLastExecutedMicroSecs": 250000
      }
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

	if !data.HasSPFLastDuration {
		t.Error("expected HasSPFLastDuration=true")
	}
	if data.SPFLastDurationSeconds != 1.5 {
		t.Errorf("SPFLastDurationSeconds: want 1.5, got %v", data.SPFLastDurationSeconds)
	}

	if !data.Areas[0].HasSPFLastExecuted {
		t.Fatal("expected area HasSPFLastExecuted=true")
	}
	// 10.25s ago, so the absolute timestamp should land within a generous
	// window of time.Now()-10.25.
	wantTimestamp := float64(time.Now().Unix()) - 10.25
	if diff := data.Areas[0].SPFLastExecutedTimestamp - wantTimestamp; diff > 2 || diff < -2 {
		t.Errorf("area SPFLastExecutedTimestamp: want ~%v, got %v", wantTimestamp, data.Areas[0].SPFLastExecutedTimestamp)
	}
}

// TestFetchFRROSPFv3Overview_SPFTimingAbsentBeforeFirstRun guards #582: FRR
// omits the numeric SPF-timing fields entirely (favoring a bare
// "spfHasRun": false) until SPF has run at least once, at both the instance
// and area level. Neither Has* flag must be fabricated true.
func TestFetchFRROSPFv3Overview_SPFTimingAbsentBeforeFirstRun(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/ospfv3overview", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
  "response": {
    "routerId": "172.16.9.1",
    "numberOfAsScopedLsa": 0,
    "spfHasRun": false,
    "areas": {
      "0.0.0.0": {"numberOfAreaScopedLsa": 0, "spfHasRun": false}
    }
  }
}`))
	})

	data, err := client.FetchFRROSPFv3Overview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.HasSPFLastDuration {
		t.Error("expected HasSPFLastDuration=false before the instance's first SPF run")
	}
	if len(data.Areas) != 1 {
		t.Fatalf("expected 1 area, got %d", len(data.Areas))
	}
	if data.Areas[0].HasSPFLastExecuted {
		t.Error("expected area HasSPFLastExecuted=false before that area's first SPF run")
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

// --- OSPFv3 route "type" label (#458): search_ospfv3route has no "type" key
// at all; it splits the same information v2 packs into one "type" string
// across destinationType + pathType. countOSPFv3Routes must compose those
// into v2's notation rather than bucket every v3 row under type="". ---

// ospfv3RouteFixture mirrors the live dev-box capture (26.7.r_35, #458): two
// rows, both destinationType "N" pathType "IA" ("N" + "IA" composes to the
// same "N IA" notation FRR's own v2 "type" field would use).
const ospfv3RouteFixture = `{
  "total": 2,
  "rowCount": 2,
  "current": 1,
  "rows": [
    {"destinationType": "N", "pathType": "IA", "network": "172.16.31.0/24"},
    {"destinationType": "N", "pathType": "IA", "network": "172.16.32.0/24"}
  ]
}`

func TestFetchFRRRouteVolumes_OSPFv3Routes_ComposesTypeFromDestinationAndPathType(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/search_ospfv3route", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(ospfv3RouteFixture))
	})
	// search_generalroute4/6, search_ospfroute, ospfdatabase, search_ospfv3database
	// left unregistered -> 404, only the v3 route slice is under test here.

	data, err := client.FetchFRRRouteVolumes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.OSPFv3Routes) != 1 {
		t.Fatalf("expected 1 distinct OSPFv3 route type, got %d: %+v", len(data.OSPFv3Routes), data.OSPFv3Routes)
	}
	got := data.OSPFv3Routes[0]
	if got.Type != "N IA" {
		t.Errorf(`Type: want "N IA" (destinationType+pathType composed), got %q`, got.Type)
	}
	if got.Count != 2 {
		t.Errorf("Count: want 2, got %v", got.Count)
	}
}

// TestFetchFRRRouteVolumes_OSPFv2Routes_TrailingSpacePreserved locks in the
// pre-existing v2 behaviour the issue requires stay unchanged: FRR's "R "
// (Router, no path-type suffix) trims to "R", not "R " or "".
func TestFetchFRRRouteVolumes_OSPFv2Routes_TrailingSpacePreserved(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/search_ospfroute", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":1,"rowCount":1,"current":1,"rows":[
			{"type": "R ", "network": "172.16.9.1/32"}
		]}`))
	})

	data, err := client.FetchFRRRouteVolumes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.OSPFRoutes) != 1 {
		t.Fatalf("expected 1 OSPF route type, got %d: %+v", len(data.OSPFRoutes), data.OSPFRoutes)
	}
	if data.OSPFRoutes[0].Type != "R" {
		t.Errorf(`Type: want "R" (trailing space trimmed), got %q`, data.OSPFRoutes[0].Type)
	}
}

// TestFetchFRRRouteVolumes_OSPFv3Routes_MissingBothFields_NoEmptyLabel covers
// a row with neither destinationType nor pathType. This shape is NOT from a
// live capture — FRR's ospf6 route dump always sends at least one of the two
// on every row observed so far — it deliberately pins the parser's tolerance
// for the acceptance criterion "a row with none of the fields does not
// silently produce an empty-string label" per #458. The row is dropped from
// the result rather than counted under type="".
func TestFetchFRRRouteVolumes_OSPFv3Routes_MissingBothFields_NoEmptyLabel(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/quagga/diagnostics/search_ospfv3route", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":1,"rowCount":1,"current":1,"rows":[
			{"network": "172.16.33.0/24"}
		]}`))
	})

	data, err := client.FetchFRRRouteVolumes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, rt := range data.OSPFv3Routes {
		if rt.Type == "" {
			t.Errorf("expected no type=\"\" series for a row with neither destinationType nor pathType, got %+v", data.OSPFv3Routes)
		}
	}
}
