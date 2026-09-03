package opnsense

import (
	"io"
	"log/slog"
	"net/http"
	"testing"
)

// populatedLLDPFixture is modelled on a real (sanitised) production capture of
// `api/lldpd/service/neighbor` (#216): 4 neighbor blocks, including one local
// port (ixl0) that sees TWO neighbors, and one block (ixl2) whose Interface:
// line carries no "alias:" token at all. Hostnames/MACs/ports are sanitised.
const populatedLLDPFixture = `{"response":"-------------------------------------------------------------------------------\nLLDP neighbors:\n-------------------------------------------------------------------------------\nInterface:    ixl0, alias: LAN (lan), via: LLDP, RID: 1, Time: 1 day, 04:56:36\n  Chassis:     \n    ChassisID:    mac aa:bb:cc:dd:ee:01\n    SysName:      test-firewall\n    SysDescr:      FreeBSD 14.3-RELEASE-p16 stable/26.1\n    MgmtIP:       10.0.0.254\n    MgmtIface:    1\n    Capability:   Bridge, off\n    Capability:   Router, on\n  Port:        \n    PortID:       ifname ixl0\n    PortDescr:    LAN (lan)\n    TTL:          120\n-------------------------------------------------------------------------------\nInterface:    ixl0, alias: LAN (lan), via: LLDP, RID: 2, Time: 1 day, 04:56:26\n  Chassis:     \n    ChassisID:    mac aa:bb:cc:dd:ee:02\n    SysName:      test-switch\n    SysDescr:     Test-Switch-Model\n    MgmtIP:       10.0.100.23\n    Capability:   Bridge, on\n    Capability:   Router, on\n  Port:        \n    PortID:       local Port 1\n    PortDescr:    UPLINK\n    TTL:          120\n-------------------------------------------------------------------------------\nInterface:    ixl2, via: LLDP, RID: 2, Time: 1 day, 04:56:32\n  Chassis:     \n    ChassisID:    mac aa:bb:cc:dd:ee:02\n    SysName:      test-switch\n    SysDescr:     Test-Switch-Model\n    MgmtIP:       10.0.100.23\n    Capability:   Bridge, on\n    Capability:   Router, on\n  Port:        \n    PortID:       local Port 5\n    PortDescr:    ONTBRIDGE\n    TTL:          120\n-------------------------------------------------------------------------------\nInterface:    igb0, alias: WAN (opt6), via: LLDP, RID: 2, Time: 1 day, 04:56:34\n  Chassis:     \n    ChassisID:    mac aa:bb:cc:dd:ee:02\n    SysName:      test-switch\n    SysDescr:     Test-Switch-Model\n    MgmtIP:       10.0.100.23\n    Capability:   Bridge, on\n    Capability:   Router, on\n  Port:        \n    PortID:       local Port 3\n    PortDescr:    MODEM\n    TTL:          120\n-------------------------------------------------------------------------------\n\n\n"}`

// emptyLLDPFixture is modelled on a real (structurally-valid, zero-neighbor)
// dev-box capture: lldpd is running but has seen no neighbors yet.
const emptyLLDPFixture = `{"response":"-------------------------------------------------------------------------------\nLLDP neighbors:\n-------------------------------------------------------------------------------\n\n\n"}`

// devBoxLLDPFixture is a real (unmodified) dev-box capture taken after the
// hypervisor-level LLDP multicast block was fixed (#216): a Meraki switch
// ("odin") plus the box's own WAN NIC show up as neighbors on two local
// interfaces (vtnet0, vtnet1), each with two neighbor entries. Exercises
// fields absent from the production capture: an Interface: line with
// RID/Time ("0 day, 00:01:12"), a PortID of the "ifalias N" form, and
// "Unknown TLVs:" blocks with "TLV: OUI: ..., SubType: N, Len: N ..." lines —
// the unknown block must simply be ignored (it maps to no known key), while
// chassis MAC and management addresses are retained for bounded inventory.
const devBoxLLDPFixture = `{"response":"-------------------------------------------------------------------------------\nLLDP neighbors:\n-------------------------------------------------------------------------------\nInterface:    vtnet0, alias: LAN (lan), via: LLDP, RID: 2, Time: 0 day, 00:01:12\n  Chassis:     \n    ChassisID:    mac bc:24:11:c1:d5:12\n    SysName:      opnsense-devel\n    SysDescr:      FreeBSD 15.1-RELEASE-p1 FreeBSD 15.1-RELEASE-p1 stable/26.7-n283669-9664a203d589 SMP amd64\n    MgmtIP:       10.0.0.114\n    MgmtIface:    1\n    MgmtIP:       fd6b:d9cd:7613:4c33:be24:11ff:fec1:d512\n    MgmtIface:    1\n    Capability:   Bridge, off\n    Capability:   Router, on\n    Capability:   Wlan, off\n    Capability:   Station, off\n  Port:        \n    PortID:       ifname vtnet1\n    PortDescr:    WAN (wan)\n    TTL:          120\n-------------------------------------------------------------------------------\nInterface:    vtnet0, alias: LAN (lan), via: LLDP, RID: 1, Time: 0 day, 00:00:42\n  Chassis:     \n    ChassisID:    mac cc:9c:3e:02:94:60\n    SysName:      odin\n    SysDescr:     Meraki MS250-24P Cloud Managed PoE Switch\n    MgmtIP:       10.0.100.10\n    Capability:   Bridge, on\n  Port:        \n    PortID:       ifalias 22\n    PortDescr:    Port 22\n    TTL:          120\n  Unknown TLVs:\n    TLV:          OUI: 00,80,C2, SubType: 6, Len: 2 00,64\n    TLV:          OUI: 00,18,0A, SubType: 1, Len: 4 00,AE,B4,A3\n-------------------------------------------------------------------------------\nInterface:    vtnet1, alias: WAN (wan), via: LLDP, RID: 2, Time: 0 day, 00:01:12\n  Chassis:     \n    ChassisID:    mac bc:24:11:c1:d5:12\n    SysName:      opnsense-devel\n    SysDescr:      FreeBSD 15.1-RELEASE-p1 FreeBSD 15.1-RELEASE-p1 stable/26.7-n283669-9664a203d589 SMP amd64\n    MgmtIP:       10.0.0.114\n    MgmtIface:    1\n    MgmtIP:       fd6b:d9cd:7613:4c33:be24:11ff:fec1:d512\n    MgmtIface:    1\n    Capability:   Bridge, off\n    Capability:   Router, on\n    Capability:   Wlan, off\n    Capability:   Station, off\n  Port:        \n    PortID:       ifname vtnet0\n    PortDescr:    LAN (lan)\n    TTL:          120\n-------------------------------------------------------------------------------\nInterface:    vtnet1, alias: WAN (wan), via: LLDP, RID: 1, Time: 0 day, 00:00:42\n  Chassis:     \n    ChassisID:    mac cc:9c:3e:02:94:60\n    SysName:      odin\n    SysDescr:     Meraki MS250-24P Cloud Managed PoE Switch\n    MgmtIP:       10.0.100.10\n    Capability:   Bridge, on\n  Port:        \n    PortID:       ifalias 22\n    PortDescr:    Port 22\n    TTL:          120\n  Unknown TLVs:\n    TLV:          OUI: 00,80,C2, SubType: 6, Len: 2 00,64\n    TLV:          OUI: 00,18,0A, SubType: 1, Len: 4 00,AE,B4,A3\n-------------------------------------------------------------------------------\n\n\n"}`

func TestFetchLLDPNeighbors_Populated(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/lldpd/service/neighbor", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		_, _ = w.Write([]byte(populatedLLDPFixture))
	})

	data, err := client.FetchLLDPNeighbors()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if len(data.Neighbors) != 4 {
		t.Fatalf("expected 4 neighbors, got %d: %+v", len(data.Neighbors), data.Neighbors)
	}

	// ixl0 has two neighbors — the multi-neighbor-per-port case.
	var ixl0 []LLDPNeighbor
	for _, n := range data.Neighbors {
		if n.Interface == "ixl0" {
			ixl0 = append(ixl0, n)
		}
	}
	if len(ixl0) != 2 {
		t.Fatalf("expected 2 neighbors on ixl0, got %d: %+v", len(ixl0), ixl0)
	}
	if ixl0[0].ChassisName != "test-firewall" || ixl0[0].PortID != "ifname ixl0" || ixl0[0].PortDescr != "LAN (lan)" {
		t.Errorf("unexpected first ixl0 neighbor: %+v", ixl0[0])
	}
	if ixl0[1].ChassisName != "test-switch" || ixl0[1].PortID != "local Port 1" || ixl0[1].PortDescr != "UPLINK" {
		t.Errorf("unexpected second ixl0 neighbor: %+v", ixl0[1])
	}

	// ixl2's Interface: line has no "alias:" token — must still parse the
	// interface name and the rest of the block correctly.
	var ixl2 *LLDPNeighbor
	for i, n := range data.Neighbors {
		if n.Interface == "ixl2" {
			ixl2 = &data.Neighbors[i]
		}
	}
	if ixl2 == nil {
		t.Fatal("expected a neighbor on ixl2 (no-alias variant)")
	}
	if ixl2.ChassisName != "test-switch" || ixl2.PortID != "local Port 5" || ixl2.PortDescr != "ONTBRIDGE" {
		t.Errorf("unexpected ixl2 neighbor: %+v", *ixl2)
	}

	var igb0 *LLDPNeighbor
	for i, n := range data.Neighbors {
		if n.Interface == "igb0" {
			igb0 = &data.Neighbors[i]
		}
	}
	if igb0 == nil {
		t.Fatal("expected a neighbor on igb0")
	}
	if igb0.PortID != "local Port 3" || igb0.PortDescr != "MODEM" {
		t.Errorf("unexpected igb0 neighbor: %+v", *igb0)
	}
}

// TestFetchLLDPNeighbors_DevBoxCapture exercises a real dev-box capture that
// carries fields the production capture does not: an Interface: line with
// RID/Time, an "ifalias N" PortID, and "Unknown TLVs:" sub-blocks — none of
// which are metric fields, so the parser must ignore them without losing the
// neighbor entry they belong to (#216). Chassis MAC and management addresses
// are retained for bounded device inventory.
func TestFetchLLDPNeighbors_DevBoxCapture(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/lldpd/service/neighbor", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(devBoxLLDPFixture))
	})

	data, err := client.FetchLLDPNeighbors()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if len(data.Neighbors) != 4 {
		t.Fatalf("expected 4 neighbors, got %d: %+v", len(data.Neighbors), data.Neighbors)
	}

	counts := map[string]int{}
	for _, n := range data.Neighbors {
		counts[n.Interface]++
	}
	if counts["vtnet0"] != 2 {
		t.Errorf("expected 2 neighbors on vtnet0, got %d", counts["vtnet0"])
	}
	if counts["vtnet1"] != 2 {
		t.Errorf("expected 2 neighbors on vtnet1, got %d", counts["vtnet1"])
	}

	var meraki *LLDPNeighbor
	for i, n := range data.Neighbors {
		if n.ChassisName == "odin" && n.Interface == "vtnet0" {
			meraki = &data.Neighbors[i]
		}
	}
	if meraki == nil {
		t.Fatal("expected a neighbor named 'odin' on vtnet0")
	}
	if meraki.PortID != "ifalias 22" || meraki.PortDescr != "Port 22" {
		t.Errorf("unexpected 'odin' neighbor (Unknown TLVs lines must not corrupt parsing): %+v", *meraki)
	}
	if meraki.ChassisMAC != "cc:9c:3e:02:94:60" {
		t.Errorf("meraki chassis MAC = %q, want cc:9c:3e:02:94:60", meraki.ChassisMAC)
	}
	if len(meraki.MgmtIPs) != 1 || meraki.MgmtIPs[0] != "10.0.100.10" {
		t.Errorf("meraki management IPs = %v, want [10.0.100.10]", meraki.MgmtIPs)
	}

	var selfPeer *LLDPNeighbor
	for i, n := range data.Neighbors {
		if n.ChassisName == "opnsense-devel" && n.Interface == "vtnet0" {
			selfPeer = &data.Neighbors[i]
		}
	}
	if selfPeer == nil {
		t.Fatal("expected a neighbor named 'opnsense-devel' on vtnet0")
	}
	if selfPeer.PortID != "ifname vtnet1" || selfPeer.PortDescr != "WAN (wan)" {
		t.Errorf("unexpected 'opnsense-devel' neighbor: %+v", *selfPeer)
	}
	if selfPeer.ChassisMAC != "bc:24:11:c1:d5:12" || len(selfPeer.MgmtIPs) != 2 {
		t.Errorf("self peer chassis identity = MAC %q, management IPs %v; want MAC and both addresses", selfPeer.ChassisMAC, selfPeer.MgmtIPs)
	}
}

func TestFetchLLDPNeighbors_Empty(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/lldpd/service/neighbor", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(emptyLLDPFixture))
	})

	data, err := client.FetchLLDPNeighbors()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true even with zero neighbors (lldpd is running, just quiet)")
	}
	if len(data.Neighbors) != 0 {
		t.Errorf("expected 0 neighbors, got %d: %+v", len(data.Neighbors), data.Neighbors)
	}
}

func TestFetchLLDPNeighbors_NotFound(t *testing.T) {
	// Plugin not installed: endpoint returns 404. This must be treated as
	// "feature absent" — empty data, no error — so boxes without os-lldpd do
	// not log errors or increment endpoint counters every scrape.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/lldpd/service/neighbor", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errorMessage":"Endpoint not found"}`))
	})

	data, err := client.FetchLLDPNeighbors()
	if err != nil {
		t.Fatalf("expected nil error for 404 (plugin absent), got %v", err)
	}
	if data.Present {
		t.Error("expected Present=false for 404")
	}
	if len(data.Neighbors) != 0 {
		t.Errorf("expected 0 neighbors for 404, got %d", len(data.Neighbors))
	}
}

func TestFetchLLDPNeighbors_ServerError(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/lldpd/service/neighbor", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("error"))
	})

	_, err := client.FetchLLDPNeighbors()
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

// TestParseLLDPNeighbors_MalformedBlockSkipped verifies that a garbage block
// (no Interface: line — e.g. a future lldpcli output-format drift) is skipped
// rather than failing the whole parse, while well-formed neighbor blocks
// elsewhere in the same payload still come through.
func TestParseLLDPNeighbors_MalformedBlockSkipped(t *testing.T) {
	client := &Client{}
	text := "-------------------------------------------------------------------------------\n" +
		"LLDP neighbors:\n" +
		"-------------------------------------------------------------------------------\n" +
		"Interface:    ixl0, alias: LAN (lan), via: LLDP, RID: 1, Time: 1 day, 04:56:36\n" +
		"  Chassis:     \n" +
		"    SysName:      test-firewall\n" +
		"  Port:        \n" +
		"    PortID:       ifname ixl0\n" +
		"    PortDescr:    LAN (lan)\n" +
		"-------------------------------------------------------------------------------\n" +
		"Something totally unexpected with no Interface line at all\n" +
		"    RandomField:  RandomValue\n" +
		"-------------------------------------------------------------------------------\n" +
		"\n\n"
	client.log = slog.New(slog.NewTextHandler(io.Discard, nil))

	got := client.parseLLDPNeighbors(text)
	if len(got) != 1 {
		t.Fatalf("expected 1 well-formed neighbor to survive the malformed block, got %d: %+v", len(got), got)
	}
	if got[0].Interface != "ixl0" || got[0].ChassisName != "test-firewall" {
		t.Errorf("unexpected surviving neighbor: %+v", got[0])
	}
}
