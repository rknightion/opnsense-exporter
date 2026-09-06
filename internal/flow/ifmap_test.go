package flow

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
)

// liveIfaces is the interface list as the box enumerated it for #346,
// constructed so that the 1-based ifinfo enumeration reproduces the ifIndex
// mapping VERIFIED LIVE on the production box (#346):
//
//	ifIndex 1  ixl0         LAN
//	ifIndex 5  igb0         WAN2
//	ifIndex 7  lo0          loopback
//	ifIndex 11 ixl0_vlan100 MGMT
//	ifIndex 12 ixl0_vlan25  CAM
//	ifIndex 13 ixl0_vlan50  IOT
//	ifIndex 14 pppoe0       WAN1
//
// The filler rows at the indices not in that table are the interfaces the box
// enumerates between them; they exist so the verified indices land where the live
// box put them, which is the whole point of the fixture.
func liveIfaces() []enrich.IfaceInfo {
	return []enrich.IfaceInfo{
		{Device: "ixl0", Name: "LAN", Identifier: "lan", Addrs: addrs("10.0.0.114")}, // 1
		{Device: "ixl1"}, // 2
		{Device: "ixl2"}, // 3
		{Device: "ixl3"}, // 4
		{Device: "igb0", Name: "WAN2", Identifier: "opt5", IsWAN: true, // 5
			Addrs: addrs("203.0.113.9")},
		{Device: "igb1"}, // 6
		{Device: "lo0", Name: "loopback", Addrs: addrs("127.0.0.1")}, // 7
		{Device: "enc0"},    // 8
		{Device: "pflog0"},  // 9
		{Device: "pfsync0"}, // 10
		{Device: "ixl0_vlan100", Name: "MGMT", Identifier: "opt1", // 11
			VlanTag: "100", VlanParent: "ixl0", Addrs: addrs("10.100.0.1")},
		{Device: "ixl0_vlan25", Name: "CAM", Identifier: "opt2", // 12
			VlanTag: "25", VlanParent: "ixl0", Addrs: addrs("10.25.0.1")},
		// VlanParent deliberately EMPTY: this row exercises the name-parsing
		// fallback in ParentOf, the one that reads "<parent>_vlan<tag>".
		{Device: "ixl0_vlan50", Name: "IOT", Identifier: "opt3", // 13
			VlanTag: "50", Addrs: addrs("10.50.0.1")},
		{Device: "pppoe0", Name: "WAN1", Identifier: "wan", IsWAN: true, // 14
			Addrs: addrs("198.51.100.42")},
	}
}

// liveVLANIfaces is liveIfaces with the per-interface SUBNETS retained, which is
// what #465 added to enrich.IfaceInfo. The addresses are the same; only Prefixes is
// new, so a fixture without it exercises the "no subnet evidence at all" path.
func liveVLANIfaces() []enrich.IfaceInfo {
	ifaces := liveIfaces()
	for i := range ifaces {
		switch ifaces[i].Device {
		case "ixl0":
			ifaces[i].Prefixes = nets("10.0.0.0/24")
		case "ixl0_vlan100":
			ifaces[i].Prefixes = nets("10.100.0.0/24")
		case "ixl0_vlan25":
			ifaces[i].Prefixes = nets("10.25.0.0/24")
		case "ixl0_vlan50":
			ifaces[i].Prefixes = nets("10.50.0.0/24")
		case "pppoe0":
			ifaces[i].Prefixes = nets("198.51.100.42/32")
		case "igb0":
			ifaces[i].Prefixes = nets("203.0.113.0/24")
		}
	}
	return ifaces
}

func nets(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s).Masked())
	}
	return out
}

// #465: address -> the ONE VLAN child that owns it, which is the evidence that lets a
// trunk-captured record be attributed on FIRST SIGHT instead of by arrival order.
func TestIfMap_VLANChildFor(t *testing.T) {
	m := BuildIfMap(IfMapInput{Order: devicesOf(liveVLANIfaces()), Ifaces: liveVLANIfaces()})

	tests := []struct {
		name       string
		parent     string
		addr       string
		wantOK     bool
		wantDevice string
	}{
		{"host on a child subnet", "ixl0", "10.50.0.4", true, "ixl0_vlan50"},
		{"another child of the same trunk", "ixl0", "10.25.0.99", true, "ixl0_vlan25"},
		{"the child's own address", "ixl0", "10.100.0.1", true, "ixl0_vlan100"},
		// The v4-mapped form of the same address must resolve identically; netip
		// compares the two as different Addrs.
		{"v4-mapped form", "ixl0", "::ffff:10.50.0.4", true, "ixl0_vlan50"},
		// The trunk's OWN subnet is not a child subnet: a host on 10.0.0.0/24 really is
		// on the trunk, and relabelling it would invent VLAN traffic.
		{"trunk's own subnet", "ixl0", "10.0.0.5", false, ""},
		// No child prefix contains it. This is the fallback-to-hold population.
		{"address on no child subnet", "ixl0", "8.8.8.8", false, ""},
		// Right address, WRONG trunk: the evidence is about a child of ixl0, so it says
		// nothing about a record naming igb1. Relabelling here would move the flow to a
		// different physical interface entirely.
		{"child of a different parent", "igb1", "10.50.0.4", false, ""},
		{"empty parent", "", "10.50.0.4", false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := m.VLANChildFor(tc.parent, netip.MustParseAddr(tc.addr))
			if ok != tc.wantOK {
				t.Fatalf("VLANChildFor(%q, %s) ok = %v, want %v (got %+v)", tc.parent, tc.addr, ok, tc.wantOK, got)
			}
			if got.Device != tc.wantDevice {
				t.Errorf("VLANChildFor(%q, %s).Device = %q, want %q", tc.parent, tc.addr, got.Device, tc.wantDevice)
			}
		})
	}
	if _, ok := m.VLANChildFor("ixl0", netip.Addr{}); ok {
		t.Error("VLANChildFor(invalid addr) must miss")
	}
	if _, ok := (*IfMap)(nil).VLANChildFor("ixl0", netip.MustParseAddr("10.50.0.4")); ok {
		t.Error("VLANChildFor on a nil map must miss")
	}
}

// The resolved child must carry its NAME and ifIndex, not just the device: the repair
// stage writes this straight onto the record's interface attribution, and a device
// without its friendly name would relabel the metric from "LAN" to "ixl0_vlan50"
// instead of to "IOT".
func TestIfMap_VLANChildForCarriesNameAndIndex(t *testing.T) {
	m := BuildIfMap(IfMapInput{Order: devicesOf(liveVLANIfaces()), Ifaces: liveVLANIfaces()})
	got, ok := m.VLANChildFor("ixl0", netip.MustParseAddr("10.50.0.4"))
	if !ok || got.Name != "IOT" || got.Index != 13 {
		t.Errorf("VLANChildFor = %+v, %v; want IOT at ifIndex 13", got, ok)
	}
}

// AMBIGUOUS EVIDENCE MUST MISS, never pick. #403 measured 9,431 of 372,109 pairs as
// ambiguous, and those are exactly the population that must keep falling back to the
// hold contest. Two children whose prefixes both contain the address is not a
// tie-break to be won by prefix length or map order — Go randomises map iteration, so
// "most specific wins" would still have to be a deliberate decision, and no capture
// supports one.
func TestIfMap_VLANChildForRefusesOverlappingChildren(t *testing.T) {
	ifaces := []enrich.IfaceInfo{
		{Device: "ixl0", Name: "LAN", Prefixes: nets("10.0.0.0/24")},
		{Device: "ixl0_vlan50", Name: "IOT", VlanParent: "ixl0", Prefixes: nets("10.50.0.0/24")},
		{Device: "ixl0_vlan51", Name: "IOT2", VlanParent: "ixl0", Prefixes: nets("10.50.0.0/25")},
	}
	m := BuildIfMap(IfMapInput{Order: devicesOf(ifaces), Ifaces: ifaces})

	if got, ok := m.VLANChildFor("ixl0", netip.MustParseAddr("10.50.0.4")); ok {
		t.Errorf("VLANChildFor resolved an address matching TWO children to %+v; it must miss", got)
	}
	// An address inside only the wider prefix is unambiguous and must still resolve.
	if got, ok := m.VLANChildFor("ixl0", netip.MustParseAddr("10.50.0.200")); !ok || got.Device != "ixl0_vlan50" {
		t.Errorf("VLANChildFor(10.50.0.200) = %+v, %v; want ixl0_vlan50", got, ok)
	}
}

// A child holding two subnets is ONE owning interface, not an ambiguity. The rule is
// "exactly one child DEVICE owns this address", not "exactly one prefix matches".
func TestIfMap_VLANChildForMultiSubnetChild(t *testing.T) {
	ifaces := []enrich.IfaceInfo{
		{Device: "ixl0", Name: "LAN", Prefixes: nets("10.0.0.0/24")},
		{Device: "ixl0_vlan50", Name: "IOT", VlanParent: "ixl0",
			Prefixes: nets("10.50.0.0/24", "10.50.0.0/25", "10.51.0.0/24")},
	}
	m := BuildIfMap(IfMapInput{Order: devicesOf(ifaces), Ifaces: ifaces})

	for _, addr := range []string{"10.50.0.4", "10.51.0.9"} {
		if got, ok := m.VLANChildFor("ixl0", netip.MustParseAddr(addr)); !ok || got.Device != "ixl0_vlan50" {
			t.Errorf("VLANChildFor(%s) = %+v, %v; want ixl0_vlan50", addr, got, ok)
		}
	}
}

// A fixture with no Prefixes at all — the shape of every interface list before #465,
// and of a box whose API rows carry no CIDR — must simply have no evidence, not panic
// and not resolve.
func TestIfMap_VLANChildForWithoutPrefixes(t *testing.T) {
	m := BuildIfMap(IfMapInput{Order: devicesOf(liveIfaces()), Ifaces: liveIfaces()})
	if got, ok := m.VLANChildFor("ixl0", netip.MustParseAddr("10.50.0.4")); ok {
		t.Errorf("VLANChildFor resolved %+v with no per-interface prefixes; it must miss", got)
	}
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s).Unmap())
	}
	return out
}

// devicesOf builds an enumeration that agrees exactly with a metadata list.
// Fixtures that are not about the two lists DISAGREEING use it, so the cases
// below that do disagree are the only ones where they can.
func devicesOf(ifaces []enrich.IfaceInfo) []string {
	order := make([]string, 0, len(ifaces))
	for _, info := range ifaces {
		order = append(order, info.Device)
	}
	return order
}

func liveInput() IfMapInput {
	return IfMapInput{Order: devicesOf(liveIfaces()), Ifaces: liveIfaces()}
}

// --- the #361 regression -----------------------------------------------------
//
// shiftedOrder and shiftedMetadata are the REAL pair captured from the reference
// box on 2026-07-24, and they are the whole bug in two fixtures: the box
// enumerates 16 devices, the metadata endpoint returns 15 because it omits
// pfsync0, and the old derivation counted metadata ROWS. Every index from 10 up
// came out one too low, which put 91% of the box's inbound bytes — the PPPoE WAN
// at index 15 — under the label belonging to index 16.
//
// Structure only: device names, descriptions and identifiers, no addresses.
func shiftedOrder() []string {
	return []string{
		"ixl0", "ixl1", "ixl2", "ixl3", "igb0", "igb1", "lo0", "enc0",
		"pflog0", "pfsync0", "ixl0_vlan100", "ixl0_vlan25", "ixl0_vlan50",
		"zen0", "pppoe0", "tailscale0",
	}
}

// shiftedMetadata is what api/interfaces/overview/interfaces_info returns for the
// same box: the same devices MINUS pfsync0. Deliberately shuffled relative to the
// ordering, because the join is by device NAME and must not care.
func shiftedMetadata() []enrich.IfaceInfo {
	return []enrich.IfaceInfo{
		{Device: "pppoe0", Name: "AAISP", Identifier: "opt7", IsWAN: true},
		{Device: "ixl0_vlan25", Name: "CAM", Identifier: "opt4", VlanTag: "25", VlanParent: "ixl0"},
		{Device: "ixl0_vlan50", Name: "IOT", Identifier: "opt2", VlanTag: "50", VlanParent: "ixl0"},
		{Device: "ixl0", Name: "LAN", Identifier: "lan"},
		{Device: "ixl0_vlan100", Name: "MGMT", Identifier: "opt3", VlanTag: "100", VlanParent: "ixl0"},
		{Device: "ixl1", Name: "VIRGIN", Identifier: "opt6", IsWAN: true},
		{Device: "tailscale0", Name: "tailscale", Identifier: "opt1"},
		{Device: "zen0", Name: "zenoverlay", Identifier: "opt5"},
		{Device: "lo0", Name: "Loopback"},
		{Device: "ixl2"}, {Device: "ixl3"}, {Device: "igb0"}, {Device: "igb1"},
		{Device: "enc0"}, {Device: "pflog0"},
	}
}

// The regression this issue exists for. Before the fix the metadata list WAS the
// enumeration, so index 15 resolved to tailscale0 and index 16 to nothing.
func TestBuildIfMap_MetadataMissingADeviceDoesNotShiftLaterIndices(t *testing.T) {
	m := BuildIfMap(IfMapInput{Order: shiftedOrder(), Ifaces: shiftedMetadata()})

	tests := []struct {
		idx        uint32
		wantDevice string
		wantName   string
	}{
		{1, "ixl0", "LAN"},
		{2, "ixl1", "VIRGIN"},
		{7, "lo0", "Loopback"},
		// pfsync0 has no metadata row. It still occupies slot 10 with an empty
		// Name, which is exactly what keeps everything below correct.
		{10, "pfsync0", ""},
		{11, "ixl0_vlan100", "MGMT"},
		{12, "ixl0_vlan25", "CAM"},
		{13, "ixl0_vlan50", "IOT"},
		{14, "zen0", "zenoverlay"},
		{15, "pppoe0", "AAISP"},
		{16, "tailscale0", "tailscale"},
	}
	for _, tc := range tests {
		got := m.Iface(tc.idx)
		if got.Device != tc.wantDevice || got.Name != tc.wantName {
			t.Errorf("Iface(%d) = {Device:%q Name:%q}, want {Device:%q Name:%q}",
				tc.idx, got.Device, got.Name, tc.wantDevice, tc.wantName)
		}
	}
	// The slot with no metadata must still label itself honestly rather than
	// resolving to nothing at all.
	if got := m.Iface(10).Label(); got != "pfsync0" {
		t.Errorf("Iface(10).Label() = %q, want the device name %q", got, "pfsync0")
	}
	if got := m.Stats().UnmappedLookups; got != 0 {
		t.Errorf("UnmappedLookups = %d; every index in the enumeration must resolve", got)
	}
}

// A device the metadata knows but the enumeration does not is the guard for the
// ordering source going stale or wrong. It must be counted, not swallowed.
func TestBuildIfMap_CountsDevicesMissingFromTheOrdering(t *testing.T) {
	ifaces := append(shiftedMetadata(), enrich.IfaceInfo{Device: "vtnet9", Name: "GHOST"})
	m := BuildIfMap(IfMapInput{Order: shiftedOrder(), Ifaces: ifaces})

	if got := m.Stats().UnlistedDevices; got != 1 {
		t.Errorf("UnlistedDevices = %d, want 1 (vtnet9 is in the metadata, not in the ordering)", got)
	}
	if got := m.Stats().StatedIndexDisagreements; got != 0 {
		t.Errorf("StatedIndexDisagreements = %d, want 0 (nothing stated an index here)", got)
	}
}

// The index the API STATES for a device is an independent cross-check on the
// position we derived. Agreement is silent; disagreement is the signal that
// something was destroyed and recreated and the enumeration has moved.
func TestBuildIfMap_StatedIndexIsAGuardNotTheMap(t *testing.T) {
	stated := map[string]uint32{
		"ixl0":   1,  // agrees
		"pppoe0": 16, // disagrees: position says 15
	}
	m := BuildIfMap(IfMapInput{Order: shiftedOrder(), Ifaces: shiftedMetadata(), Stated: stated})

	if got := m.Stats().StatedIndexDisagreements; got != 1 {
		t.Errorf("StatedIndexDisagreements = %d, want 1", got)
	}
	// The map must still follow the POSITION. rc.d/netflow names the netgraph
	// hook from the position, so the position is what the exporter is receiving.
	if got := m.Iface(15); got.Device != "pppoe0" {
		t.Errorf("Iface(15).Device = %q, want pppoe0; the stated index must not win", got.Device)
	}
	if got := m.Iface(16); got.Device != "tailscale0" {
		t.Errorf("Iface(16).Device = %q, want tailscale0", got.Device)
	}
}

// An empty ordering means the fetch never succeeded. Building a map from nothing
// must not invent one: only the synthetic local-origin entry survives, so every
// real index misses visibly instead of resolving to a lie.
func TestBuildIfMap_EmptyOrderingDerivesNothing(t *testing.T) {
	m := BuildIfMap(IfMapInput{Ifaces: shiftedMetadata()})
	if got := m.Iface(1); got != (Iface{}) {
		t.Errorf("Iface(1) = %+v with no ordering, want the zero Iface", got)
	}
	if got := m.Iface(0).Name; got != LocalOriginName {
		t.Errorf("Iface(0).Name = %q, want %q", got, LocalOriginName)
	}
}

// An ordering can arrive before the interface metadata. Keep the device so logs and
// later diagnostics retain the source fact, but use the unresolved metric label until
// a description is available.
func TestBuildIfMap_ColdMetadataMarksDeviceOnlyInterfaceUnresolved(t *testing.T) {
	m := BuildIfMap(IfMapInput{Order: []string{"ixl0"}})

	got := m.Iface(1)
	if got.Device != "ixl0" {
		t.Fatalf("Iface(1).Device = %q, want ixl0", got.Device)
	}
	if !got.Unresolved {
		t.Fatal("Iface(1).Unresolved = false, want true before interface metadata arrives")
	}
	if got.Label() != UnresolvedInterfaceLabel {
		t.Errorf("Iface(1).Label() = %q, want %q", got.Label(), UnresolvedInterfaceLabel)
	}
}

// The counter that must outlive the map.
//
// UnmappedLookups is the alarm for the whole class of fault this issue is about,
// and it could never fire: it lived on the IfMap instance, which main rebuilds
// every 60 seconds, so it reset before anything could scrape it. It read 0 on a
// box where 0.9% of volume was landing on an unmapped index.
func TestIfMapCounters_SurviveARebuild(t *testing.T) {
	var counters IfMapCounters

	first := BuildIfMap(liveInput())
	first.AttachCounters(&counters)
	first.Iface(900)
	first.Iface(901)
	if got := first.Stats().UnmappedLookups; got != 2 {
		t.Fatalf("UnmappedLookups = %d before the rebuild, want 2", got)
	}

	second := BuildIfMap(liveInput())
	second.AttachCounters(&counters)
	second.Iface(902)

	if got := second.Stats().UnmappedLookups; got != 3 {
		t.Errorf("UnmappedLookups = %d after a rebuild, want 3; the counter reset", got)
	}
	if got := first.Stats().UnmappedLookups; got != 3 {
		t.Errorf("the superseded map reports %d, want 3; both must read the same counter", got)
	}
}

// A map with no counters attached still counts, into its own. Tests and the
// cold-start path build maps without a Processor, and a nil dereference there
// would be a worse bug than the one being fixed.
func TestIfMapCounters_UnattachedMapStillCounts(t *testing.T) {
	m := BuildIfMap(liveInput())
	m.Iface(900)
	if got := m.Stats().UnmappedLookups; got != 1 {
		t.Errorf("UnmappedLookups = %d on an unattached map, want 1", got)
	}
}

// SetIfMap is where the attachment has to happen: main builds a fresh map on a
// ticker and hands it straight to the processor, so if the processor does not
// adopt it into its own counters the reset comes back.
func TestProcessor_SetIfMapKeepsUnmappedCountAcrossRebuilds(t *testing.T) {
	p := NewProcessor(&captureSink{}, NewRepairer(100, 1000), nil)

	p.SetIfMap(BuildIfMap(liveInput()))
	p.IfMap().Iface(900)
	p.SetIfMap(BuildIfMap(liveInput()))
	p.IfMap().Iface(901)

	if got := p.IfMap().Stats().UnmappedLookups; got != 2 {
		t.Errorf("UnmappedLookups = %d across a SetIfMap rebuild, want 2", got)
	}
}

// Entries is what the operator console renders. This bug survived for months
// because nothing in the product ever showed the mapping, so the accessor is
// part of the fix, not a convenience.
func TestIfMap_EntriesAreSortedAndFlagged(t *testing.T) {
	m := BuildIfMap(IfMapInput{
		Order:    shiftedOrder(),
		Ifaces:   shiftedMetadata(),
		Stated:   map[string]uint32{"pppoe0": 16},
		Override: map[uint32]string{2: "ixl1"},
	})

	entries := m.Entries()
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Index > entries[i].Index {
			t.Fatalf("Entries not sorted by Index: %d before %d",
				entries[i-1].Index, entries[i].Index)
		}
	}
	byIdx := make(map[uint32]IfaceEntry, len(entries))
	for _, e := range entries {
		byIdx[e.Index] = e
	}
	if e := byIdx[0]; e.Name != LocalOriginName {
		t.Errorf("Entries missing the synthetic index 0: %+v", e)
	}
	if e := byIdx[2]; !e.Overridden {
		t.Errorf("Entries[2].Overridden = false, want true")
	}
	if e := byIdx[15]; !e.Disagrees || e.Stated != 16 {
		t.Errorf("Entries[15] = {Stated:%d Disagrees:%v}, want {16 true}", e.Stated, e.Disagrees)
	}
	if e := byIdx[1]; e.Disagrees {
		t.Errorf("Entries[1].Disagrees = true; nothing stated an index for ixl0")
	}
}

// The derived enumeration must reproduce the mapping verified on the live box.
// These expectations are the live table, not this code's own output.
func TestBuildIfMap_DerivesVerifiedLiveEnumeration(t *testing.T) {
	m := BuildIfMap(IfMapInput{Order: devicesOf(liveIfaces()), Ifaces: liveIfaces(), Built: time.Unix(1700000000, 0)})

	tests := []struct {
		idx        uint32
		wantDevice string
		wantName   string
	}{
		{0, "", LocalOriginName},
		{1, "ixl0", "LAN"},
		{5, "igb0", "WAN2"},
		{7, "lo0", "loopback"},
		{11, "ixl0_vlan100", "MGMT"},
		{12, "ixl0_vlan25", "CAM"},
		{13, "ixl0_vlan50", "IOT"},
		{14, "pppoe0", "WAN1"},
	}
	for _, tc := range tests {
		got := m.Iface(tc.idx)
		if got.Device != tc.wantDevice || got.Name != tc.wantName {
			t.Errorf("Iface(%d) = {Device:%q Name:%q}, want {Device:%q Name:%q}",
				tc.idx, got.Device, got.Name, tc.wantDevice, tc.wantName)
		}
		if got.Index != tc.idx {
			t.Errorf("Iface(%d).Index = %d, want %d", tc.idx, got.Index, tc.idx)
		}
		if got.Corrected {
			t.Errorf("Iface(%d).Corrected = true; BuildIfMap never corrects", tc.idx)
		}
	}
	if got := m.Stats().UnmappedLookups; got != 0 {
		t.Errorf("UnmappedLookups = %d after only mapped lookups, want 0", got)
	}
}

// ifIndex 0 is ng_netflow's "locally originated" — traffic the firewall itself
// sourced. It is a real, known value and must NEVER fall through to unmapped.
func TestBuildIfMap_IndexZeroIsLocallyOriginated(t *testing.T) {
	m := BuildIfMap(IfMapInput{Order: devicesOf(liveIfaces()), Ifaces: liveIfaces()})
	got := m.Iface(0)
	if got.Name != LocalOriginName {
		t.Errorf("Iface(0).Name = %q, want %q", got.Name, LocalOriginName)
	}
	if got.Label() != LocalOriginName {
		t.Errorf("Iface(0).Label() = %q, want %q", got.Label(), LocalOriginName)
	}
	if n := m.Stats().UnmappedLookups; n != 0 {
		t.Fatalf("ifIndex 0 counted as an unmapped lookup (%d); it is known, not unknown", n)
	}
}

// An index the enumeration does not cover must yield NOTHING — no device, no name,
// no guess — and must be countable, because a wrong interface label is worse than a
// missing one and silent misses are how a renumbering goes unnoticed.
func TestBuildIfMap_UnmappedIndexIsEmptyAndCounted(t *testing.T) {
	m := BuildIfMap(IfMapInput{Order: devicesOf(liveIfaces()), Ifaces: liveIfaces()})

	for _, idx := range []uint32{15, 99, 4294967295} {
		got := m.Iface(idx)
		if got != (Iface{}) {
			t.Errorf("Iface(%d) = %+v, want the zero Iface (never a guess)", idx, got)
		}
		if got.Label() != "" {
			t.Errorf("Iface(%d).Label() = %q, want \"\"", idx, got.Label())
		}
	}
	if got := m.Stats().UnmappedLookups; got != 3 {
		t.Errorf("UnmappedLookups = %d, want 3", got)
	}
}

// The operator override is the escape hatch for the case the derivation cannot
// solve (the API list not reproducing ifinfo order). It must win OUTRIGHT.
func TestBuildIfMap_OverrideBeatsDerivation(t *testing.T) {
	override := map[uint32]string{
		0: "firewall-itself", // even the synthetic local-origin entry is overridable
		1: "igb0",            // names a KNOWN device: resolves to that interface
		5: "SATELLITE",       // names nothing we know: honoured verbatim as the name
	}
	m := BuildIfMap(IfMapInput{Order: devicesOf(liveIfaces()), Ifaces: liveIfaces(), Override: override})

	if got := m.Iface(0); got.Name != "firewall-itself" {
		t.Errorf("Iface(0).Name = %q, want the override %q", got.Name, "firewall-itself")
	}
	if got := m.Iface(1); got.Device != "igb0" || got.Name != "WAN2" {
		t.Errorf("Iface(1) = {Device:%q Name:%q}, want the overridden device igb0/WAN2 "+
			"(an override naming a known device resolves to it)", got.Device, got.Name)
	}
	if got := m.Iface(5); got.Device != "" || got.Name != "SATELLITE" {
		t.Errorf("Iface(5) = {Device:%q Name:%q}, want {\"\", \"SATELLITE\"}", got.Device, got.Name)
	}
	// Untouched indices keep the derived value.
	if got := m.Iface(14); got.Device != "pppoe0" {
		t.Errorf("Iface(14).Device = %q, want pppoe0 (override must not disturb other indices)", got.Device)
	}

	st := m.Stats()
	if st.Overridden != 3 {
		t.Errorf("Overridden = %d, want 3", st.Overridden)
	}
	if st.Conflicts != 3 {
		t.Errorf("Conflicts = %d, want 3 (every one of these disagrees with the derivation)", st.Conflicts)
	}
}

// An override that AGREES with the derivation is applied but is not a conflict:
// disagreement is the signal worth surfacing, so it must not be drowned out.
func TestBuildIfMap_AgreeingOverrideIsNotAConflict(t *testing.T) {
	m := BuildIfMap(IfMapInput{Order: devicesOf(liveIfaces()), Ifaces: liveIfaces(), Override: map[uint32]string{1: "ixl0"}})
	st := m.Stats()
	if st.Overridden != 1 {
		t.Errorf("Overridden = %d, want 1", st.Overridden)
	}
	if st.Conflicts != 0 {
		t.Errorf("Conflicts = %d, want 0 (the override matches the derivation)", st.Conflicts)
	}
}

// An index BEYOND the enumeration can still be overridden — that is exactly the
// case where the API list is short of what ifinfo enumerated.
func TestBuildIfMap_OverrideCanAddAnIndexTheDerivationNeverSaw(t *testing.T) {
	m := BuildIfMap(IfMapInput{Order: devicesOf(liveIfaces()), Ifaces: liveIfaces(), Override: map[uint32]string{40: "ixl0_vlan50"}})
	got := m.Iface(40)
	if got.Device != "ixl0_vlan50" || got.Name != "IOT" || got.Index != 40 {
		t.Errorf("Iface(40) = %+v, want the overridden ixl0_vlan50/IOT at index 40", got)
	}
	if n := m.Stats().UnmappedLookups; n != 0 {
		t.Errorf("UnmappedLookups = %d, want 0 — index 40 IS mapped, by the override", n)
	}
}

// A conflict count on its own cannot be triaged: "the pin names a different
// interface than the derivation did" and "the derivation never produced that
// index at all" are different failures with different fixes, and #516 hit
// exactly that ambiguity on a live box — three conflicts against ten pins, with
// no way to tell from the metric which kind they were without shell access to
// the firewall. So the two are counted separately.
func TestBuildIfMap_ConflictReasonsAreCountedSeparately(t *testing.T) {
	override := map[uint32]string{
		1:  "igb0",          // index 1 IS derived (ixl0): the pin names a different interface
		5:  "SATELLITE",     // index 5 IS derived: verbatim name, still a different interface
		40: "ixl0_vlan50",   // index 40 was never derived at all
		41: "somethingelse", // ditto
	}
	m := BuildIfMap(IfMapInput{Order: devicesOf(liveIfaces()), Ifaces: liveIfaces(), Override: override})
	st := m.Stats()

	if st.Conflicts != 4 {
		t.Errorf("Conflicts = %d, want 4 (the total must stay the sum of the reasons)", st.Conflicts)
	}
	if st.ConflictsDiffering != 2 {
		t.Errorf("ConflictsDiffering = %d, want 2 (indices 1 and 5 exist in the derivation "+
			"and name a different interface)", st.ConflictsDiffering)
	}
	if st.ConflictsAbsent != 2 {
		t.Errorf("ConflictsAbsent = %d, want 2 (indices 40 and 41 were never derived)", st.ConflictsAbsent)
	}
}

// Named is what tells a caller the map is FINISHED rather than merely populated.
// The enrichment refresher fetches the ordering and the interface metadata in two
// separate API calls, so a map built between them has every index right and not one
// name (#522). ifIndex 0 must not count: its name is synthetic and always present,
// so counting it would make every map look named.
func TestBuildIfMap_NamedCountsResolvableNamesAndNotIfIndexZero(t *testing.T) {
	order := devicesOf(liveIfaces())

	if got := BuildIfMap(IfMapInput{Order: order}).Stats().Named; got != 0 {
		t.Errorf("Named = %d, want 0 — the ordering landed before the metadata, so no "+
			"entry has a name and ifIndex 0's synthetic one must not be counted", got)
	}

	full := BuildIfMap(IfMapInput{Order: order, Ifaces: liveIfaces()}).Stats()
	if full.Named == 0 || full.Named >= full.Entries {
		t.Errorf("Named = %d with Entries = %d, want a non-zero count below Entries "+
			"(every listed interface here is named, but ifIndex 0 is excluded)", full.Named, full.Entries)
	}

	// An override names an interface even when the metadata has not arrived, so it
	// counts: the operator asserted a label and records carry it.
	pinned := BuildIfMap(IfMapInput{Order: order, Override: map[uint32]string{3: "SATELLITE"}}).Stats()
	if pinned.Named != 1 {
		t.Errorf("Named = %d, want 1 — an override supplies a name of its own", pinned.Named)
	}
}

func TestBuildIfMap_EmptyOverrideValueIsIgnored(t *testing.T) {
	m := BuildIfMap(IfMapInput{Order: devicesOf(liveIfaces()), Ifaces: liveIfaces(), Override: map[uint32]string{1: "", 5: "   "}})
	if got := m.Iface(1); got.Device != "ixl0" {
		t.Errorf("Iface(1).Device = %q, want ixl0 — a blank override states nothing "+
			"and must not blank out a derived entry", got.Device)
	}
	if st := m.Stats(); st.Overridden != 0 {
		t.Errorf("Overridden = %d, want 0", st.Overridden)
	}
}

func TestBuildIfMap_StatsEntries(t *testing.T) {
	m := BuildIfMap(IfMapInput{Order: devicesOf(liveIfaces()), Ifaces: liveIfaces()})
	// 14 enumerated interfaces + the synthetic ifIndex 0.
	if got := m.Stats().Entries; got != 15 {
		t.Errorf("Entries = %d, want 15 (14 enumerated + ifIndex 0)", got)
	}
}

// A row with no device name still consumes an ifinfo slot: dropping it would shift
// every later index by one, which is precisely the failure mode this map exists to
// avoid.
func TestBuildIfMap_BlankDeviceStillConsumesAnIndex(t *testing.T) {
	ifaces := []enrich.IfaceInfo{
		{Device: "ixl0", Name: "LAN"},
		{Device: "", Name: ""},
		{Device: "igb0", Name: "WAN2"},
	}
	m := BuildIfMap(IfMapInput{Order: devicesOf(ifaces), Ifaces: ifaces})
	if got := m.Iface(3); got.Device != "igb0" {
		t.Errorf("Iface(3).Device = %q, want igb0 — a nameless row must not shift the enumeration", got.Device)
	}
	if got := m.Iface(2); got != (Iface{}) {
		t.Errorf("Iface(2) = %+v, want the zero Iface", got)
	}
}

func TestIfMap_WANFor(t *testing.T) {
	m := BuildIfMap(IfMapInput{Order: devicesOf(liveIfaces()), Ifaces: liveIfaces()})

	tests := []struct {
		addr       string
		wantOK     bool
		wantDevice string
	}{
		{"203.0.113.9", true, "igb0"},
		{"198.51.100.42", true, "pppoe0"},
		// The same v4 address in its v4-mapped IPv6 form must resolve identically:
		// netip compares the two as different Addrs, so without Unmap this misses.
		{"::ffff:203.0.113.9", true, "igb0"},
		{"::ffff:198.51.100.42", true, "pppoe0"},
		{"10.0.0.114", false, ""}, // a LAN address the box holds, but not a WAN
		{"8.8.8.8", false, ""},    // nothing to do with this box
	}
	for _, tc := range tests {
		got, ok := m.WANFor(netip.MustParseAddr(tc.addr))
		if ok != tc.wantOK {
			t.Errorf("WANFor(%s) ok = %v, want %v", tc.addr, ok, tc.wantOK)
			continue
		}
		if got.Device != tc.wantDevice {
			t.Errorf("WANFor(%s).Device = %q, want %q", tc.addr, got.Device, tc.wantDevice)
		}
	}
	if _, ok := m.WANFor(netip.Addr{}); ok {
		t.Error("WANFor(invalid addr) must miss")
	}
}

func TestIfMap_WANForCarriesTheIndex(t *testing.T) {
	m := BuildIfMap(IfMapInput{Order: devicesOf(liveIfaces()), Ifaces: liveIfaces()})
	got, ok := m.WANFor(netip.MustParseAddr("198.51.100.42"))
	if !ok || got.Index != 14 {
		t.Errorf("WANFor(198.51.100.42) = %+v, %v; want pppoe0 at ifIndex 14", got, ok)
	}
}

func TestIfMap_ParentOf(t *testing.T) {
	m := BuildIfMap(IfMapInput{Order: devicesOf(liveIfaces()), Ifaces: liveIfaces()})

	tests := []struct {
		device     string
		wantParent string
		wantOK     bool
	}{
		{"ixl0_vlan100", "ixl0", true}, // API-provided VlanParent
		{"ixl0_vlan25", "ixl0", true},  // API-provided VlanParent
		{"ixl0_vlan50", "ixl0", true},  // name-parsed: the row carries no VlanParent
		{"ixl0", "", false},            // a parent is not a child
		{"pppoe0", "", false},
		{"nosuchdev", "", false},
		{"", "", false},
	}
	for _, tc := range tests {
		got, ok := m.ParentOf(tc.device)
		if got != tc.wantParent || ok != tc.wantOK {
			t.Errorf("ParentOf(%q) = %q,%v want %q,%v", tc.device, got, ok, tc.wantParent, tc.wantOK)
		}
	}
}

// HasVLANChildren is what decides whether a record can still be beaten by a more
// specific copy (#357). It must answer for the TRUNK, which is exactly the device
// ParentOf misses on, and it must never claim a device the interface list did not
// contain.
func TestIfMap_HasVLANChildren(t *testing.T) {
	m := BuildIfMap(IfMapInput{Order: devicesOf(liveIfaces()), Ifaces: liveIfaces()})

	tests := []struct {
		device string
		want   bool
	}{
		{"ixl0", true},          // the trunk: three VLAN children hang off it
		{"ixl0_vlan50", false},  // a child is not itself a trunk
		{"ixl0_vlan100", false}, // ditto
		{"pppoe0", false},       // a real interface with no children
		{"nosuchdev", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := m.HasVLANChildren(tc.device); got != tc.want {
			t.Errorf("HasVLANChildren(%q) = %v, want %v", tc.device, got, tc.want)
		}
	}
}

func TestIfMap_Age(t *testing.T) {
	built := time.Unix(1700000000, 0)
	m := BuildIfMap(IfMapInput{Order: devicesOf(liveIfaces()), Ifaces: liveIfaces(), Built: built})
	if got := m.Age(built.Add(90 * time.Second)); got != 90*time.Second {
		t.Errorf("Age = %v, want 90s", got)
	}
	// A clock that went backwards must not report a negative age.
	if got := m.Age(built.Add(-time.Minute)); got != 0 {
		t.Errorf("Age(before built) = %v, want 0", got)
	}
	// A map built with no timestamp has no meaningful age.
	if got := BuildIfMap(IfMapInput{}).Age(built); got != 0 {
		t.Errorf("Age of an unstamped map = %v, want 0", got)
	}
}

// The hot path may hold a nil map before the first build. It must miss, not panic.
func TestIfMap_NilIsSafe(t *testing.T) {
	var m *IfMap
	if got := m.Iface(1); got != (Iface{}) {
		t.Errorf("nil.Iface(1) = %+v, want the zero Iface", got)
	}
	if _, ok := m.WANFor(netip.MustParseAddr("8.8.8.8")); ok {
		t.Error("nil.WANFor must miss")
	}
	if _, ok := m.ParentOf("ixl0_vlan50"); ok {
		t.Error("nil.ParentOf must miss")
	}
	if m.HasVLANChildren("ixl0") {
		t.Error("nil.HasVLANChildren must miss")
	}
	if got := m.Age(time.Now()); got != 0 {
		t.Errorf("nil.Age = %v, want 0", got)
	}
	if got := (m.Stats()); got != (IfMapStats{}) {
		t.Errorf("nil.Stats() = %+v, want the zero value", got)
	}
}

func TestBuildIfMap_EmptyInputStillKnowsLocalOrigin(t *testing.T) {
	m := BuildIfMap(IfMapInput{})
	if got := m.Iface(0).Name; got != LocalOriginName {
		t.Errorf("Iface(0).Name = %q, want %q even with no interfaces", got, LocalOriginName)
	}
	if got := m.Iface(1); got != (Iface{}) {
		t.Errorf("Iface(1) = %+v, want the zero Iface", got)
	}
}

// An IfMap is rebuilt and swapped, never mutated, so any number of readers may run
// against one concurrently with no lock. Run under -race.
func TestIfMap_ConcurrentReaders(t *testing.T) {
	m := BuildIfMap(IfMapInput{Order: devicesOf(liveIfaces()), Ifaces: liveIfaces(), Override: map[uint32]string{5: "SATELLITE"}, Built: time.Unix(1700000000, 0)})

	const readers = 16
	const iterations = 500
	var wg sync.WaitGroup
	wg.Add(readers)
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				if got := m.Iface(1); got.Device != "ixl0" {
					t.Errorf("Iface(1).Device = %q under concurrency", got.Device)
					return
				}
				_ = m.Iface(0)
				_ = m.Iface(9999) // unmapped: the one mutable counter
				_, _ = m.WANFor(netip.MustParseAddr("198.51.100.42"))
				_, _ = m.ParentOf("ixl0_vlan50")
				_ = m.Stats()
				_ = m.Age(time.Unix(1700000060, 0))
			}
		}()
	}
	wg.Wait()

	if got := m.Stats().UnmappedLookups; got != readers*iterations {
		t.Errorf("UnmappedLookups = %d, want %d — the counter lost increments",
			got, readers*iterations)
	}
}
