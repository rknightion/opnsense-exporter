package flow

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// liveIfaces is an interface list in the order the OPNsense API returns it,
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

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s).Unmap())
	}
	return out
}

// The derived enumeration must reproduce the mapping verified on the live box.
// These expectations are the live table, not this code's own output.
func TestBuildIfMap_DerivesVerifiedLiveEnumeration(t *testing.T) {
	m := BuildIfMap(liveIfaces(), nil, time.Unix(1700000000, 0))

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
	m := BuildIfMap(liveIfaces(), nil, time.Time{})
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
	m := BuildIfMap(liveIfaces(), nil, time.Time{})

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
	m := BuildIfMap(liveIfaces(), override, time.Time{})

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
	m := BuildIfMap(liveIfaces(), map[uint32]string{1: "ixl0"}, time.Time{})
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
	m := BuildIfMap(liveIfaces(), map[uint32]string{40: "ixl0_vlan50"}, time.Time{})
	got := m.Iface(40)
	if got.Device != "ixl0_vlan50" || got.Name != "IOT" || got.Index != 40 {
		t.Errorf("Iface(40) = %+v, want the overridden ixl0_vlan50/IOT at index 40", got)
	}
	if n := m.Stats().UnmappedLookups; n != 0 {
		t.Errorf("UnmappedLookups = %d, want 0 — index 40 IS mapped, by the override", n)
	}
}

func TestBuildIfMap_EmptyOverrideValueIsIgnored(t *testing.T) {
	m := BuildIfMap(liveIfaces(), map[uint32]string{1: "", 5: "   "}, time.Time{})
	if got := m.Iface(1); got.Device != "ixl0" {
		t.Errorf("Iface(1).Device = %q, want ixl0 — a blank override states nothing "+
			"and must not blank out a derived entry", got.Device)
	}
	if st := m.Stats(); st.Overridden != 0 {
		t.Errorf("Overridden = %d, want 0", st.Overridden)
	}
}

func TestBuildIfMap_StatsEntries(t *testing.T) {
	m := BuildIfMap(liveIfaces(), nil, time.Time{})
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
	m := BuildIfMap(ifaces, nil, time.Time{})
	if got := m.Iface(3); got.Device != "igb0" {
		t.Errorf("Iface(3).Device = %q, want igb0 — a nameless row must not shift the enumeration", got.Device)
	}
	if got := m.Iface(2); got != (Iface{}) {
		t.Errorf("Iface(2) = %+v, want the zero Iface", got)
	}
}

func TestIfMap_WANFor(t *testing.T) {
	m := BuildIfMap(liveIfaces(), nil, time.Time{})

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
	m := BuildIfMap(liveIfaces(), nil, time.Time{})
	got, ok := m.WANFor(netip.MustParseAddr("198.51.100.42"))
	if !ok || got.Index != 14 {
		t.Errorf("WANFor(198.51.100.42) = %+v, %v; want pppoe0 at ifIndex 14", got, ok)
	}
}

func TestIfMap_ParentOf(t *testing.T) {
	m := BuildIfMap(liveIfaces(), nil, time.Time{})

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

func TestIfMap_Age(t *testing.T) {
	built := time.Unix(1700000000, 0)
	m := BuildIfMap(liveIfaces(), nil, built)
	if got := m.Age(built.Add(90 * time.Second)); got != 90*time.Second {
		t.Errorf("Age = %v, want 90s", got)
	}
	// A clock that went backwards must not report a negative age.
	if got := m.Age(built.Add(-time.Minute)); got != 0 {
		t.Errorf("Age(before built) = %v, want 0", got)
	}
	// A map built with no timestamp has no meaningful age.
	if got := BuildIfMap(nil, nil, time.Time{}).Age(built); got != 0 {
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
	if got := m.Age(time.Now()); got != 0 {
		t.Errorf("nil.Age = %v, want 0", got)
	}
	if got := (m.Stats()); got != (IfMapStats{}) {
		t.Errorf("nil.Stats() = %+v, want the zero value", got)
	}
}

func TestBuildIfMap_EmptyInputStillKnowsLocalOrigin(t *testing.T) {
	m := BuildIfMap(nil, nil, time.Time{})
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
	m := BuildIfMap(liveIfaces(), map[uint32]string{5: "SATELLITE"}, time.Unix(1700000000, 0))

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
