package flow

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// The interfaces below are the ones ifmap_test.go's fixture describes, at the
// ifIndexes verified live on the production box (#346). Both test files therefore
// describe ONE box, so a topology claim made here can be checked against the map
// that will actually produce these values.
var (
	rpIfLAN  = Iface{Device: "ixl0", Name: "LAN", Index: 1}
	rpIfIOT  = Iface{Device: "ixl0_vlan50", Name: "IOT", Index: 13}
	rpIfWAN1 = Iface{Device: "pppoe0", Name: "WAN1", Index: 14}
	rpIfWAN2 = Iface{Device: "igb0", Name: "WAN2", Index: 5}
)

// The firewall's own addresses, matching ifmap_test.go's fixture.
const (
	rpWAN1Addr = "198.51.100.42"
	rpWAN2Addr = "203.0.113.9"
	rpLANAddr  = "10.0.0.114"
)

var rpT0 = time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

// rpIfMap is a hand-built stand-in for *IfMap. The repairer resolves against the
// ifTopology seam, so these tests exercise the real decision logic without waiting
// on the map builder — and without encoding an assumption about how it is
// constructed.
type rpIfMap struct {
	parents map[string]string // VLAN child -> parent device
	wans    map[string]Iface  // firewall-held address -> the WAN holding it
	wanDevs map[string]bool
}

func rpBox() *rpIfMap {
	return &rpIfMap{
		parents: map[string]string{
			"ixl0_vlan50":  "ixl0",
			"ixl0_vlan25":  "ixl0",
			"ixl0_vlan100": "ixl0",
		},
		wans: map[string]Iface{
			rpWAN1Addr: rpIfWAN1,
			rpWAN2Addr: rpIfWAN2,
		},
		wanDevs: map[string]bool{"pppoe0": true, "igb0": true},
	}
}

func (f *rpIfMap) Iface(uint32) Iface { return Iface{} }

func (f *rpIfMap) WANFor(addr netip.Addr) (Iface, bool) {
	i, ok := f.wans[addr.Unmap().String()]
	return i, ok
}

func (f *rpIfMap) ParentOf(device string) (string, bool) {
	p, ok := f.parents[device]
	return p, ok
}

func (f *rpIfMap) IsWAN(device string) bool { return f.wanDevs[device] }

// rpBlindBox is the same topology with IsWAN withheld, which is the shape of the
// seam as it is specified today. It exists so the address-echo fallback in
// ifaceIsWAN is exercised for real rather than being dead code behind the optional
// assertion.
type rpBlindBox struct{ inner *rpIfMap }

func (f rpBlindBox) WANFor(a netip.Addr) (Iface, bool) { return f.inner.WANFor(a) }
func (f rpBlindBox) ParentOf(d string) (string, bool)  { return f.inner.ParentOf(d) }

func rpSnapshot() *enrich.Snapshot {
	return &enrich.Snapshot{
		SelfIPs: map[netip.Addr]bool{
			netip.MustParseAddr(rpLANAddr):  true,
			netip.MustParseAddr(rpWAN1Addr): true,
			netip.MustParseAddr(rpWAN2Addr): true,
		},
		LocalNets: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
			netip.MustParsePrefix("10.0.50.0/24"),
		},
	}
}

// rpVLANPair is the duplicate observed in the live capture, verbatim:
//
//	10.0.50.4:5432 -> 10.0.0.5:44554
//	     LAN/ixl0 -> LAN/ixl0    24,935 B
//	          IOT -> LAN/ixl0    24,935 B
//
// The same packets, exported twice, because ng_netflow captures on the trunk AND on
// its VLAN children. The parent copy additionally mis-attributes IOT traffic to LAN.
func rpVLANPair() (parent, child Record) {
	base := Record{
		Source:  SourceNetflow,
		Proto:   6,
		SrcAddr: netip.MustParseAddr("10.0.50.4"),
		SrcPort: 5432,
		DstAddr: netip.MustParseAddr("10.0.0.5"),
		DstPort: 44554,
		Start:   rpT0,
		End:     rpT0.Add(3 * time.Second),
		NF:      Counters{TxBytes: 24935, TxPackets: 37, Present: true},
		VLANID:  "50",
	}
	parent, child = base, base
	parent.In, parent.Out = rpIfLAN, rpIfLAN
	child.In, child.Out = rpIfIOT, rpIfLAN
	return parent, child
}

// rpRun feeds records through the repairer in order and returns the ones kept.
func rpRun(r *Repairer, m ifTopology, snap *enrich.Snapshot, now time.Time, recs ...Record) []Record {
	kept := make([]Record, 0, len(recs))
	for _, rec := range recs {
		if r.repairWith(&rec, m, snap, now) {
			kept = append(kept, rec)
		}
	}
	return kept
}

// The control for repair 1. The two copies arrive in different datagrams and
// nothing guarantees which lands first, so BOTH orders must collapse to exactly one
// record — and it must be the VLAN copy, because the parent copy calls IOT traffic
// LAN.
func TestRepairer_VLANDuplicateCollapsesToTheVLANCopyInBothArrivalOrders(t *testing.T) {
	parent, child := rpVLANPair()

	tests := []struct {
		name string
		in   []Record
	}{
		{"parent copy first", []Record{parent, child}},
		{"vlan copy first", []Record{child, parent}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRepairer(1000)
			kept := rpRun(r, rpBox(), rpSnapshot(), rpT0, tc.in...)

			if len(kept) != 1 {
				t.Fatalf("kept %d records, want exactly 1 — the two copies are the same 24,935 bytes", len(kept))
			}
			if kept[0].In.Device != "ixl0_vlan50" {
				t.Errorf("survivor In.Device = %q, want ixl0_vlan50: the parent copy attributes "+
					"IOT traffic to LAN, so it is the wrong copy to keep", kept[0].In.Device)
			}
			if kept[0].In.Name != "IOT" {
				t.Errorf("survivor In.Name = %q, want IOT", kept[0].In.Name)
			}
			if got := kept[0].NF.Bytes(); got != 24935 {
				t.Errorf("survivor bytes = %d, want 24935", got)
			}
			if st := r.Stats(); st.VLANDuplicatesDropped != 1 {
				t.Errorf("VLANDuplicatesDropped = %d, want 1 (%+v)", st.VLANDuplicatesDropped, st)
			}
		})
	}
}

// Without the 802.1Q tag on the parent copy the two are distinguishable only by
// having been seen before, so the instance table is what guarantees exactly one
// survives. It cannot un-emit, so in parent-first order the parent copy is the one
// that survives — the byte total is right, the interface attribution is not. That
// residual is the reason the tag matters and is called out in repair.go.
func TestRepairer_UntaggedParentCopyStillCollapsesToOneRecord(t *testing.T) {
	parent, child := rpVLANPair()
	parent.VLANID, child.VLANID = "", ""

	tests := []struct {
		name       string
		in         []Record
		wantDevice string
	}{
		{"vlan copy first", []Record{child, parent}, "ixl0_vlan50"},
		{"parent copy first", []Record{parent, child}, "ixl0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRepairer(1000)
			kept := rpRun(r, rpBox(), rpSnapshot(), rpT0, tc.in...)

			if len(kept) != 1 {
				t.Fatalf("kept %d records, want exactly 1", len(kept))
			}
			if kept[0].In.Device != tc.wantDevice {
				t.Errorf("survivor In.Device = %q, want %q", kept[0].In.Device, tc.wantDevice)
			}
			if st := r.Stats(); st.VLANDuplicatesDropped != 1 {
				t.Errorf("VLANDuplicatesDropped = %d, want 1", st.VLANDuplicatesDropped)
			}
		})
	}
}

// The instance key is (canonical 5-tuple, First, Last). A long-lived conversation is
// exported repeatedly with the SAME tuple and different timestamps, so keying on the
// tuple alone would silently discard every export after the first — turning a busy
// flow into a single record.
func TestRepairer_SameTupleDifferentInstanceIsKept(t *testing.T) {
	_, child := rpVLANPair()
	second := child
	second.Start = child.End
	second.End = child.End.Add(3 * time.Second)

	r := NewRepairer(1000)
	kept := rpRun(r, rpBox(), rpSnapshot(), rpT0, child, second)

	if len(kept) != 2 {
		t.Fatalf("kept %d records, want 2 — a later export of the same conversation is new data", len(kept))
	}
	if st := r.Stats(); st.VLANDuplicatesDropped != 0 {
		t.Errorf("VLANDuplicatesDropped = %d, want 0", st.VLANDuplicatesDropped)
	}
	if st := r.Stats(); st.DedupeEntries != 2 {
		t.Errorf("DedupeEntries = %d, want 2", st.DedupeEntries)
	}
}

// A record the repairer drops must never be corrected, counted or given a
// direction: it is not going downstream, so any work done on it is at best wasted
// and at worst reaches a metric.
//
// The fixture is deliberately synthetic — a VLAN-tagged flow sourced from the
// firewall's own WAN2 address does not occur naturally. It exists to make the
// dropped record ALSO qualify for repair 2, which is the only way to prove the
// ordering rather than assume it.
func TestRepairer_DroppedRecordIsNeverCorrectedOrDirected(t *testing.T) {
	parent, _ := rpVLANPair()
	parent.SrcAddr = netip.MustParseAddr(rpWAN2Addr)
	parent.Out = rpIfWAN1 // what the FIB lookup claimed

	r := NewRepairer(1000)
	if r.repairWith(&parent, rpBox(), rpSnapshot(), rpT0) {
		t.Fatal("parent copy was kept; it is a VLAN duplicate")
	}
	if parent.Out.Corrected {
		t.Error("dropped record was egress-corrected")
	}
	if parent.Out.Device != "pppoe0" {
		t.Errorf("dropped record Out.Device = %q, want it untouched at pppoe0", parent.Out.Device)
	}
	if parent.Direction != DirectionUnknown {
		t.Errorf("dropped record Direction = %v, want it untouched", parent.Direction)
	}
	if st := r.Stats(); st.EgressCorrected != 0 {
		t.Errorf("EgressCorrected = %d, want 0 — a dropped record must not move a counter", st.EgressCorrected)
	}
}

// Repair 2. ng_netflow derives OUTPUT_SNMP from a FIB route lookup, but multi-WAN
// policy routing happens in pf, which ng_netflow never sees. A flow NAT'd to WAN2's
// address genuinely left over WAN2 while the FIB says WAN1 — that mislabelled
// 3.36 GB of WAN2 traffic as WAN1 in one window, leaving WAN2 reading 37.8 MB
// against ~3.4 GB actual.
//
// The guard is as important as the repair: rewriting an egress that already agrees
// would mask the day ng_netflow starts getting it right.
func TestRepairer_EgressCorrectedOnlyWhenTheObservedInterfaceDiffers(t *testing.T) {
	dst := netip.MustParseAddr("93.184.216.34")

	tests := []struct {
		name          string
		src           string
		observedOut   Iface
		wantDevice    string
		wantCorrected bool
		wantCount     uint64
	}{
		{
			name:          "policy-routed flow the FIB attributed to WAN1",
			src:           rpWAN2Addr,
			observedOut:   rpIfWAN1,
			wantDevice:    "igb0",
			wantCorrected: true,
			wantCount:     1,
		},
		{
			name:          "observed egress already agrees",
			src:           rpWAN2Addr,
			observedOut:   rpIfWAN2,
			wantDevice:    "igb0",
			wantCorrected: false,
			wantCount:     0,
		},
		{
			name:          "unmapped egress is a correction, not an agreement",
			src:           rpWAN1Addr,
			observedOut:   Iface{},
			wantDevice:    "pppoe0",
			wantCorrected: true,
			wantCount:     1,
		},
		{
			name:          "source is not a firewall WAN address: nothing deduced",
			src:           "10.0.0.5",
			observedOut:   rpIfWAN1,
			wantDevice:    "pppoe0",
			wantCorrected: false,
			wantCount:     0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := Record{
				Source: SourceNetflow, Proto: 6,
				SrcAddr: netip.MustParseAddr(tc.src), SrcPort: 51234,
				DstAddr: dst, DstPort: 443,
				Start: rpT0, End: rpT0.Add(time.Second),
				In:  rpIfLAN,
				Out: tc.observedOut,
				NF:  Counters{TxBytes: 4096, TxPackets: 8, Present: true},
			}
			r := NewRepairer(1000)
			if !r.repairWith(&rec, rpBox(), rpSnapshot(), rpT0) {
				t.Fatal("record was dropped; it is not a duplicate")
			}
			if rec.Out.Device != tc.wantDevice {
				t.Errorf("Out.Device = %q, want %q", rec.Out.Device, tc.wantDevice)
			}
			if rec.Out.Corrected != tc.wantCorrected {
				t.Errorf("Out.Corrected = %v, want %v", rec.Out.Corrected, tc.wantCorrected)
			}
			if st := r.Stats(); st.EgressCorrected != tc.wantCount {
				t.Errorf("EgressCorrected = %d, want %d", st.EgressCorrected, tc.wantCount)
			}
		})
	}
}

// A corrected egress must be the WAN it was corrected TO, name and index included:
// the rollup labels the series from Out (processor.go interfaceLabel), so keeping
// WAN1's name on WAN2's device would move the mislabelling rather than fix it.
func TestRepairer_CorrectedEgressCarriesTheDeducedWANIdentity(t *testing.T) {
	rec := Record{
		Source: SourceNetflow, Proto: 6,
		SrcAddr: netip.MustParseAddr(rpWAN2Addr), SrcPort: 51234,
		DstAddr: netip.MustParseAddr("93.184.216.34"), DstPort: 443,
		Start: rpT0, End: rpT0.Add(time.Second),
		In: rpIfLAN, Out: rpIfWAN1,
	}
	r := NewRepairer(1000)
	r.repairWith(&rec, rpBox(), rpSnapshot(), rpT0)

	if rec.Out.Name != "WAN2" || rec.Out.Index != 5 {
		t.Errorf("Out = %+v, want WAN2 at ifIndex 5", rec.Out)
	}
	// The correction is what proves this flow left over a WAN, so the direction must
	// follow it: the source is the firewall's own address, so scope alone says "self
	// to remote", which rule 2 cannot resolve.
	if rec.Direction != DirectionOutbound {
		t.Errorf("Direction = %v, want outbound", rec.Direction)
	}
}

// Repair 3. NetFlow field 61 (DIRECTION) is not exported by this box, so direction
// is inferred. The rule must agree with the Zenarmor lane's directionOf on rules 1,
// 2 and 4 — the two lanes describe the same traffic and a dashboard splits on this
// label.
func TestRepairer_DirectionRules(t *testing.T) {
	tests := []struct {
		name     string
		src, dst string
		in, out  Iface
		snap     *enrich.Snapshot
		want     Direction
	}{
		{
			// Rule 1. SSDP never leaves the L2 domain, but 239.255.255.250 sits in no
			// configured subnet, so scope alone calls it remote.
			name: "ipv4 multicast destination is internal",
			src:  "10.0.0.5", dst: "239.255.255.250",
			in: rpIfLAN, snap: rpSnapshot(), want: DirectionInternal,
		},
		{
			name: "ipv6 link-local multicast (mDNS) is internal",
			src:  "fe80::1", dst: "ff02::fb",
			in: rpIfLAN, snap: rpSnapshot(), want: DirectionInternal,
		},
		{
			name: "unspecified destination is internal",
			src:  "0.0.0.0", dst: "0.0.0.0",
			in: rpIfLAN, snap: rpSnapshot(), want: DirectionInternal,
		},
		{
			// Rule 2, and the trap in it: "self" is NOT remote. A LAN host reaching the
			// firewall's own web UI on its WAN address is internal traffic, even though
			// the record's egress interface is a WAN.
			name: "lan host to the firewall itself is internal, not outbound",
			src:  "10.0.0.5", dst: rpWAN1Addr,
			in: rpIfLAN, out: rpIfWAN1, snap: rpSnapshot(), want: DirectionInternal,
		},
		{
			name: "vlan host to lan host is internal",
			src:  "10.0.50.4", dst: "10.0.0.5",
			in: rpIfIOT, out: rpIfLAN, snap: rpSnapshot(), want: DirectionInternal,
		},
		{
			// Rule 3.
			name: "egress interface is a wan: outbound",
			src:  "10.0.0.5", dst: "93.184.216.34",
			in: rpIfLAN, out: rpIfWAN1, snap: rpSnapshot(), want: DirectionOutbound,
		},
		{
			name: "ingress interface is a wan: inbound",
			src:  "93.184.216.34", dst: "10.0.0.5",
			in: rpIfWAN1, out: rpIfLAN, snap: rpSnapshot(), want: DirectionInbound,
		},
		{
			// The ifIndex evidence is the thing NetFlow has that Zenarmor does not, so it
			// must still resolve when the enrichment snapshot is cold and every scope
			// lookup returns "".
			name: "cold snapshot still resolves from the interfaces",
			src:  "10.0.0.5", dst: "93.184.216.34",
			in: rpIfLAN, out: rpIfWAN1, snap: &enrich.Snapshot{}, want: DirectionOutbound,
		},
		{
			// Rule 3b. A unidirectional record from a local address to a remote one
			// describes packets that left, whatever the interfaces did or did not say.
			name: "local to remote with no interface evidence: outbound",
			src:  "10.0.0.5", dst: "93.184.216.34",
			snap: rpSnapshot(), want: DirectionOutbound,
		},
		{
			name: "remote to local with no interface evidence: inbound",
			src:  "93.184.216.34", dst: "10.0.0.5",
			snap: rpSnapshot(), want: DirectionInbound,
		},
		{
			// Both ends remote is transit: it says nothing about orientation relative to
			// this firewall, so rule 3b must NOT fire.
			name: "remote to remote decides nothing",
			src:  "93.184.216.34", dst: "1.1.1.1",
			snap: rpSnapshot(), want: DirectionUnknown,
		},
		{
			// Rule 4. Nothing classifies this, so it stays unknown rather than being
			// guessed: "unknown" is a real emitted value.
			name: "no scope and no wan interface: unknown",
			src:  "10.0.0.5", dst: "93.184.216.34",
			in: rpIfLAN, out: rpIfLAN, snap: &enrich.Snapshot{}, want: DirectionUnknown,
		},
		{
			name: "nil snapshot and unmapped interfaces: unknown",
			src:  "10.0.0.5", dst: "93.184.216.34",
			want: DirectionUnknown,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := Record{
				Source: SourceNetflow, Proto: 17,
				SrcAddr: netip.MustParseAddr(tc.src), SrcPort: 40000,
				DstAddr: netip.MustParseAddr(tc.dst), DstPort: 1900,
				Start: rpT0, End: rpT0,
				In: tc.in, Out: tc.out,
			}
			r := NewRepairer(1000)
			if !r.repairWith(&rec, rpBox(), tc.snap, rpT0) {
				t.Fatal("record was dropped; it is not a duplicate")
			}
			if rec.Direction != tc.want {
				t.Errorf("Direction = %v, want %v (scopes src=%q dst=%q)",
					rec.Direction, tc.want, rec.Enrich.SrcScope, rec.Enrich.DstScope)
			}
		})
	}
}

// The seam as specified cannot answer "is this device a WAN", so rule 3 falls back
// to the evidence it does have: a post-NAT source address that the WAN table
// resolves is the WAN the flow left by. Without this the correction in repair 2
// would be the only thing keeping direction alive on an IfMap that exposes no
// IsWAN, and un-NAT'd records would silently read unknown.
func TestRepairer_DirectionWithoutAnIsWANPredicate(t *testing.T) {
	blind := rpBlindBox{inner: rpBox()}

	outbound := Record{
		Source: SourceNetflow, Proto: 6,
		SrcAddr: netip.MustParseAddr(rpWAN1Addr), SrcPort: 51234,
		DstAddr: netip.MustParseAddr("93.184.216.34"), DstPort: 443,
		Start: rpT0, End: rpT0, In: rpIfLAN, Out: rpIfWAN1,
	}
	r := NewRepairer(1000)
	r.repairWith(&outbound, blind, rpSnapshot(), rpT0)
	if outbound.Direction != DirectionOutbound {
		t.Errorf("Direction = %v, want outbound", outbound.Direction)
	}

	inbound := Record{
		Source: SourceNetflow, Proto: 6,
		SrcAddr: netip.MustParseAddr("93.184.216.34"), SrcPort: 443,
		DstAddr: netip.MustParseAddr(rpWAN1Addr), DstPort: 51234,
		Start: rpT0, End: rpT0, In: rpIfWAN1, Out: rpIfLAN,
	}
	r2 := NewRepairer(1000)
	r2.repairWith(&inbound, blind, rpSnapshot(), rpT0)
	if inbound.Direction != DirectionInbound {
		t.Errorf("Direction = %v, want inbound", inbound.Direction)
	}
}

// Scope is resolved here because the repairer needs it BEFORE the enrich stage runs
// (processor.go repairs, then enriches). It must land on the record so the two
// stages cannot disagree about what the same snapshot said.
func TestRepairer_ResolvesScopesForTheRecord(t *testing.T) {
	rec := Record{
		Source: SourceNetflow, Proto: 6,
		SrcAddr: netip.MustParseAddr("10.0.0.5"), SrcPort: 40000,
		DstAddr: netip.MustParseAddr(rpLANAddr), DstPort: 53,
		Start: rpT0, End: rpT0, In: rpIfLAN,
	}
	r := NewRepairer(1000)
	r.repairWith(&rec, rpBox(), rpSnapshot(), rpT0)

	if rec.Enrich.SrcScope != "local" {
		t.Errorf("SrcScope = %q, want local", rec.Enrich.SrcScope)
	}
	if rec.Enrich.DstScope != "self" {
		t.Errorf("DstScope = %q, want self — the firewall holds %s", rec.Enrich.DstScope, rpLANAddr)
	}
}

// Time-based expiry is what bounds the table's time dimension. An aged-out entry is
// healthy housekeeping, so it is counted apart from the capacity path: the two mean
// very different things to an operator.
func TestRepairer_DedupeExpiresAgedEntries(t *testing.T) {
	_, child := rpVLANPair()
	later := child
	later.SrcPort = 5433

	r := NewRepairer(1000)
	if !r.repairWith(&child, rpBox(), rpSnapshot(), rpT0) {
		t.Fatal("first record dropped")
	}
	if st := r.Stats(); st.DedupeEntries != 1 || st.DedupeEvicted != 0 {
		t.Fatalf("Stats() = %+v, want 1 entry and no evictions", st)
	}

	// One TTL later, plus a margin: the first instance can no longer be part of a
	// duplicate pair, so it must not still be occupying the table.
	r.repairWith(&later, rpBox(), rpSnapshot(), rpT0.Add(dedupeTTL+time.Second))

	st := r.Stats()
	if st.DedupeEvicted != 1 {
		t.Errorf("DedupeEvicted = %d, want 1", st.DedupeEvicted)
	}
	if st.DedupeEntries != 1 {
		t.Errorf("DedupeEntries = %d, want 1 (the aged entry gone, the new one held)", st.DedupeEntries)
	}
	if st.DedupeCapped != 0 {
		t.Errorf("DedupeCapped = %d, want 0 — nothing was forced out early", st.DedupeCapped)
	}
}

// The table is fed by an unauthenticated UDP listener, so it MUST be bounded. At
// capacity the oldest instance goes, because it is the one least likely to still
// have a duplicate in flight — and the pressure is counted, because a table running
// permanently at its bound is silently deduping less than the operator thinks.
func TestRepairer_DedupeIsBoundedAndCountsThePressure(t *testing.T) {
	r := NewRepairer(2)
	_, child := rpVLANPair()

	for i := 0; i < 5; i++ {
		rec := child
		rec.SrcPort = uint16(5432 + i)
		if !r.repairWith(&rec, rpBox(), rpSnapshot(), rpT0) {
			t.Fatalf("record %d dropped; these are five distinct instances", i)
		}
	}

	st := r.Stats()
	if st.DedupeEntries != 2 {
		t.Errorf("DedupeEntries = %d, want 2 — the bound is not being enforced", st.DedupeEntries)
	}
	if st.DedupeCapped != 3 {
		t.Errorf("DedupeCapped = %d, want 3", st.DedupeCapped)
	}
	if st.DedupeEvicted != 0 {
		t.Errorf("DedupeEvicted = %d, want 0 — nothing aged out, the bound forced these", st.DedupeEvicted)
	}
}

// An evicted instance can no longer be deduped: its duplicate is emitted. That is
// the honest consequence of the bound, and it is what DedupeCapped exists to warn
// about.
func TestRepairer_EvictedInstanceNoLongerDedupes(t *testing.T) {
	parent, child := rpVLANPair()
	parent.VLANID, child.VLANID = "", "" // force the table path, not the tag path

	r := NewRepairer(1)
	if !r.repairWith(&child, rpBox(), rpSnapshot(), rpT0) {
		t.Fatal("vlan copy dropped")
	}
	// A second instance evicts the first.
	other := child
	other.SrcPort = 5433
	r.repairWith(&other, rpBox(), rpSnapshot(), rpT0)

	if !r.repairWith(&parent, rpBox(), rpSnapshot(), rpT0) {
		t.Error("parent copy was still deduped after its instance was evicted; " +
			"the table cannot suppress what it no longer remembers")
	}
	if st := r.Stats(); st.DedupeCapped == 0 {
		t.Errorf("DedupeCapped = 0; the eviction that caused this must be visible (%+v)", st)
	}
}

// A maxDedupeEntries of zero means unbounded, matching NewRollup's convention for
// its own caps. Silently clamping to zero entries would disable de-dup entirely.
func TestRepairer_ZeroMaxEntriesIsUnbounded(t *testing.T) {
	r := NewRepairer(0)
	_, child := rpVLANPair()
	for i := 0; i < 200; i++ {
		rec := child
		rec.SrcPort = uint16(1000 + i)
		r.repairWith(&rec, rpBox(), rpSnapshot(), rpT0)
	}
	st := r.Stats()
	if st.DedupeEntries != 200 {
		t.Errorf("DedupeEntries = %d, want 200", st.DedupeEntries)
	}
	if st.DedupeCapped != 0 {
		t.Errorf("DedupeCapped = %d, want 0", st.DedupeCapped)
	}
}

// A nil IfMap is the state before the first interface refresh, and a nil snapshot is
// a lane running with enrichment off. Neither may panic, and neither may cause a
// record to be dropped: without topology we cannot prove anything is a duplicate.
func TestRepairer_NilInputsKeepRecordsAndDoNotPanic(t *testing.T) {
	parent, child := rpVLANPair()
	r := NewRepairer(1000)

	kept := 0
	for _, rec := range []Record{parent, child} {
		if r.Repair(&rec, nil, nil, rpT0) {
			kept++
		}
	}
	if kept != 2 {
		t.Errorf("kept %d of 2 records with no IfMap; an unproven duplicate must not be dropped", kept)
	}
	if st := r.Stats(); st.VLANDuplicatesDropped != 0 || st.EgressCorrected != 0 {
		t.Errorf("Stats() = %+v, want no repairs claimed with nothing to repair against", st)
	}
}

// Repair runs on a UDP worker POOL, so the table is shared mutable state. Run under
// -race. The assertions are deterministic by construction: every parent copy is
// dropped by the tag rule on sight, which does not depend on what any other
// goroutine did first.
func TestRepairer_ConcurrentRepairIsRaceFree(t *testing.T) {
	const workers = 8
	const iterations = 250

	r := NewRepairer(4096)
	m := rpBox()
	snap := rpSnapshot()

	var wg sync.WaitGroup
	wg.Add(workers)
	kept := make([]int, workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				parent, child := rpVLANPair()
				child.SrcPort = uint16(1024 + i)
				parent.SrcPort = child.SrcPort
				now := rpT0.Add(time.Duration(i) * time.Millisecond)
				if r.repairWith(&parent, m, snap, now) {
					kept[w]++
				}
				if r.repairWith(&child, m, snap, now) {
					kept[w]++
				}
			}
		}(w)
	}
	wg.Wait()

	st := r.Stats()
	if want := uint64(workers * iterations); st.VLANDuplicatesDropped != want {
		t.Errorf("VLANDuplicatesDropped = %d, want %d — the counter lost increments",
			st.VLANDuplicatesDropped, want)
	}
	total := 0
	for _, n := range kept {
		total += n
	}
	if want := workers * iterations; total != want {
		t.Errorf("kept %d records, want %d (every parent copy dropped, every vlan copy kept)", total, want)
	}
	if st.DedupeEntries > 4096 {
		t.Errorf("DedupeEntries = %d, over the bound", st.DedupeEntries)
	}
}

// The shape that actually arrives in production, driven through the REAL IfMap
// rather than a hand-built topology: a pre-NAT outbound record, whose source is a
// LAN address the WAN table cannot resolve and whose egress interface the map cannot
// be asked about, because IfMap exposes no IsWAN.
//
// This is the majority of WAN traffic. It read "unknown" until rule 3b existed, and
// it is the reason 3b exists.
func TestRepairer_ProductionShapeOutboundIsNotUnknown(t *testing.T) {
	m := BuildIfMap(liveIfaces(), nil, time.Time{})
	snap := &enrich.Snapshot{
		SelfIPs:   map[netip.Addr]bool{netip.MustParseAddr(rpWAN1Addr): true},
		LocalNets: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	}

	outbound := Record{
		Source: SourceNetflow, Proto: 6,
		SrcAddr: netip.MustParseAddr("10.0.0.5"), SrcPort: 51234,
		DstAddr: netip.MustParseAddr("93.184.216.34"), DstPort: 443,
		Start: rpT0, End: rpT0,
		In:  m.Iface(1),  // ixl0, LAN
		Out: m.Iface(14), // pppoe0, WAN1
	}
	r := NewRepairer(1000)
	if !r.Repair(&outbound, m, snap, rpT0) {
		t.Fatal("record was dropped")
	}
	if outbound.Direction != DirectionOutbound {
		t.Errorf("Direction = %v, want outbound (scopes %q/%q)",
			outbound.Direction, outbound.Enrich.SrcScope, outbound.Enrich.DstScope)
	}

	inbound := Record{
		Source: SourceNetflow, Proto: 6,
		SrcAddr: netip.MustParseAddr("93.184.216.34"), SrcPort: 443,
		DstAddr: netip.MustParseAddr("10.0.0.5"), DstPort: 51234,
		Start: rpT0, End: rpT0,
		In:  m.Iface(14),
		Out: m.Iface(1),
	}
	if !r.Repair(&inbound, m, snap, rpT0) {
		t.Fatal("record was dropped")
	}
	if inbound.Direction != DirectionInbound {
		t.Errorf("Direction = %v, want inbound", inbound.Direction)
	}
}

// The VLAN de-dup resolved against the REAL IfMap: ifIndex 1 is the trunk ixl0 and
// ifIndex 13 is ixl0_vlan50/IOT, both verified live (#346). Driving the hand-built
// topology alone would prove the logic but not that the map it will actually run
// against answers ParentOf the way the logic assumes.
func TestRepairer_VLANDedupeAgainstTheRealIfMap(t *testing.T) {
	m := BuildIfMap(liveIfaces(), nil, time.Time{})
	parent, child := rpVLANPair()
	parent.In, parent.Out = m.Iface(1), m.Iface(1)
	child.In, child.Out = m.Iface(13), m.Iface(1)

	r := NewRepairer(1000)
	kept := 0
	var survivor Record
	for _, rec := range []Record{parent, child} {
		if r.Repair(&rec, m, rpSnapshot(), rpT0) {
			kept++
			survivor = rec
		}
	}
	if kept != 1 {
		t.Fatalf("kept %d records, want 1", kept)
	}
	if survivor.In.Name != "IOT" {
		t.Errorf("survivor In.Name = %q, want IOT", survivor.In.Name)
	}
}

// Repair is the exported entry point and must behave identically to the seam the
// rest of these tests drive; a divergence there would make every one of them prove
// nothing about what the processor actually calls.
func TestRepairer_ExportedRepairMatchesTheSeam(t *testing.T) {
	var m *IfMap // the pre-refresh state processor.go can pass
	_, child := rpVLANPair()
	r := NewRepairer(1000)
	if !r.Repair(&child, m, rpSnapshot(), rpT0) {
		t.Fatal("Repair dropped a record with a nil IfMap")
	}
	if child.Enrich.DstScope != "local" {
		t.Errorf("DstScope = %q, want local — Repair must still resolve scope", child.Enrich.DstScope)
	}
}

// The IfMap the receiver lane owns must satisfy the seam this package resolves
// against. If this stops compiling, the contract moved.
var _ ifTopology = (*IfMap)(nil)
