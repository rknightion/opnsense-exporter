package flow

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
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
	// childNets is #465's subnet evidence, in the same shape *IfMap holds it: a
	// containment scan, because the question is which prefixes CONTAIN an address.
	childNets []rpChildNet
}

type rpChildNet struct {
	prefix netip.Prefix
	iface  Iface
	parent string
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
		// The IOT subnet, matching rpSnapshot's LocalNets and the addresses in
		// rpVLANPair. ixl0_vlan25 and ixl0_vlan100 deliberately have NO subnet here:
		// a box whose API rows carry no CIDR for an interface must simply have no
		// evidence for it, and the fallback path needs a child in that state.
		childNets: []rpChildNet{
			{netip.MustParsePrefix("10.0.50.0/24"), rpIfIOT, "ixl0"},
		},
	}
}

// VLANChildFor mirrors *IfMap's contract: exactly one owning child device, hanging off
// the named parent, or nothing at all.
func (f *rpIfMap) VLANChildFor(parent string, addr netip.Addr) (Iface, bool) {
	if parent == "" || !addr.IsValid() {
		return Iface{}, false
	}
	addr = addr.Unmap()
	var (
		found  Iface
		device string
	)
	for _, cn := range f.childNets {
		if !cn.prefix.Contains(addr) {
			continue
		}
		if device != "" && cn.iface.Device != device {
			return Iface{}, false
		}
		found, device = cn.iface, cn.iface.Device
		if cn.parent != parent {
			found = Iface{}
		}
	}
	if found.Device == "" {
		return Iface{}, false
	}
	return found, true
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

func (f *rpIfMap) HasVLANChildren(device string) bool {
	if device == "" {
		return false
	}
	for _, parent := range f.parents {
		if parent == device {
			return true
		}
	}
	return false
}

func (f *rpIfMap) IsWAN(device string) bool { return f.wanDevs[device] }

// rpBlindBox is the same topology with IsWAN withheld, which is the shape of the
// seam as it is specified today. It exists so the address-echo fallback in
// ifaceIsWAN is exercised for real rather than being dead code behind the optional
// assertion.
type rpBlindBox struct{ inner *rpIfMap }

func (f rpBlindBox) WANFor(a netip.Addr) (Iface, bool)  { return f.inner.WANFor(a) }
func (f rpBlindBox) ParentOf(d string) (string, bool)   { return f.inner.ParentOf(d) }
func (f rpBlindBox) HasVLANChildren(device string) bool { return f.inner.HasVLANChildren(device) }
func (f rpBlindBox) VLANChildFor(p string, a netip.Addr) (Iface, bool) {
	return f.inner.VLANChildFor(p, a)
}

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

// rpVLANPairUntagged is rpVLANPair with NO 802.1Q tag, which is the shape that
// actually arrives: 0 of the 131 records in the golden capture carry SRC_VLAN/DST_VLAN,
// so mechanism A never fires on the reference box and the pair has to be resolved
// without it. Every #465 test uses this rather than the tagged fixture, because a
// tagged pair is dropped on sight by mechanism A and would prove nothing about the
// subnet evidence.
func rpVLANPairUntagged() (parent, child Record) {
	parent, child = rpVLANPair()
	parent.VLANID, child.VLANID = "", ""
	return parent, child
}

// rpRun feeds records through the repairer in order and returns the ones kept.
//
// It runs the lane to COMPLETION: records the stage parks are collected from the
// closing Flush, exactly as the processor's shutdown path does. Without that, a test
// asserting "one record survives" could not tell a held record from a dropped one.
func rpRun(r *Repairer, m ifTopology, snap *enrich.Snapshot, now time.Time, recs ...Record) []Record {
	kept := make([]Record, 0, len(recs))
	for _, rec := range recs {
		if r.repairWith(&rec, m, snap, now) == RepairEmit {
			kept = append(kept, rec)
		}
	}
	return append(kept, r.Flush()...)
}

// rpOne feeds ONE record through the repairer and returns it as it LEAVES the stage,
// whether that was immediately or from the hold buffer.
//
// Repairs 2 and 3 are deferred for a held record, so a test that read the record it
// passed in would see an unrepaired one and prove nothing. Reading what came out is
// also the honest model of the pipeline: the processor never ships the record it
// handed to Repair either.
func rpOne(t *testing.T, r *Repairer, m ifTopology, snap *enrich.Snapshot, now time.Time, rec Record) Record {
	t.Helper()
	out := rpRun(r, m, snap, now, rec)
	if len(out) != 1 {
		t.Fatalf("record did not survive the repair stage (%d emitted, want 1)", len(out))
	}
	return out[0]
}

// rpFeed feeds one record and drains the hold buffer, so the instance ends up in the
// DE-DUP TABLE rather than parked in front of it. The table's own tests — expiry,
// bounds, eviction — are about that table, and a record still sitting in the hold
// buffer has not reached it yet.
func rpFeed(r *Repairer, m ifTopology, snap *enrich.Snapshot, now time.Time, rec Record) RepairVerdict {
	v := r.repairWith(&rec, m, snap, now)
	r.Flush()
	return v
}

// ════════════════════════════════════════════════════════════════════════════
// #465 — mechanism A', subnet evidence
// ════════════════════════════════════════════════════════════════════════════

// THE DEFECT-1 REGRESSION TEST. #403 measured 108,678 pairs whose inter-arrival gap
// exceeded vlanHoldWindow, and ALL 108,678 were trunk-first: the trunk copy was held,
// released after 2s, inserted into the de-dup table, and the child copy that arrived
// afterwards was dropped by mechanism C — attributing the flow to the trunk, which is
// exactly what the repair stage exists to prevent.
//
// Subnet evidence resolves it on FIRST SIGHT, so the gap stops mattering.
func TestRepairer_AboveWindowPairIsAttributedToTheVLANChild(t *testing.T) {
	parent, child := rpVLANPairUntagged()
	// Comfortably past the 2s window, and past the p99 gap of 31.2s measured in #403.
	const gap = 40 * time.Second

	tests := []struct {
		name          string
		first, second Record
	}{
		{"trunk copy first (the measured case: 108,678 of 108,678)", parent, child},
		{"child copy first", child, parent},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRepairer(1000, 1000)
			m, snap := rpBox(), rpSnapshot()

			kept := rpRun(r, m, snap, rpT0, tc.first)
			kept = append(kept, rpRun(r, m, snap, rpT0.Add(gap), tc.second)...)

			if len(kept) != 1 {
				t.Fatalf("kept %d records across a %s gap, want exactly 1", len(kept), gap)
			}
			if kept[0].In.Device != "ixl0_vlan50" {
				t.Errorf("survivor In.Device = %q, want ixl0_vlan50 — a gap wider than "+
					"vlanHoldWindow must not send the flow back to the trunk", kept[0].In.Device)
			}
			if kept[0].In.Name != "IOT" {
				t.Errorf("survivor In.Name = %q, want IOT: the label follows the device", kept[0].In.Name)
			}
		})
	}
}

// ORDER-INDEPENDENCE, pinned across the whole matrix #465 asks for: both arrival
// orders, at gaps inside and outside the hold window. The winner must be byte-for-byte
// identical in every cell — that is the property, not "usually the child".
func TestRepairer_SubnetEvidenceIsOrderIndependentAtEveryGap(t *testing.T) {
	parent, child := rpVLANPairUntagged()
	gaps := []time.Duration{0, 500 * time.Millisecond, vlanHoldWindow - time.Millisecond,
		vlanHoldWindow + time.Millisecond, 40 * time.Second, 108 * time.Second}

	for _, gap := range gaps {
		t.Run(gap.String(), func(t *testing.T) {
			winners := map[string]Record{}
			for _, order := range []struct {
				name          string
				first, second Record
			}{
				{"trunk-first", parent, child},
				{"child-first", child, parent},
			} {
				r := NewRepairer(1000, 1000)
				m, snap := rpBox(), rpSnapshot()
				kept := rpRun(r, m, snap, rpT0, order.first)
				kept = append(kept, rpRun(r, m, snap, rpT0.Add(gap), order.second)...)
				if len(kept) != 1 {
					t.Fatalf("%s: kept %d records, want exactly 1", order.name, len(kept))
				}
				winners[order.name] = kept[0]
			}
			a, b := winners["trunk-first"], winners["child-first"]
			if a.In != b.In || a.Out != b.Out {
				t.Errorf("arrival order changed the winner: trunk-first %+v/%+v, child-first %+v/%+v",
					a.In, a.Out, b.In, b.Out)
			}
			if a.In.Device != "ixl0_vlan50" {
				t.Errorf("winner In.Device = %q, want ixl0_vlan50 in both orders", a.In.Device)
			}
		})
	}
}

// THE 247,105 RECORDS NO HOLD WINDOW OF ANY SIZE COULD HAVE FIXED. #403 found that
// many trunk-touching records matched exactly one VLAN child prefix and had NO child
// copy anywhere in the 18h35m capture. There is no second copy to prefer, so only
// subnet evidence can attribute them.
func TestRepairer_LoneTrunkRecordIsAttributedToTheVLANChild(t *testing.T) {
	parent, _ := rpVLANPairUntagged()

	r := NewRepairer(1000, 1000)
	got := rpOne(t, r, rpBox(), rpSnapshot(), rpT0, parent)

	if got.In.Device != "ixl0_vlan50" || got.In.Name != "IOT" {
		t.Errorf("In = %+v, want ixl0_vlan50/IOT: a lone trunk copy with subnet evidence "+
			"has no partner to lose to, so the evidence is all there is", got.In)
	}
	if n := r.Stats().VLANSubnetAttributed; n != 1 {
		t.Errorf("VLANSubnetAttributed = %d, want 1", n)
	}
}

// It must not enter the hold buffer at all: bypassing the hold is what removes the
// arrival-order dependency AND what keeps occupancy from growing, which is #465's
// occupancy criterion.
func TestRepairer_SubnetEvidenceBypassesTheHoldBuffer(t *testing.T) {
	base, _ := rpVLANPairUntagged()
	// The bulk shape: an IOT host talking to the internet, so the ONLY trunk-named side
	// is the one the evidence resolves. Once it names the child, no side can be beaten,
	// so there is nothing to wait for.
	rec := base
	rec.DstAddr = netip.MustParseAddr("8.8.8.8")
	rec.In, rec.Out = rpIfLAN, rpIfWAN1

	r := NewRepairer(1000, 1000)
	if v := r.repairWith(&rec, rpBox(), rpSnapshot(), rpT0); v != RepairEmit {
		t.Fatalf("verdict = %v, want RepairEmit: an unambiguously attributed record must "+
			"not wait out the hold window", v)
	}
	if got := r.Stats().HeldEntries; got != 0 {
		t.Errorf("HeldEntries = %d, want 0", got)
	}
	if got := r.Stats().VLANSubnetAttributed; got != 1 {
		t.Errorf("VLANSubnetAttributed = %d, want 1", got)
	}
}

// THE OCCUPANCY CRITERION, and the conservative limit of the bypass. A side that still
// names a TRUNK the evidence could not resolve is still holdable — a more specific copy
// of THAT side may genuinely exist, and #465 is explicit that the 2-second hold stays as
// the fallback. So the bypass is not "attributed records never hold", it is "a record
// with no unresolved trunk side never holds".
//
// This is what makes the occupancy win real without making it a guess: the LAN-to-WAN
// and WAN-to-LAN flows that dominate real traffic name one trunk, which A' resolves, so
// they stop entering the buffer; a LAN-to-LAN flow whose far end sits on the trunk's own
// subnet keeps its trunk egress and still holds.
func TestRepairer_HoldStillCoversAnUnresolvedTrunkSide(t *testing.T) {
	parent, _ := rpVLANPairUntagged() // in=ixl0 out=ixl0, dst on the trunk's own subnet

	r := NewRepairer(1000, 1000)
	rec := parent
	if v := r.repairWith(&rec, rpBox(), rpSnapshot(), rpT0); v != RepairHold {
		t.Fatalf("verdict = %v, want RepairHold: the EGRESS still names a trunk that no "+
			"subnet evidence resolved, so a more specific copy of that side may exist", v)
	}
	// The ingress was still relabelled — a partial resolution is kept, not discarded.
	if got := r.Stats().VLANSubnetAttributed; got != 1 {
		t.Errorf("VLANSubnetAttributed = %d, want 1", got)
	}
	out := r.Flush()
	if len(out) != 1 || out[0].In.Device != "ixl0_vlan50" {
		t.Fatalf("released %d records, first In = %+v; want one record on ixl0_vlan50", len(out), out[0].In)
	}
}

// The EGRESS side resolves from the DESTINATION address, not the source. The pairing is
// physical: a record whose INGRESS is the trunk entered from the VLAN, so its SOURCE is
// the VLAN host; one whose EGRESS is the trunk is leaving toward the VLAN, so its
// DESTINATION is. Using the wrong address would attribute a flow to whichever VLAN the
// other end happened to sit on.
func TestRepairer_SubnetEvidenceResolvesEachSideFromItsOwnAddress(t *testing.T) {
	base, _ := rpVLANPairUntagged()

	t.Run("egress trunk resolves from the destination", func(t *testing.T) {
		rec := base
		// Inbound: from the internet to the IOT host, leaving by the trunk.
		rec.SrcAddr = netip.MustParseAddr("8.8.8.8")
		rec.DstAddr = netip.MustParseAddr("10.0.50.4")
		rec.In, rec.Out = rpIfWAN1, rpIfLAN

		got := rpOne(t, NewRepairer(1000, 1000), rpBox(), rpSnapshot(), rpT0, rec)
		if got.Out.Device != "ixl0_vlan50" {
			t.Errorf("Out.Device = %q, want ixl0_vlan50", got.Out.Device)
		}
		if got.In.Device != rpIfWAN1.Device {
			t.Errorf("In.Device = %q, want it untouched at %q", got.In.Device, rpIfWAN1.Device)
		}
	})

	t.Run("ingress trunk is not resolved from the destination", func(t *testing.T) {
		rec := base
		// The IOT address is the DESTINATION while the trunk is the INGRESS: the traffic
		// came in on the trunk from somewhere else entirely. There is no evidence about
		// the ingress here, so it must be left alone.
		rec.SrcAddr = netip.MustParseAddr("10.0.0.5")
		rec.DstAddr = netip.MustParseAddr("10.0.50.4")
		rec.In, rec.Out = rpIfLAN, rpIfWAN1

		got := rpOne(t, NewRepairer(1000, 1000), rpBox(), rpSnapshot(), rpT0, rec)
		if got.In.Device != "ixl0" {
			t.Errorf("In.Device = %q, want ixl0 untouched: the destination says nothing "+
				"about which interface the traffic ARRIVED on", got.In.Device)
		}
	})
}

// AMBIGUOUS OR ABSENT EVIDENCE MUST FALL BACK TO THE HOLD, unchanged. #403 measured
// 9,431 ambiguous pairs of 372,109, and #465 is explicit that the 2-second hold stays
// for them: subnet evidence is not total.
func TestRepairer_WithoutSubnetEvidenceTheHoldContestStillDecides(t *testing.T) {
	parent, child := rpVLANPairUntagged()
	// An address on no child subnet at all — the trunk's own subnet on both ends.
	for _, rec := range []*Record{&parent, &child} {
		rec.SrcAddr = netip.MustParseAddr("10.0.0.7")
		rec.DstAddr = netip.MustParseAddr("10.0.0.5")
	}

	t.Run("no evidence still holds", func(t *testing.T) {
		r := NewRepairer(1000, 1000)
		rec := parent
		if v := r.repairWith(&rec, rpBox(), rpSnapshot(), rpT0); v != RepairHold {
			t.Fatalf("verdict = %v, want RepairHold: with no subnet evidence the contest "+
				"is the only thing that can decide", v)
		}
		if got := r.Stats().VLANSubnetAttributed; got != 0 {
			t.Errorf("VLANSubnetAttributed = %d, want 0", got)
		}
	})

	// And the contest still produces the child, in both orders, exactly as before #465.
	for _, tc := range []struct {
		name string
		in   []Record
	}{
		{"trunk first", []Record{parent, child}},
		{"child first", []Record{child, parent}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRepairer(1000, 1000)
			kept := rpRun(r, rpBox(), rpSnapshot(), rpT0, tc.in...)
			if len(kept) != 1 {
				t.Fatalf("kept %d records, want 1", len(kept))
			}
			if kept[0].In.Device != "ixl0_vlan50" {
				t.Errorf("survivor In.Device = %q, want ixl0_vlan50 from the hold contest", kept[0].In.Device)
			}
		})
	}
}

// NEVER DROP AN UNCERTAIN RECORD — #403's scope says so outright. A record the
// evidence cannot place must still be emitted, on the trunk, rather than withheld.
func TestRepairer_UnresolvableRecordIsStillEmitted(t *testing.T) {
	parent, _ := rpVLANPairUntagged()
	parent.SrcAddr = netip.MustParseAddr("10.0.0.7") // no child subnet contains it
	parent.DstAddr = netip.MustParseAddr("10.0.0.5")

	got := rpOne(t, NewRepairer(1000, 1000), rpBox(), rpSnapshot(), rpT0, parent)
	if got.In.Device != "ixl0" {
		t.Errorf("In.Device = %q, want the trunk ixl0: unresolved means unchanged, not dropped", got.In.Device)
	}
}

// A record already naming a VLAN child is left completely alone. Re-resolving it could
// only ever move it to a different child, and the child copy is the ground truth.
func TestRepairer_ChildCopyIsNotReattributed(t *testing.T) {
	_, child := rpVLANPairUntagged()

	r := NewRepairer(1000, 1000)
	got := rpOne(t, r, rpBox(), rpSnapshot(), rpT0, child)
	if got.In != rpIfIOT {
		t.Errorf("In = %+v, want it untouched at %+v", got.In, rpIfIOT)
	}
	if n := r.Stats().VLANSubnetAttributed; n != 0 {
		t.Errorf("VLANSubnetAttributed = %d, want 0 — nothing was reattributed", n)
	}
}

// The relabel is recorded ON THE RECORD, not only in a counter, for the same reason the
// egress correction is: the counter says how often, this says which one. And it must be
// a LOG attribute, never Iface.Corrected — ifaceIsWAN treats Corrected as proof of a
// WAN by construction, so setting it on a VLAN child would make the direction rules
// call an IOT interface an uplink.
func TestRepairer_SubnetAttributionIsObservableWithoutClaimingAWAN(t *testing.T) {
	parent, _ := rpVLANPairUntagged()

	got := rpOne(t, NewRepairer(1000, 1000), rpBox(), rpSnapshot(), rpT0, parent)
	if !got.Repairs.VLANSubnetAttributed {
		t.Error("Repairs.VLANSubnetAttributed = false; a repair nobody can observe is a repair nobody will trust")
	}
	if got.In.Corrected {
		t.Error("In.Corrected = true; only the WAN-egress repair may set that — ifaceIsWAN " +
			"reads it as proof the interface IS a WAN")
	}
	if got.Direction == DirectionOutbound {
		t.Errorf("Direction = %v; a LAN-to-LAN flow relabelled onto a VLAN child must not "+
			"become outbound", got.Direction)
	}
}

// MECHANISM C'S RESIDUAL IS COUNTED RATHER THAN SILENTLY CORRECTED. An
// already-EMITTED record cannot be taken back — it has been counted in the rollup and
// shipped — so a later, more specific copy must still be dropped. What changes is that
// this is no longer invisible: the case is counted, so the residual is observable and
// the fix can be shown to have removed it.
func TestRepairer_LateMoreSpecificCopyIsCounted(t *testing.T) {
	parent, child := rpVLANPairUntagged()
	// Strip the evidence so A' cannot fire and the trunk copy really is admitted first.
	for _, rec := range []*Record{&parent, &child} {
		rec.SrcAddr = netip.MustParseAddr("10.0.0.7")
		rec.DstAddr = netip.MustParseAddr("10.0.0.5")
	}

	r := NewRepairer(1000, 1000)
	m, snap := rpBox(), rpSnapshot()
	// The trunk copy is held, then released into the de-dup table.
	if v := rpFeed(r, m, snap, rpT0, parent); v != RepairHold {
		t.Fatalf("first verdict = %v, want RepairHold", v)
	}
	// The child copy arrives after the window: proven duplicate, more specific, too late.
	rec := child
	if v := r.repairWith(&rec, m, snap, rpT0.Add(40*time.Second)); v != RepairDrop {
		t.Fatalf("second verdict = %v, want RepairDrop: the trunk copy has already been "+
			"emitted and counted, so re-emitting would double-count", v)
	}
	if n := r.Stats().VLANLateChildCopies; n != 1 {
		t.Errorf("VLANLateChildCopies = %d, want 1 — the residual must be observable", n)
	}
}

// The residual counter must NOT fire on an ordinary duplicate that is no more specific
// than the copy already admitted, or it would report a misattribution on every VLAN
// duplicate the stage resolves correctly.
func TestRepairer_LateCopyCounterIgnoresEquallySpecificDuplicates(t *testing.T) {
	_, child := rpVLANPairUntagged()

	r := NewRepairer(1000, 1000)
	m, snap := rpBox(), rpSnapshot()
	// The child copy's EGRESS still names the trunk, so it is held and then released
	// into the de-dup table by the flush rpFeed performs. Either way it is admitted.
	rpFeed(r, m, snap, rpT0, child)
	if got := r.Stats().DedupeEntries; got != 1 {
		t.Fatalf("DedupeEntries = %d after the flush, want 1", got)
	}
	rec := child
	if v := r.repairWith(&rec, m, snap, rpT0.Add(40*time.Second)); v != RepairDrop {
		t.Fatalf("second verdict = %v, want RepairDrop", v)
	}
	if n := r.Stats().VLANLateChildCopies; n != 0 {
		t.Errorf("VLANLateChildCopies = %d, want 0: an identical copy is not a misattribution", n)
	}
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
			r := NewRepairer(1000, 1000)
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

// The tag is what this box never sends: 0 of the 131 records in the golden capture
// carry SRC_VLAN/DST_VLAN, so mechanism A never fires on it and the untagged pair is
// the ONLY shape that occurs in production. The copies are then distinguishable only
// by topology, and the parent copy is the one that arrives first — every time, because
// the trunk hook and the child hook flush in separate consecutive datagrams of one
// expiry sweep.
//
// So this is the case #357 is about, and holding the parent copy is what fixes it:
// BOTH orders must collapse to the VLAN child, not merely to one record.
//
// SINCE #465 THE PARENT COPY IS RELABELLED BEFORE IT IS EVER HELD, so the hold contest
// has nothing left to win — the held record already names the child, and
// VLANChildPreferred stays at 0 in both orders. The OUTCOME asserted below is unchanged,
// which is the point: subnet evidence resolves this pair earlier, not differently.
// VLANSubnetAttributed is now the counter that moves. #403 measured 0 disagreements
// between the two mechanisms across 362,678 pairs, and this is one of them.
func TestRepairer_UntaggedVLANDuplicateStillResolvesToTheChildInBothOrders(t *testing.T) {
	parent, child := rpVLANPairUntagged()

	tests := []struct {
		name               string
		in                 []Record
		wantChildPreferred uint64
	}{
		{"vlan copy first", []Record{child, parent}, 0},
		// The production order. Before #465 the parent copy was held and the child took
		// its place (VLANChildPreferred = 1); now A' relabels the parent copy onto the
		// child on sight, so the two copies are identical by the time they meet.
		{"parent copy first", []Record{parent, child}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRepairer(1000, 1000)
			kept := rpRun(r, rpBox(), rpSnapshot(), rpT0, tc.in...)

			if len(kept) != 1 {
				t.Fatalf("kept %d records, want exactly 1", len(kept))
			}
			if kept[0].In.Device != "ixl0_vlan50" {
				t.Errorf("survivor In.Device = %q, want ixl0_vlan50 — keeping the trunk copy "+
					"attributes IOT traffic to LAN, which is the defect in #357", kept[0].In.Device)
			}
			if got := kept[0].NF.Bytes(); got != 24935 {
				t.Errorf("survivor bytes = %d, want 24935", got)
			}
			st := r.Stats()
			if st.VLANDuplicatesDropped != 1 {
				t.Errorf("VLANDuplicatesDropped = %d, want 1", st.VLANDuplicatesDropped)
			}
			if st.VLANChildPreferred != tc.wantChildPreferred {
				t.Errorf("VLANChildPreferred = %d, want %d", st.VLANChildPreferred, tc.wantChildPreferred)
			}
			if st.VLANSubnetAttributed == 0 {
				t.Error("VLANSubnetAttributed = 0; the trunk copy carries a source address " +
					"inside the IOT subnet, so A' must be what resolved this")
			}
			if st.VLANLateChildCopies != 0 {
				t.Errorf("VLANLateChildCopies = %d, want 0: nothing was misattributed here", st.VLANLateChildCopies)
			}
			if st.HeldEntries != 0 {
				t.Errorf("HeldEntries = %d after the flush, want 0", st.HeldEntries)
			}
		})
	}
}

// The de-dup keyed on the INGRESS device alone until #357, which left the inbound half
// of every VLAN conversation undeduplicated: for traffic arriving from the WAN and
// leaving on a VLAN, the two copies agree on the ingress (pppoe0) and differ on the
// EGRESS. Nothing about a duplicate pair says which side the hooks disagree about.
func TestRepairer_EgressSideVLANDuplicateIsResolvedToTheChild(t *testing.T) {
	base := Record{
		Source: SourceNetflow, Proto: 6,
		SrcAddr: netip.MustParseAddr("93.184.216.34"), SrcPort: 443,
		DstAddr: netip.MustParseAddr("10.0.50.4"), DstPort: 51234,
		Start: rpT0, End: rpT0.Add(time.Second),
		NF: Counters{TxBytes: 8192, TxPackets: 12, Present: true},
	}
	parent, child := base, base
	parent.In, parent.Out = rpIfWAN1, rpIfLAN
	child.In, child.Out = rpIfWAN1, rpIfIOT

	for _, tc := range []struct {
		name string
		in   []Record
	}{
		{"parent copy first", []Record{parent, child}},
		{"vlan copy first", []Record{child, parent}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRepairer(1000, 1000)
			kept := rpRun(r, rpBox(), rpSnapshot(), rpT0, tc.in...)

			if len(kept) != 1 {
				t.Fatalf("kept %d records, want exactly 1 — the same 8,192 bytes twice", len(kept))
			}
			if kept[0].Out.Device != "ixl0_vlan50" {
				t.Errorf("survivor Out.Device = %q, want ixl0_vlan50", kept[0].Out.Device)
			}
			if st := r.Stats(); st.VLANDuplicatesDropped != 1 {
				t.Errorf("VLANDuplicatesDropped = %d, want 1", st.VLANDuplicatesDropped)
			}
		})
	}
}

// An inter-VLAN flow is seen by BOTH hooks with the same ingress and egress ifIndex —
// trunk in, child out — so the two copies are byte-for-byte identical and no
// trunk/child pair distinguishes them. Requiring such a pair let both through and
// double-counted the bytes; on the golden fixture that was two flows and 211 bytes.
//
// Everything else about the key has already established these are one export: same
// direction, same timestamps, same volume. Two of those cannot be two flows.
func TestRepairer_IdenticalCopiesOnOneInterfacePairCollapse(t *testing.T) {
	rec := Record{
		Source: SourceNetflow, Proto: 17,
		SrcAddr: netip.MustParseAddr("10.0.0.5"), SrcPort: 41302,
		DstAddr: netip.MustParseAddr("10.0.50.19"), DstPort: 161,
		Start: rpT0, End: rpT0,
		In: rpIfLAN, Out: rpIfIOT,
		NF: Counters{TxBytes: 69, TxPackets: 1, Present: true},
	}

	r := NewRepairer(1000, 1000)
	kept := rpRun(r, rpBox(), rpSnapshot(), rpT0, rec, rec)

	if len(kept) != 1 {
		t.Fatalf("kept %d records, want exactly 1 — 69 bytes counted twice is 69 bytes of invented traffic", len(kept))
	}
	if st := r.Stats(); st.VLANDuplicatesDropped != 1 {
		t.Errorf("VLANDuplicatesDropped = %d, want 1", st.VLANDuplicatesDropped)
	}
}

// The two DIRECTIONS of one conversation are two exports, not two copies of one. They
// share a canonical tuple and, when both halves close in the same sweep, their First
// and Last as well — which is exactly how the pre-#357 key folded them together and
// destroyed the smaller one as a "VLAN duplicate".
//
// Their volumes differ, because they carried different traffic. That is what the key
// now keys on, and this is the case it exists for.
func TestRepairer_OppositeDirectionsWithOneTimestampAreBothKept(t *testing.T) {
	forward := Record{
		Source: SourceNetflow, Proto: 6,
		SrcAddr: netip.MustParseAddr("10.0.50.15"), SrcPort: 52231,
		DstAddr: netip.MustParseAddr("10.0.0.16"), DstPort: 8080,
		Start: rpT0, End: rpT0,
		In: rpIfIOT, Out: rpIfLAN,
		NF: Counters{TxBytes: 4907, TxPackets: 8, Present: true},
	}
	reverse := Record{
		Source: SourceNetflow, Proto: 6,
		SrcAddr: forward.DstAddr, SrcPort: forward.DstPort,
		DstAddr: forward.SrcAddr, DstPort: forward.SrcPort,
		Start: rpT0, End: rpT0,
		In: rpIfLAN, Out: rpIfIOT,
		NF: Counters{TxBytes: 558, TxPackets: 7, Present: true},
	}

	r := NewRepairer(1000, 1000)
	kept := rpRun(r, rpBox(), rpSnapshot(), rpT0, forward, reverse)

	if len(kept) != 2 {
		t.Fatalf("kept %d records, want 2 — a NetFlow record is unidirectional, so the "+
			"two halves of a conversation are separate exports and neither is the other's duplicate", len(kept))
	}
	if st := r.Stats(); st.VLANDuplicatesDropped != 0 {
		t.Errorf("VLANDuplicatesDropped = %d, want 0 — nothing here was proven a duplicate", st.VLANDuplicatesDropped)
	}
}

// The hold window is what makes the outcome independent of arrival order, and it must
// end on its own: a record whose partner never arrives is emitted, not stranded. Its
// repairs run at release, so this also proves the deferral does not lose them.
func TestRepairer_HeldRecordIsReleasedWhenItsWindowElapses(t *testing.T) {
	rec := Record{
		Source: SourceNetflow, Proto: 6,
		SrcAddr: netip.MustParseAddr(rpWAN2Addr), SrcPort: 51234,
		DstAddr: netip.MustParseAddr("93.184.216.34"), DstPort: 443,
		Start: rpT0, End: rpT0.Add(time.Second),
		In: rpIfLAN, Out: rpIfWAN1, // the FIB's claim; repair 2 must still correct it
		NF: Counters{TxBytes: 4096, TxPackets: 8, Present: true},
	}

	r := NewRepairer(1000, 1000)
	if v := r.repairWith(&rec, rpBox(), rpSnapshot(), rpT0); v != RepairHold {
		t.Fatalf("verdict = %v, want RepairHold — ixl0 is a trunk, so a better copy could still arrive", v)
	}
	if st := r.Stats(); st.HeldEntries != 1 {
		t.Fatalf("HeldEntries = %d, want 1", st.HeldEntries)
	}
	if got := r.Release(rpT0.Add(vlanHoldWindow - time.Millisecond)); len(got) != 0 {
		t.Fatalf("released %d records before the window elapsed, want 0", len(got))
	}

	got := r.Release(rpT0.Add(vlanHoldWindow))
	if len(got) != 1 {
		t.Fatalf("released %d records at the deadline, want 1", len(got))
	}
	if !got[0].Out.Corrected || got[0].Out.Device != "igb0" {
		t.Errorf("released record Out = %+v, want the corrected igb0 — repair 2 is deferred, not skipped", got[0].Out)
	}
	if got[0].Direction != DirectionOutbound {
		t.Errorf("released record Direction = %v, want outbound — repair 3 is deferred, not skipped", got[0].Direction)
	}
	if st := r.Stats(); st.HeldEntries != 0 || st.DedupeEntries != 1 {
		t.Errorf("Stats() = %+v, want the record out of the hold buffer and remembered by the table", st)
	}
}

// The hold buffer holds records nobody downstream has seen, so overrunning its bound
// must never DROP one. The oldest is released early instead — degrading that record to
// the first-seen-wins behaviour that predates #357 — and the pressure is counted apart
// from everything else, because it is the one number that says attribution is being
// decided by arrival order again.
func TestRepairer_HoldBufferOverflowReleasesRatherThanDrops(t *testing.T) {
	r := NewRepairer(1000, 2)
	_, child := rpVLANPair()
	child.VLANID = "" // this box sends no tag; mechanism A must not pre-empt the hold

	var held []Record
	for i := range 5 {
		rec := child
		rec.In = rpIfLAN // a trunk, so every one of these is a hold candidate
		rec.SrcPort = uint16(5432 + i)
		if v := r.repairWith(&rec, rpBox(), rpSnapshot(), rpT0); v != RepairHold {
			t.Fatalf("record %d verdict = %v, want RepairHold", i, v)
		}
		held = append(held, r.Release(rpT0)...)
	}

	st := r.Stats()
	if st.HeldEntries != 2 {
		t.Errorf("HeldEntries = %d, want 2 — the bound is not being enforced", st.HeldEntries)
	}
	if st.HoldOverflow != 3 {
		t.Errorf("HoldOverflow = %d, want 3", st.HoldOverflow)
	}
	if len(held) != 3 {
		t.Errorf("released %d records early, want 3 — an overflowing buffer must emit, never drop", len(held))
	}
	if st.VLANDuplicatesDropped != 0 {
		t.Errorf("VLANDuplicatesDropped = %d, want 0 — nothing here was a duplicate", st.VLANDuplicatesDropped)
	}
	if total := len(held) + st.HeldEntries; total != 5 {
		t.Errorf("%d of 5 records accounted for; the rest were lost", total)
	}
}

// The instance key is (directional 5-tuple, First, Last, volume). A long-lived
// conversation is exported repeatedly with the SAME tuple and different timestamps, so
// keying on the tuple alone would silently discard every export after the first —
// turning a busy flow into a single record.
func TestRepairer_SameTupleDifferentInstanceIsKept(t *testing.T) {
	_, child := rpVLANPair()
	second := child
	second.Start = child.End
	second.End = child.End.Add(3 * time.Second)

	r := NewRepairer(1000, 1000)
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

	r := NewRepairer(1000, 1000)
	if r.repairWith(&parent, rpBox(), rpSnapshot(), rpT0) != RepairDrop {
		t.Fatal("parent copy was not dropped; it is a tagged VLAN duplicate")
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
			r := NewRepairer(1000, 1000)
			rec = rpOne(t, r, rpBox(), rpSnapshot(), rpT0, rec)
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
	r := NewRepairer(1000, 1000)
	rec = rpOne(t, r, rpBox(), rpSnapshot(), rpT0, rec)

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
			r := NewRepairer(1000, 1000)
			rec = rpOne(t, r, rpBox(), tc.snap, rpT0, rec)
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
	r := NewRepairer(1000, 1000)
	outbound = rpOne(t, r, blind, rpSnapshot(), rpT0, outbound)
	if outbound.Direction != DirectionOutbound {
		t.Errorf("Direction = %v, want outbound", outbound.Direction)
	}

	inbound := Record{
		Source: SourceNetflow, Proto: 6,
		SrcAddr: netip.MustParseAddr("93.184.216.34"), SrcPort: 443,
		DstAddr: netip.MustParseAddr(rpWAN1Addr), DstPort: 51234,
		Start: rpT0, End: rpT0, In: rpIfWAN1, Out: rpIfLAN,
	}
	r2 := NewRepairer(1000, 1000)
	inbound = rpOne(t, r2, blind, rpSnapshot(), rpT0, inbound)
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
	r := NewRepairer(1000, 1000)
	rec = rpOne(t, r, rpBox(), rpSnapshot(), rpT0, rec)

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

	r := NewRepairer(1000, 1000)
	if rpFeed(r, rpBox(), rpSnapshot(), rpT0, child) == RepairDrop {
		t.Fatal("first record dropped")
	}
	if st := r.Stats(); st.DedupeEntries != 1 || st.DedupeEvicted != 0 {
		t.Fatalf("Stats() = %+v, want 1 entry and no evictions", st)
	}

	// One TTL later, plus a margin: the first instance can no longer be part of a
	// duplicate pair, so it must not still be occupying the table.
	rpFeed(r, rpBox(), rpSnapshot(), rpT0.Add(dedupeTTL+time.Second), later)

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
	r := NewRepairer(2, 1000)
	_, child := rpVLANPair()

	for i := 0; i < 5; i++ {
		rec := child
		rec.SrcPort = uint16(5432 + i)
		if rpFeed(r, rpBox(), rpSnapshot(), rpT0, rec) == RepairDrop {
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

	r := NewRepairer(1, 1000)
	if rpFeed(r, rpBox(), rpSnapshot(), rpT0, child) == RepairDrop {
		t.Fatal("vlan copy dropped")
	}
	// A second instance evicts the first.
	other := child
	other.SrcPort = 5433
	rpFeed(r, rpBox(), rpSnapshot(), rpT0, other)

	if rpFeed(r, rpBox(), rpSnapshot(), rpT0, parent) == RepairDrop {
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
	r := NewRepairer(0, 1000)
	_, child := rpVLANPair()
	for i := 0; i < 200; i++ {
		rec := child
		rec.SrcPort = uint16(1000 + i)
		rpFeed(r, rpBox(), rpSnapshot(), rpT0, rec)
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
	r := NewRepairer(1000, 1000)

	kept := 0
	for _, rec := range []Record{parent, child} {
		if r.Repair(&rec, nil, nil, rpT0) == RepairEmit {
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

// Repair runs on a UDP worker POOL, so the table and the hold buffer are shared
// mutable state. Run under -race. The assertions are deterministic by construction:
// every parent copy is dropped by the tag rule on sight, which does not depend on what
// any other goroutine did first.
//
// Each worker owns a DISJOINT port range. Two workers emitting the identical record
// would not be a concurrency artefact to tolerate — with the #357 key it is a genuine
// duplicate and the stage would rightly suppress it, which would make this test assert
// the de-dup rule rather than the locking.
func TestRepairer_ConcurrentRepairIsRaceFree(t *testing.T) {
	const workers = 8
	const iterations = 250

	r := NewRepairer(4096, 1000)
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
				child.SrcPort = uint16(1024 + w*iterations + i)
				parent.SrcPort = child.SrcPort
				now := rpT0.Add(time.Duration(i) * time.Millisecond)
				// Not-dropped rather than emitted: the child copy names the trunk on its
				// egress, so it is HELD and reaches the sink from the release path.
				if r.repairWith(&parent, m, snap, now) != RepairDrop {
					kept[w]++
				}
				if r.repairWith(&child, m, snap, now) != RepairDrop {
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
	m := BuildIfMap(IfMapInput{Order: devicesOf(liveIfaces()), Ifaces: liveIfaces()})
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
	r := NewRepairer(1000, 1000)
	outbound = rpOne(t, r, m, snap, rpT0, outbound)
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
	inbound = rpOne(t, r, m, snap, rpT0, inbound)
	if inbound.Direction != DirectionInbound {
		t.Errorf("Direction = %v, want inbound", inbound.Direction)
	}
}

// The VLAN de-dup resolved against the REAL IfMap: ifIndex 1 is the trunk ixl0 and
// ifIndex 13 is ixl0_vlan50/IOT, both verified live (#346). Driving the hand-built
// topology alone would prove the logic but not that the map it will actually run
// against answers ParentOf the way the logic assumes.
func TestRepairer_VLANDedupeAgainstTheRealIfMap(t *testing.T) {
	m := BuildIfMap(IfMapInput{Order: devicesOf(liveIfaces()), Ifaces: liveIfaces()})
	parent, child := rpVLANPair()
	parent.In, parent.Out = m.Iface(1), m.Iface(1)
	child.In, child.Out = m.Iface(13), m.Iface(1)

	r := NewRepairer(1000, 1000)
	var kept []Record
	for _, rec := range []Record{parent, child} {
		if r.Repair(&rec, m, rpSnapshot(), rpT0) == RepairEmit {
			kept = append(kept, rec)
		}
	}
	kept = append(kept, r.Flush()...)
	if len(kept) != 1 {
		t.Fatalf("kept %d records, want 1", len(kept))
	}
	if kept[0].In.Name != "IOT" {
		t.Errorf("survivor In.Name = %q, want IOT", kept[0].In.Name)
	}
}

// Repair is the exported entry point and must behave identically to the seam the
// rest of these tests drive; a divergence there would make every one of them prove
// nothing about what the processor actually calls.
func TestRepairer_ExportedRepairMatchesTheSeam(t *testing.T) {
	var m *IfMap // the pre-refresh state processor.go can pass
	_, child := rpVLANPair()
	r := NewRepairer(1000, 1000)
	if r.Repair(&child, m, rpSnapshot(), rpT0) != RepairEmit {
		t.Fatal("Repair dropped or held a record with a nil IfMap; with no topology " +
			"nothing is provably a duplicate and nothing can be beaten")
	}
	if child.Enrich.DstScope != "local" {
		t.Errorf("DstScope = %q, want local — Repair must still resolve scope", child.Enrich.DstScope)
	}
}

// The IfMap the receiver lane owns must satisfy the seam this package resolves
// against. If this stops compiling, the contract moved.
var _ ifTopology = (*IfMap)(nil)
