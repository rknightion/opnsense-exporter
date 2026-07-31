package flow

import (
	"net/netip"
	"testing"
	"time"
)

// The bug, verbatim from the prod firewall (#603): a LAN host policy-routed out
// WAN2 by pf, whose PRE-NAT NetFlow record — the only copy that can ever correlate
// with a Zenarmor conn document — carries OUTPUT_SNMP from the FIB and therefore
// names WAN1.
func rpPolicyRoutedRecord() Record {
	return Record{
		Source:  SourceNetflow,
		Proto:   6,
		SrcAddr: netip.MustParseAddr("10.0.0.6"),
		SrcPort: 52824,
		DstAddr: netip.MustParseAddr("203.0.113.203"),
		DstPort: 8007,
		Start:   rpT0,
		End:     rpT0.Add(3 * time.Second),
		NF:      Counters{TxBytes: 3186, TxPackets: 15, Present: true},
		In:      rpIfLAN,
		Out:     rpIfWAN1, // the FIB's answer, and it is wrong
	}
}

// rpRoutes builds a table stating that the conversation above left by WAN2.
func rpRoutes(device string) *RouteTable {
	return BuildRouteTable(RouteTableInput{
		Rows: []StateRow{{
			Proto: "tcp", Direction: "in",
			SrcAddr: "10.0.0.6", SrcPort: "52824",
			DstAddr: "203.0.113.203", DstPort: "8007",
			RouteToDevice: device,
		}},
		Built: rpT0,
	})
}

func TestRepairer_PolicyRouteOverridesTheFIBEgress(t *testing.T) {
	r := NewRepairer(0, 0)
	r.SetRouteTable(rpRoutes(rpIfWAN2.Device))

	got := rpOne(t, r, rpBox(), rpSnapshot(), rpT0, rpPolicyRoutedRecord())

	if got.Out.Device != rpIfWAN2.Device {
		t.Fatalf("Out.Device = %q, want %q", got.Out.Device, rpIfWAN2.Device)
	}
	if got.Out.Name != rpIfWAN2.Name {
		t.Fatalf("Out.Name = %q, want %q — the label must be the description, not the kernel device", got.Out.Name, rpIfWAN2.Name)
	}
	if !got.Repairs.PolicyRouteCorrected {
		t.Error("Repairs.PolicyRouteCorrected = false; the correction must be visible on the record")
	}
	// The invariant #603 called out explicitly: ifaceIsWAN reads Iface.Corrected as
	// proof-of-WAN-by-construction, and only repair 2 may set it.
	if got.Out.Corrected {
		t.Error("Out.Corrected = true; only the WAN-egress repair may set that flag")
	}
	if got.Direction != DirectionOutbound {
		t.Errorf("Direction = %v, want outbound", got.Direction)
	}
	if s := r.Stats(); s.PolicyRouteCorrected != 1 {
		t.Errorf("PolicyRouteCorrected = %d, want 1", s.PolicyRouteCorrected)
	}
	if s := r.Stats(); s.PolicyRouteNoState != 0 {
		t.Errorf("PolicyRouteNoState = %d, want 0", s.PolicyRouteNoState)
	}
}

// A state exists and pf applied NO route-to: the FIB decided, so OUTPUT_SNMP is
// already right and nothing may move. This is the majority of states on the live
// box (1,464 of 3,232 direction="in" rows carry no route-to) and it must NOT be
// counted as a miss.
func TestRepairer_PolicyRouteLeavesFIBRoutedRecordsAlone(t *testing.T) {
	r := NewRepairer(0, 0)
	r.SetRouteTable(rpRoutes(""))

	got := rpOne(t, r, rpBox(), rpSnapshot(), rpT0, rpPolicyRoutedRecord())

	if got.Out.Device != rpIfWAN1.Device {
		t.Fatalf("Out.Device = %q, want %q unchanged", got.Out.Device, rpIfWAN1.Device)
	}
	if got.Repairs.PolicyRouteCorrected {
		t.Error("Repairs.PolicyRouteCorrected = true on a FIB-routed record")
	}
	s := r.Stats()
	if s.PolicyRouteCorrected != 0 || s.PolicyRouteNoState != 0 {
		t.Errorf("corrected=%d noState=%d, want 0/0", s.PolicyRouteCorrected, s.PolicyRouteNoState)
	}
}

// The miss window: a short flow whose state expired before its record arrived. It
// is REFUSED and COUNTED, never guessed — the counters for "corrected" and "no
// state" are kept apart because they call for opposite operator responses.
func TestRepairer_PolicyRouteRefusesAndCountsAMissingState(t *testing.T) {
	r := NewRepairer(0, 0)
	r.SetRouteTable(BuildRouteTable(RouteTableInput{Built: rpT0}))

	got := rpOne(t, r, rpBox(), rpSnapshot(), rpT0, rpPolicyRoutedRecord())

	if got.Out.Device != rpIfWAN1.Device {
		t.Fatalf("Out.Device = %q, want %q unchanged — a missing state proves nothing", got.Out.Device, rpIfWAN1.Device)
	}
	s := r.Stats()
	if s.PolicyRouteNoState != 1 {
		t.Errorf("PolicyRouteNoState = %d, want 1", s.PolicyRouteNoState)
	}
	if s.PolicyRouteCorrected != 0 {
		t.Errorf("PolicyRouteCorrected = %d, want 0", s.PolicyRouteCorrected)
	}
}

// The ambiguity the destination-match design would have had to refuse cannot arise
// on this key — it is the tuple pf itself keys states by. Two LAN hosts to the SAME
// destination over DIFFERENT WANs get their own answers, not each other's.
func TestRepairer_PolicyRouteDoesNotCrossAttributeTwoHostsToOneDestination(t *testing.T) {
	r := NewRepairer(0, 0)
	r.SetRouteTable(BuildRouteTable(RouteTableInput{
		Rows: []StateRow{
			{Proto: "tcp", Direction: "in", SrcAddr: "10.0.0.6", SrcPort: "52824",
				DstAddr: "203.0.113.203", DstPort: "8007", RouteToDevice: rpIfWAN2.Device},
			{Proto: "tcp", Direction: "in", SrcAddr: "10.0.0.7", SrcPort: "40001",
				DstAddr: "203.0.113.203", DstPort: "8007"},
		},
		Built: rpT0,
	}))

	viaWAN2 := rpPolicyRoutedRecord()
	viaFIB := rpPolicyRoutedRecord()
	viaFIB.SrcAddr = netip.MustParseAddr("10.0.0.7")
	viaFIB.SrcPort = 40001

	gotWAN2 := rpOne(t, r, rpBox(), rpSnapshot(), rpT0, viaWAN2)
	gotFIB := rpOne(t, r, rpBox(), rpSnapshot(), rpT0, viaFIB)

	if gotWAN2.Out.Device != rpIfWAN2.Device {
		t.Errorf("policy-routed host: Out.Device = %q, want %q", gotWAN2.Out.Device, rpIfWAN2.Device)
	}
	if gotFIB.Out.Device != rpIfWAN1.Device {
		t.Errorf("FIB-routed host: Out.Device = %q, want %q — it must not inherit the other host's WAN",
			gotFIB.Out.Device, rpIfWAN1.Device)
	}
}

// A POST-NAT record's source IS a WAN address, so its tuple is not one any
// direction="in" state carries. Consulting the table for it would turn every such
// record into a phantom "no state" and drown the counter that matters.
func TestRepairer_PolicyRouteIgnoresPostNATRecords(t *testing.T) {
	r := NewRepairer(0, 0)
	r.SetRouteTable(BuildRouteTable(RouteTableInput{Built: rpT0}))

	rec := rpPolicyRoutedRecord()
	rec.SrcAddr = netip.MustParseAddr(rpWAN2Addr)
	rec.Out = rpIfWAN2

	got := rpOne(t, r, rpBox(), rpSnapshot(), rpT0, rec)

	if got.Out.Device != rpIfWAN2.Device {
		t.Errorf("Out.Device = %q, want %q unchanged", got.Out.Device, rpIfWAN2.Device)
	}
	if s := r.Stats(); s.PolicyRouteNoState != 0 {
		t.Errorf("PolicyRouteNoState = %d, want 0 — a post-NAT record is not in the miss window", s.PolicyRouteNoState)
	}
}

// An inbound record's egress is a LAN interface, so it is not a candidate at all.
func TestRepairer_PolicyRouteIgnoresRecordsNotLeavingByAWAN(t *testing.T) {
	r := NewRepairer(0, 0)
	r.SetRouteTable(BuildRouteTable(RouteTableInput{Built: rpT0}))

	rec := rpPolicyRoutedRecord()
	rec.In, rec.Out = rpIfWAN1, rpIfLAN

	rpOne(t, r, rpBox(), rpSnapshot(), rpT0, rec)

	if s := r.Stats(); s.PolicyRouteNoState != 0 {
		t.Errorf("PolicyRouteNoState = %d, want 0", s.PolicyRouteNoState)
	}
}

// A route-to naming a device the interface map cannot corroborate must NOT reach
// the metric label as a raw kernel name (#606's failure mode). It is refused and
// counted apart from the miss window, because the two have different fixes.
func TestRepairer_PolicyRouteRefusesAnUnresolvableDevice(t *testing.T) {
	r := NewRepairer(0, 0)
	r.SetRouteTable(rpRoutes("ixl9"))

	got := rpOne(t, r, rpBox(), rpSnapshot(), rpT0, rpPolicyRoutedRecord())

	if got.Out.Device != rpIfWAN1.Device {
		t.Fatalf("Out.Device = %q, want %q unchanged", got.Out.Device, rpIfWAN1.Device)
	}
	s := r.Stats()
	if s.PolicyRouteUnresolvedDevice != 1 {
		t.Errorf("PolicyRouteUnresolvedDevice = %d, want 1", s.PolicyRouteUnresolvedDevice)
	}
	if s.PolicyRouteNoState != 0 || s.PolicyRouteCorrected != 0 {
		t.Errorf("noState=%d corrected=%d, want 0/0", s.PolicyRouteNoState, s.PolicyRouteCorrected)
	}
}

// No table published yet — the window between startup and the first cold-tier poll.
// Nothing may be corrected and nothing may be counted as a miss: the mechanism is
// absent, not failing.
func TestRepairer_PolicyRouteIsInertWithoutATable(t *testing.T) {
	r := NewRepairer(0, 0)

	got := rpOne(t, r, rpBox(), rpSnapshot(), rpT0, rpPolicyRoutedRecord())

	if got.Out.Device != rpIfWAN1.Device {
		t.Fatalf("Out.Device = %q, want %q unchanged", got.Out.Device, rpIfWAN1.Device)
	}
	s := r.Stats()
	if s.PolicyRouteNoState != 0 || s.PolicyRouteCorrected != 0 {
		t.Errorf("noState=%d corrected=%d, want 0/0 with no table", s.PolicyRouteNoState, s.PolicyRouteCorrected)
	}
}

// A held record's repairs are deferred to Release, so repair 4 has to run there too
// — otherwise every VLAN-held record skips the correction.
func TestRepairer_PolicyRouteAppliesToHeldRecords(t *testing.T) {
	r := NewRepairer(0, 0)
	r.SetRouteTable(BuildRouteTable(RouteTableInput{
		Rows: []StateRow{{
			Proto: "tcp", Direction: "in",
			SrcAddr: "10.0.50.4", SrcPort: "5432",
			DstAddr: "203.0.113.203", DstPort: "8007",
			RouteToDevice: rpIfWAN2.Device,
		}},
		Built: rpT0,
	}))

	// A trunk-named record: HasVLANChildren("ixl0") is true, so the stage parks it.
	rec := Record{
		Source:  SourceNetflow,
		Proto:   6,
		SrcAddr: netip.MustParseAddr("10.0.50.4"),
		SrcPort: 5432,
		DstAddr: netip.MustParseAddr("203.0.113.203"),
		DstPort: 8007,
		Start:   rpT0,
		End:     rpT0.Add(time.Second),
		NF:      Counters{TxBytes: 100, TxPackets: 2, Present: true},
		In:      rpIfLAN,
		Out:     rpIfWAN1,
	}
	got := rpOne(t, r, rpBox(), rpSnapshot(), rpT0, rec)
	if got.Out.Device != rpIfWAN2.Device {
		t.Fatalf("held record Out.Device = %q, want %q", got.Out.Device, rpIfWAN2.Device)
	}
}
