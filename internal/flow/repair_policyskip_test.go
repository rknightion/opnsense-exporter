package flow

import (
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
)

// Repair 4's four SILENT EXITS, made countable (#624).
//
// None of these is a fault — they are the ways the repair correctly has nothing to
// do. They are tested because before they were counted, three of the four moved no
// counter at all, so "the repair has nothing to correct" and "the repair is never
// running" produced identical telemetry.

func skipTopology() *IfMap {
	return BuildIfMap(IfMapInput{
		Order: []string{"ixl0", "ixl1", "pppoe0"},
		Ifaces: []enrich.IfaceInfo{
			{Device: "ixl0", Name: "LAN", Identifier: "lan", Addrs: addrs("10.0.0.1")},
			{Device: "ixl1", Name: "VIRGIN", Identifier: "opt6", IsWAN: true, Addrs: addrs("198.51.100.6")},
			{Device: "pppoe0", Name: "AAISP", Identifier: "wan", IsWAN: true, Addrs: addrs("198.51.100.42")},
		},
		Built: time.Unix(1700000000, 0),
	})
}

func skipRecord(src string, sport uint16, dst string, dport uint16, out Iface) *Record {
	return &Record{
		Proto:   6,
		SrcAddr: netip.MustParseAddr(src),
		DstAddr: netip.MustParseAddr(dst),
		SrcPort: sport,
		DstPort: dport,
		NF:      Counters{TxBytes: 1000, TxPackets: 4, Present: true},
		Start:   time.Unix(1700000000, 0),
		End:     time.Unix(1700000001, 0),
		In:      Iface{Device: "ixl0", Name: "LAN"},
		Out:     out,
	}
}

// stateRow is one direction="in" pf state, optionally policy-routed.
func inRow(src string, sport uint16, dst string, dport uint16, device string) StateRow {
	return StateRow{
		Proto: "tcp", Direction: "in",
		SrcAddr: src, SrcPort: portStr(sport),
		DstAddr: dst, DstPort: portStr(dport),
		RouteToDevice: device,
	}
}

func portStr(v uint16) string { return strconv.Itoa(int(v)) }

func skipRepairer(rows ...StateRow) *Repairer {
	r := NewRepairer(0, 1000)
	r.SetRouteTable(BuildRouteTable(RouteTableInput{Rows: rows, Built: time.Unix(1700000000, 0)}))
	return r
}

func TestPolicyRouteSkipNotWANEgress(t *testing.T) {
	// The majority of records on any box - and also exactly what a wrong interface
	// map looks like, which is why it is counted rather than merely returned from.
	r := skipRepairer()
	m := skipTopology()
	rec := skipRecord("10.0.0.6", 5000, "10.0.0.9", 22, Iface{Device: "ixl0", Name: "LAN"})
	r.correctPolicyRoute(rec, m)

	st := r.Stats()
	if st.PolicyRouteSkippedNotWANEgress != 1 {
		t.Errorf("not_wan_egress = %d, want 1", st.PolicyRouteSkippedNotWANEgress)
	}
	if st.PolicyRouteNoState != 0 {
		t.Errorf("no_state = %d, want 0: a non-WAN record is not a miss", st.PolicyRouteNoState)
	}
}

func TestPolicyRouteSkipPostNAT(t *testing.T) {
	// Repair 2's population: the source IS a WAN address, so it was already resolved.
	r := skipRepairer()
	m := skipTopology()
	rec := skipRecord("198.51.100.6", 42031, "203.0.113.9", 8007, Iface{Device: "ixl1", Name: "VIRGIN"})
	r.correctPolicyRoute(rec, m)

	if got := r.Stats().PolicyRouteSkippedPostNAT; got != 1 {
		t.Errorf("post_nat = %d, want 1", got)
	}
}

func TestPolicyRouteSkipFIBAgreed(t *testing.T) {
	// A state exists but carries NO route-to: pf used the FIB, which is precisely
	// when ng_netflow's OUTPUT_SNMP is already right.
	r := skipRepairer(inRow("10.0.0.6", 36180, "203.0.113.9", 8007, ""))
	m := skipTopology()
	rec := skipRecord("10.0.0.6", 36180, "203.0.113.9", 8007, Iface{Device: "pppoe0", Name: "AAISP"})
	r.correctPolicyRoute(rec, m)

	st := r.Stats()
	if st.PolicyRouteSkippedFIBAgreed != 1 {
		t.Errorf("fib_agreed = %d, want 1", st.PolicyRouteSkippedFIBAgreed)
	}
	if st.PolicyRouteSkippedAlreadyOnWAN != 0 {
		t.Errorf("already_on_wan = %d, want 0 — an empty route-to is the FIB, not agreement", st.PolicyRouteSkippedAlreadyOnWAN)
	}
	if st.PolicyRouteCorrected != 0 {
		t.Errorf("corrected = %d, want 0", st.PolicyRouteCorrected)
	}
}

func TestPolicyRouteSkipAlreadyOnWAN(t *testing.T) {
	// pf DID policy-route it, and ng_netflow happened to name the same device.
	// Kept apart from fib_agreed: a high fib_agreed means the box barely
	// policy-routes, a high already_on_wan means it does and we agree with it.
	r := skipRepairer(inRow("10.0.0.6", 36180, "203.0.113.9", 8007, "pppoe0"))
	m := skipTopology()
	rec := skipRecord("10.0.0.6", 36180, "203.0.113.9", 8007, Iface{Device: "pppoe0", Name: "AAISP"})
	r.correctPolicyRoute(rec, m)

	st := r.Stats()
	if st.PolicyRouteSkippedAlreadyOnWAN != 1 {
		t.Errorf("already_on_wan = %d, want 1", st.PolicyRouteSkippedAlreadyOnWAN)
	}
	if st.PolicyRouteSkippedFIBAgreed != 0 {
		t.Errorf("fib_agreed = %d, want 0", st.PolicyRouteSkippedFIBAgreed)
	}
}

func TestPolicyRouteCorrectionStillFiresAndSkipsNothing(t *testing.T) {
	// The control: a genuine correction must move ONLY the corrected counter, or the
	// four new buckets would be double-counting the population they partition.
	r := skipRepairer(inRow("10.0.0.6", 36180, "203.0.113.9", 8007, "ixl1"))
	m := skipTopology()
	rec := skipRecord("10.0.0.6", 36180, "203.0.113.9", 8007, Iface{Device: "pppoe0", Name: "AAISP"})
	r.correctPolicyRoute(rec, m)

	st := r.Stats()
	if st.PolicyRouteCorrected != 1 {
		t.Fatalf("corrected = %d, want 1", st.PolicyRouteCorrected)
	}
	if rec.Out.Device != "ixl1" || rec.Out.Name != "VIRGIN" {
		t.Errorf("Out = %+v, want the VIRGIN interface", rec.Out)
	}
	if n := st.PolicyRouteSkippedNotWANEgress + st.PolicyRouteSkippedPostNAT +
		st.PolicyRouteSkippedFIBAgreed + st.PolicyRouteSkippedAlreadyOnWAN; n != 0 {
		t.Errorf("skip counters total = %d, want 0 on a corrected record", n)
	}
}

func TestPolicyRouteRefusalStillCountsAsAMiss(t *testing.T) {
	// No state at all: the genuine miss window, and it must NOT be reclassified into
	// one of the new skip buckets.
	r := skipRepairer()
	m := skipTopology()
	rec := skipRecord("10.0.0.6", 36180, "203.0.113.9", 8007, Iface{Device: "pppoe0", Name: "AAISP"})
	r.correctPolicyRoute(rec, m)

	st := r.Stats()
	if st.PolicyRouteNoState != 1 {
		t.Errorf("no_state = %d, want 1", st.PolicyRouteNoState)
	}
	if st.PolicyRouteSkippedFIBAgreed != 0 || st.PolicyRouteSkippedAlreadyOnWAN != 0 {
		t.Error("a miss was reclassified as a skip")
	}
}
