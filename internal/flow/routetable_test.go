package flow

import (
	"net/netip"
	"testing"
	"time"
)

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

// The live conversation #603 was diagnosed on, verbatim from the prod state table
// (read-only, 2026-07-31): the direction="in" row IS the pre-NAT 5-tuple and
// already carries the route-to, so no NAT join is needed.
func TestRouteTableResolvesThePolicyRoutedConversation(t *testing.T) {
	rt := BuildRouteTable(RouteTableInput{
		Rows: []StateRow{
			{
				Proto: "tcp", Direction: "in",
				SrcAddr: "10.0.0.6", SrcPort: "52824",
				DstAddr: "203.0.113.203", DstPort: "8007",
				RouteToDevice: "ixl1",
			},
			// The post-NAT half of the same conversation. It must NOT be keyed: its
			// tuple is not one any pre-NAT NetFlow record carries, and on prod the two
			// halves' route-to can legitimately disagree.
			{
				Proto: "tcp", Direction: "out",
				SrcAddr: "198.51.100.148", SrcPort: "24260",
				DstAddr: "203.0.113.203", DstPort: "8007",
				RouteToDevice: "pppoe0",
			},
		},
		Built: time.Unix(1000, 0),
	})

	dev, ok := rt.Egress(6, addr(t, "10.0.0.6"), 52824, addr(t, "203.0.113.203"), 8007)
	if !ok {
		t.Fatalf("pre-NAT tuple not found in the table")
	}
	if dev != "ixl1" {
		t.Fatalf("egress device = %q, want ixl1", dev)
	}

	// The post-NAT tuple is deliberately absent.
	if _, ok := rt.Egress(6, addr(t, "198.51.100.148"), 24260, addr(t, "203.0.113.203"), 8007); ok {
		t.Fatalf("post-NAT tuple was keyed; only direction=\"in\" rows may be")
	}

	if got := rt.Stats().Entries; got != 1 {
		t.Fatalf("Entries = %d, want 1", got)
	}
	if got := rt.Stats().PolicyRouted; got != 1 {
		t.Fatalf("PolicyRouted = %d, want 1", got)
	}
}

// A state that carries no route-to followed the FIB, which is exactly the case
// ng_netflow's OUTPUT_SNMP already gets right. It is still keyed — the difference
// between "the FIB decided" and "no state exists at all" is the difference between
// nothing to do and a genuine miss, and only a table holding both can tell them
// apart.
func TestRouteTableKeepsFIBStatesAsAKnownEmptyAnswer(t *testing.T) {
	rt := BuildRouteTable(RouteTableInput{
		Rows: []StateRow{{
			Proto: "udp", Direction: "in",
			SrcAddr: "10.0.0.5", SrcPort: "53000",
			DstAddr: "192.0.2.53", DstPort: "53",
		}},
	})
	dev, ok := rt.Egress(17, addr(t, "10.0.0.5"), 53000, addr(t, "192.0.2.53"), 53)
	if !ok {
		t.Fatalf("FIB state was not keyed")
	}
	if dev != "" {
		t.Fatalf("egress device = %q, want \"\" (the FIB decided)", dev)
	}
	if got := rt.Stats().PolicyRouted; got != 0 {
		t.Fatalf("PolicyRouted = %d, want 0", got)
	}
}

func TestRouteTableSkipsRowsItCannotKey(t *testing.T) {
	rt := BuildRouteTable(RouteTableInput{
		Rows: []StateRow{
			{Proto: "carp", Direction: "in", SrcAddr: "10.0.0.1", DstAddr: "224.0.0.18"}, // unmodelled proto
			{Proto: "tcp", Direction: "in", SrcAddr: "not-an-address", SrcPort: "1", DstAddr: "192.0.2.53", DstPort: "2"},
			{Proto: "tcp", Direction: "in", SrcAddr: "10.0.0.2", SrcPort: "notaport", DstAddr: "192.0.2.53", DstPort: "2"},
		},
	})
	if got := rt.Stats().Entries; got != 0 {
		t.Fatalf("Entries = %d, want 0", got)
	}
	if got := rt.Stats().Skipped; got != 3 {
		t.Fatalf("Skipped = %d, want 3", got)
	}
}

// ICMP states have no ports; pf reports the ICMP id in src_port and the sequence in
// dst_port, which a NetFlow record does not carry. They are keyed anyway because a
// key that never matches is harmless, and refusing them would need a proto list this
// file has no reason to maintain.
func TestRouteTableIsNilSafe(t *testing.T) {
	var rt *RouteTable
	if _, ok := rt.Egress(6, addr(t, "10.0.0.1"), 1, addr(t, "192.0.2.53"), 2); ok {
		t.Fatalf("nil table answered")
	}
	if got := rt.Stats().Entries; got != 0 {
		t.Fatalf("nil table Entries = %d, want 0", got)
	}
	if got := rt.Age(time.Now()); got != 0 {
		t.Fatalf("nil table Age = %v, want 0", got)
	}
}

// Measured on the live prod table: 3,232 direction="in" rows, zero duplicate
// 5-tuple keys, zero keys mapping to more than one egress. The table therefore
// cannot produce the two-hosts-one-destination ambiguity the destination-match
// design would have had to refuse — but if upstream ever did, the FIRST row must
// win rather than the last, so a later duplicate cannot silently move traffic.
func TestRouteTableRefusesToLetADuplicateKeyMoveTraffic(t *testing.T) {
	rt := BuildRouteTable(RouteTableInput{
		Rows: []StateRow{
			{Proto: "tcp", Direction: "in", SrcAddr: "10.0.0.6", SrcPort: "1", DstAddr: "192.0.2.53", DstPort: "2", RouteToDevice: "ixl1"},
			{Proto: "tcp", Direction: "in", SrcAddr: "10.0.0.6", SrcPort: "1", DstAddr: "192.0.2.53", DstPort: "2", RouteToDevice: "pppoe0"},
		},
	})
	dev, ok := rt.Egress(6, addr(t, "10.0.0.6"), 1, addr(t, "192.0.2.53"), 2)
	if !ok || dev != "ixl1" {
		t.Fatalf("egress = %q ok=%v, want ixl1", dev, ok)
	}
	if got := rt.Stats().Conflicts; got != 1 {
		t.Fatalf("Conflicts = %d, want 1", got)
	}
}

func TestRouteTableUnmapsV4MappedAddresses(t *testing.T) {
	rt := BuildRouteTable(RouteTableInput{
		Rows: []StateRow{{
			Proto: "tcp", Direction: "in",
			SrcAddr: "10.0.0.6", SrcPort: "1", DstAddr: "192.0.2.53", DstPort: "2",
			RouteToDevice: "ixl1",
		}},
	})
	dev, ok := rt.Egress(6, netip.AddrFrom16(addr(t, "10.0.0.6").As16()), 1, addr(t, "192.0.2.53"), 2)
	if !ok || dev != "ixl1" {
		t.Fatalf("v4-mapped lookup: egress = %q ok=%v, want ixl1", dev, ok)
	}
}
