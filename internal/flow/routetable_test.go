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

// --- the rolling union (#620) -------------------------------------------------

// shortFlow is the population #620 measured on prod: a sub-90-second TCP
// connection from a LAN host, policy-routed onto a non-default WAN.
func shortFlow(port string, device string) StateRow {
	return StateRow{
		Proto: "tcp", Direction: "in",
		SrcAddr: "10.0.0.6", SrcPort: port,
		DstAddr: "203.0.113.203", DstPort: "8007",
		RouteToDevice: device,
	}
}

// The case the union exists for: a state seen at one poll, gone by the next, whose
// NetFlow record has not arrived yet. Before #620 the answer went from correct to
// refused the instant the table was rebuilt.
func TestRouteTableCarriesExpiredStatesForwardWithinRetention(t *testing.T) {
	first := BuildRouteTable(RouteTableInput{
		Rows:  []StateRow{shortFlow("52824", "ixl1")},
		Built: time.Unix(1000, 0),
	})

	// One minute later the conversation has ended and pf has dropped the state.
	second := BuildRouteTable(RouteTableInput{
		Rows:     nil,
		Built:    time.Unix(1060, 0),
		Previous: first,
		Retain:   3 * time.Minute,
	})

	dev, ok := second.Egress(6, addr(t, "10.0.0.6"), 52824, addr(t, "203.0.113.203"), 8007)
	if !ok {
		t.Fatalf("expired state was not carried forward; the record would be refused")
	}
	if dev != "ixl1" {
		t.Fatalf("carried egress device = %q, want ixl1", dev)
	}
	if got := second.Stats().Carried; got != 1 {
		t.Fatalf("Carried = %d, want 1", got)
	}
	if got := second.Stats().Entries; got != 1 {
		t.Fatalf("Entries = %d, want 1 (a carried entry is answerable, so it counts)", got)
	}
	if got := second.Stats().PolicyRouted; got != 1 {
		t.Fatalf("PolicyRouted = %d, want 1; a carried route-to still moves a record", got)
	}
}

// Retention is a bound on being WRONG, so it has to actually bind. Past it the
// table must go back to refusing rather than keep asserting a dead route.
func TestRouteTableDropsCarriedStatesPastRetention(t *testing.T) {
	first := BuildRouteTable(RouteTableInput{
		Rows:  []StateRow{shortFlow("52824", "ixl1")},
		Built: time.Unix(1000, 0),
	})
	later := BuildRouteTable(RouteTableInput{
		Built:    time.Unix(1000, 0).Add(3*time.Minute + time.Second),
		Previous: first,
		Retain:   3 * time.Minute,
	})

	if _, ok := later.Egress(6, addr(t, "10.0.0.6"), 52824, addr(t, "203.0.113.203"), 8007); ok {
		t.Fatalf("a state past the retention window is still answerable")
	}
	if got := later.Stats().Carried; got != 0 {
		t.Fatalf("Carried = %d, want 0", got)
	}
}

// Age-out measures the state's own absence, not how many rebuilds have happened
// since. A long-lived state seen in every snapshot must never expire out of the
// union — that would make the union actively worse than no union at all.
func TestRouteTableCarryAgesFromLastSeenNotFirstSeen(t *testing.T) {
	table := BuildRouteTable(RouteTableInput{
		Rows:  []StateRow{shortFlow("52824", "ixl1")},
		Built: time.Unix(1000, 0),
	})
	// Ten rebuilds over ten minutes, the state present in every one. Total elapsed
	// time far exceeds Retain.
	for i := 1; i <= 10; i++ {
		table = BuildRouteTable(RouteTableInput{
			Rows:     []StateRow{shortFlow("52824", "ixl1")},
			Built:    time.Unix(1000, 0).Add(time.Duration(i) * time.Minute),
			Previous: table,
			Retain:   3 * time.Minute,
		})
	}
	if _, ok := table.Egress(6, addr(t, "10.0.0.6"), 52824, addr(t, "203.0.113.203"), 8007); !ok {
		t.Fatalf("a continuously-present state aged out of the union")
	}
	if got := table.Stats().Carried; got != 0 {
		t.Fatalf("Carried = %d, want 0; the state is fresh in every snapshot", got)
	}
}

// The failover hazard, stated as a test: pf re-routes an existing tuple onto a
// different WAN. The fresh snapshot must win outright — a union that let history
// pin the answer would turn a bounded miss into a silent mislabel.
func TestRouteTableFreshRowBeatsCarriedEntry(t *testing.T) {
	first := BuildRouteTable(RouteTableInput{
		Rows:  []StateRow{shortFlow("52824", "ixl1")},
		Built: time.Unix(1000, 0),
	})
	second := BuildRouteTable(RouteTableInput{
		Rows:     []StateRow{shortFlow("52824", "ixl2")},
		Built:    time.Unix(1060, 0),
		Previous: first,
		Retain:   3 * time.Minute,
	})

	dev, ok := second.Egress(6, addr(t, "10.0.0.6"), 52824, addr(t, "203.0.113.203"), 8007)
	if !ok {
		t.Fatalf("tuple missing from the rebuilt table")
	}
	if dev != "ixl2" {
		t.Fatalf("egress device = %q, want ixl2; the fresh snapshot must beat the carried entry", dev)
	}
	if got := second.Stats().Conflicts; got != 0 {
		t.Fatalf("Conflicts = %d, want 0; a tuple in both snapshots is a live state, not an ambiguous key", got)
	}
	if got := second.Stats().Carried; got != 0 {
		t.Fatalf("Carried = %d, want 0", got)
	}
	if got := second.Stats().PolicyRouted; got != 1 {
		t.Fatalf("PolicyRouted = %d, want 1; the carried copy must not be double-counted", got)
	}
}

// Retain=0 is the pre-#620 behaviour, and it has to stay reachable: it is what
// every test written before the union asserts, and it is the fallback if carrying
// ever needs disabling.
func TestRouteTableZeroRetentionCarriesNothing(t *testing.T) {
	first := BuildRouteTable(RouteTableInput{
		Rows:  []StateRow{shortFlow("52824", "ixl1")},
		Built: time.Unix(1000, 0),
	})
	second := BuildRouteTable(RouteTableInput{
		Built:    time.Unix(1001, 0),
		Previous: first,
		Retain:   0,
	})

	if _, ok := second.Egress(6, addr(t, "10.0.0.6"), 52824, addr(t, "203.0.113.203"), 8007); ok {
		t.Fatalf("Retain=0 still carried an entry forward")
	}
	if got := second.Stats().Entries; got != 0 {
		t.Fatalf("Entries = %d, want 0", got)
	}
}

// A carried FIB state (route-to empty) must stay distinguishable from "no state at
// all". Collapsing the two is the one thing Egress's contract forbids, and the
// union is a new way to get it wrong.
func TestRouteTableCarriesFIBStatesAsAKnownEmptyAnswer(t *testing.T) {
	first := BuildRouteTable(RouteTableInput{
		Rows:  []StateRow{shortFlow("52824", "")},
		Built: time.Unix(1000, 0),
	})
	second := BuildRouteTable(RouteTableInput{
		Built:    time.Unix(1060, 0),
		Previous: first,
		Retain:   3 * time.Minute,
	})

	dev, ok := second.Egress(6, addr(t, "10.0.0.6"), 52824, addr(t, "203.0.113.203"), 8007)
	if !ok {
		t.Fatalf("a carried FIB state must still answer; ok=false means a genuine miss")
	}
	if dev != "" {
		t.Fatalf("carried device = %q, want empty (the FIB decided)", dev)
	}
	if got := second.Stats().PolicyRouted; got != 0 {
		t.Fatalf("PolicyRouted = %d, want 0; a route-to-less state cannot move a record", got)
	}
}
