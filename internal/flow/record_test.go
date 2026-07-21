package flow

import (
	"net/netip"
	"testing"
)

func TestCounters_PresentDistinguishesZeroFromAbsent(t *testing.T) {
	var absent Counters
	if absent.Present {
		t.Fatal("zero-value Counters must report Present=false")
	}
	zero := Counters{Present: true}
	if !zero.Present || zero.Bytes() != 0 {
		t.Fatal("an explicitly-zero counter must be Present with zero bytes")
	}
}

func TestCounters_BytesAndPacketsSumBothDirections(t *testing.T) {
	c := Counters{TxBytes: 1000, RxBytes: 50000, TxPackets: 10, RxPackets: 40, Present: true}
	if got := c.Bytes(); got != 51000 {
		t.Fatalf("Bytes() = %d, want 51000", got)
	}
	if got := c.Packets(); got != 50 {
		t.Fatalf("Packets() = %d, want 50", got)
	}
}

// CanonicalTuple must be direction-independent: the same conversation observed from
// either end yields the same tuple, which is what makes it usable as a join key
// across two sources that disagree about which end is "source".
func TestRecord_CanonicalTupleIsDirectionIndependent(t *testing.T) {
	a := Record{Proto: 6,
		SrcAddr: netip.MustParseAddr("192.0.2.5"), SrcPort: 54321,
		DstAddr: netip.MustParseAddr("198.51.100.1"), DstPort: 443}
	b := Record{Proto: 6,
		SrcAddr: netip.MustParseAddr("198.51.100.1"), SrcPort: 443,
		DstAddr: netip.MustParseAddr("192.0.2.5"), DstPort: 54321}
	if a.CanonicalTuple() != b.CanonicalTuple() {
		t.Fatalf("tuple not direction-independent:\n a=%v\n b=%v", a.CanonicalTuple(), b.CanonicalTuple())
	}
}

func TestRecord_CanonicalTupleSeparatesDifferentConversations(t *testing.T) {
	a := Record{Proto: 6, SrcAddr: netip.MustParseAddr("192.0.2.5"), SrcPort: 1,
		DstAddr: netip.MustParseAddr("198.51.100.1"), DstPort: 443}
	b := Record{Proto: 17, SrcAddr: netip.MustParseAddr("192.0.2.5"), SrcPort: 1,
		DstAddr: netip.MustParseAddr("198.51.100.1"), DstPort: 443}
	if a.CanonicalTuple() == b.CanonicalTuple() {
		t.Fatal("differing protocol must yield a different tuple")
	}
}

// A v4-mapped IPv6 address (::ffff:192.0.2.5) and its plain v4 form are the SAME
// host, but netip compares them as different Addrs. Without Unmap the two sources
// would canonicalise one conversation two ways and the phase-3 correlator would
// silently miss every join involving one. enrich.Snapshot.Scope already Unmaps for
// exactly this reason (snapshot.go:97).
func TestRecord_CanonicalTupleUnmapsV4MappedV6(t *testing.T) {
	plain := Record{Proto: 6, SrcAddr: netip.MustParseAddr("192.0.2.5"), SrcPort: 1,
		DstAddr: netip.MustParseAddr("198.51.100.1"), DstPort: 443}
	mapped := Record{Proto: 6, SrcAddr: netip.MustParseAddr("::ffff:192.0.2.5"), SrcPort: 1,
		DstAddr: netip.MustParseAddr("::ffff:198.51.100.1"), DstPort: 443}
	if plain.CanonicalTuple() != mapped.CanonicalTuple() {
		t.Fatalf("v4-mapped IPv6 must canonicalise identically to plain v4:\n plain=%v\n mapped=%v",
			plain.CanonicalTuple(), mapped.CanonicalTuple())
	}
}

// Iface.Label prefers the friendly name but never invents one: an unmapped
// interface yields the raw device, and an unknown one yields empty rather than a
// guess. A wrong interface label is worse than a missing one.
func TestIface_LabelPrefersNameThenDeviceThenNothing(t *testing.T) {
	if got := (Iface{Device: "ixl0_vlan50", Name: "IOT"}).Label(); got != "IOT" {
		t.Fatalf("Label() = %q, want IOT", got)
	}
	if got := (Iface{Device: "ixl0_vlan50"}).Label(); got != "ixl0_vlan50" {
		t.Fatalf("Label() = %q, want the raw device", got)
	}
	if got := (Iface{}).Label(); got != "" {
		t.Fatalf("Label() = %q, want empty rather than a guess", got)
	}
}

// The enumerations are metric label values, so their spellings are part of the
// exported contract and cannot drift silently. VerdictUnknown renders empty (not
// the word "unknown") to match how parse.go:95-107 leaves AttrAction unset when
// the document stated no disposition.
func TestEnumerationSpellings(t *testing.T) {
	for _, c := range []struct {
		got, want string
	}{
		{SourceUnknown.String(), "unknown"},
		{SourceNetflow.String(), "netflow"},
		{SourceZenarmor.String(), "zenarmor"},
		{SourceMerged.String(), "merged"},
		{DirectionUnknown.String(), "unknown"},
		{DirectionInbound.String(), "inbound"},
		{DirectionOutbound.String(), "outbound"},
		{DirectionInternal.String(), "internal"},
		{VerdictUnknown.String(), ""},
		{VerdictPass.String(), "pass"},
		{VerdictBlock.String(), "block"},
	} {
		if c.got != c.want {
			t.Errorf("String() = %q, want %q", c.got, c.want)
		}
	}
}
