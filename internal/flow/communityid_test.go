package flow

import (
	"net/netip"
	"testing"
)

// The expected values are the Corelight community-id v1 PUBLISHED reference
// vectors (seed 0), so this validates against the spec rather than against our own
// output. If one fails, the implementation is wrong — do NOT adjust the expectation
// to match, because a key no other tool agrees with defeats the scheme's only
// purpose.
func TestCommunityID_PublishedReferenceVectors(t *testing.T) {
	cases := []struct {
		name         string
		proto        uint8
		src, dst     string
		sport, dport uint16
		want         string
	}{
		{"tcp", 6, "128.232.110.120", "66.35.250.204", 34855, 80, "1:LQU9qZlK+B5F3KDmev6m5PMibrg="},
		{"udp", 17, "192.168.1.52", "8.8.8.8", 54585, 53, "1:d/FP5EW3wiY1vCndhwleRRKHowQ="},
		{"icmp", 1, "192.168.0.89", "192.168.0.1", 8, 0, "1:X0snYXpgwiv9TZtqg64sgzUn6Dk="},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tup := Record{
				Proto:   c.proto,
				SrcAddr: netip.MustParseAddr(c.src), SrcPort: c.sport,
				DstAddr: netip.MustParseAddr(c.dst), DstPort: c.dport,
			}.CanonicalTuple()
			if got := CommunityID(tup, 0); got != c.want {
				t.Fatalf("CommunityID = %q, want %q", got, c.want)
			}
		})
	}
}

// The whole point of the key: both directions of one conversation hash the same.
func TestCommunityID_DirectionIndependent(t *testing.T) {
	fwd := Record{Proto: 6, SrcAddr: netip.MustParseAddr("192.0.2.5"), SrcPort: 54321,
		DstAddr: netip.MustParseAddr("198.51.100.1"), DstPort: 443}.CanonicalTuple()
	rev := Record{Proto: 6, SrcAddr: netip.MustParseAddr("198.51.100.1"), SrcPort: 443,
		DstAddr: netip.MustParseAddr("192.0.2.5"), DstPort: 54321}.CanonicalTuple()
	if CommunityID(fwd, 0) != CommunityID(rev, 0) {
		t.Fatal("community_id must be identical in both directions")
	}
}

// A v4-mapped IPv6 address must hash as its plain v4 form: taking the 16-byte
// branch for ::ffff:a.b.c.d would give the same host two different ids and split
// the phase-3 join.
func TestCommunityID_V4MappedHashesAsV4(t *testing.T) {
	plain := Record{Proto: 6, SrcAddr: netip.MustParseAddr("128.232.110.120"), SrcPort: 34855,
		DstAddr: netip.MustParseAddr("66.35.250.204"), DstPort: 80}.CanonicalTuple()
	mapped := Record{Proto: 6, SrcAddr: netip.MustParseAddr("::ffff:128.232.110.120"), SrcPort: 34855,
		DstAddr: netip.MustParseAddr("::ffff:66.35.250.204"), DstPort: 80}.CanonicalTuple()
	if got, want := CommunityID(mapped, 0), CommunityID(plain, 0); got != want {
		t.Fatalf("v4-mapped id %q != plain v4 id %q", got, want)
	}
	// And it is still the published vector, not merely self-consistent.
	if want := "1:LQU9qZlK+B5F3KDmev6m5PMibrg="; CommunityID(mapped, 0) != want {
		t.Fatalf("v4-mapped id = %q, want the published vector %q", CommunityID(mapped, 0), want)
	}
}

// IPv6 endpoints take the 16-byte branch and must still be direction-independent
// and distinct from an unrelated conversation.
func TestCommunityID_IPv6(t *testing.T) {
	fwd := Record{Proto: 6, SrcAddr: netip.MustParseAddr("2001:db8::1"), SrcPort: 40000,
		DstAddr: netip.MustParseAddr("2001:db8::2"), DstPort: 443}.CanonicalTuple()
	rev := Record{Proto: 6, SrcAddr: netip.MustParseAddr("2001:db8::2"), SrcPort: 443,
		DstAddr: netip.MustParseAddr("2001:db8::1"), DstPort: 40000}.CanonicalTuple()
	other := Record{Proto: 6, SrcAddr: netip.MustParseAddr("2001:db8::1"), SrcPort: 40001,
		DstAddr: netip.MustParseAddr("2001:db8::2"), DstPort: 443}.CanonicalTuple()
	if CommunityID(fwd, 0) != CommunityID(rev, 0) {
		t.Fatal("IPv6 community_id must be direction-independent")
	}
	if CommunityID(fwd, 0) == CommunityID(other, 0) {
		t.Fatal("a different source port must yield a different id")
	}
}

// The seed is part of the hash, so two deployments using different seeds do not
// collide. Nothing in this exporter sets a non-zero seed today, but the parameter
// is part of the spec and must actually be honoured rather than ignored.
func TestCommunityID_SeedChangesTheHash(t *testing.T) {
	tup := Record{Proto: 6, SrcAddr: netip.MustParseAddr("192.0.2.5"), SrcPort: 1,
		DstAddr: netip.MustParseAddr("198.51.100.1"), DstPort: 443}.CanonicalTuple()
	if CommunityID(tup, 0) == CommunityID(tup, 1) {
		t.Fatal("the seed must participate in the hash")
	}
}
