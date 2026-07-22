package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// The anonymiser is committed but its main() needs the raw capture, which is never
// committed and is absent in CI. These tests pin the two pieces that must be correct
// for the fixture to be both safe and useful: the address bijection (stable,
// category-preserving) and the template-aware byte rewriter (rewrites every address
// element, touches nothing else). Datagrams are built by hand — a captured one would
// hide the offsets these tests exist to check.

func be16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func be32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// TestMapAddr_StableAndBijective proves the two properties every correlation in the
// fixture depends on: the same real address always maps to the same anonymised one
// (so a shared address stays shared), and distinct inputs never collide (so two
// different hosts never fuse into one).
func TestMapAddr_StableAndBijective(t *testing.T) {
	a := newAnonymizer()
	inputs := []string{
		"86.31.203.106", "135.181.211.203", "1.1.1.1", "8.8.8.8", // public v4
		"10.0.0.5", "172.16.0.1", "192.168.1.1", // private v4
		"100.64.0.1",                      // CGNAT
		"239.255.255.250",                 // v4 multicast
		"169.254.1.1",                     // v4 link-local
		"2606:4700::1111", "2a00:dd80::1", // public v6
		"fd12:3456::1", // ULA
		"fe80::1",      // v6 link-local
		"ff02::fb",     // v6 multicast
	}
	seen := map[netip.Addr]string{}
	for _, s := range inputs {
		in := netip.MustParseAddr(s)
		out := a.mapAddr(in)
		if again := a.mapAddr(in); again != out {
			t.Fatalf("mapAddr(%s) not stable: %v then %v", s, out, again)
		}
		if prev, dup := seen[out]; dup {
			t.Fatalf("mapAddr collision: %s and %s both -> %v", prev, s, out)
		}
		seen[out] = s
	}
}

// TestMapAddr_CategoryPreserved is the leak-guard's other half: a public address
// must land in a documentation range, and a non-global address must stay non-global,
// or the direction/scope inference the fixture exercises would change meaning.
func TestMapAddr_CategoryPreserved(t *testing.T) {
	a := newAnonymizer()
	inDoc := func(x netip.Addr) bool {
		for _, p := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
			if netip.MustParsePrefix(p).Contains(x) {
				return true
			}
		}
		return false
	}
	cases := []struct {
		in   string
		want func(netip.Addr) bool
		why  string
	}{
		{"86.31.203.106", func(x netip.Addr) bool { return x.Is4() && inDoc(x) }, "public v4 -> RFC 5737"},
		{"2606:4700::1", func(x netip.Addr) bool { return x.Is6() && inDoc(x) }, "public v6 -> RFC 3849"},
		{"10.9.8.7", func(x netip.Addr) bool { return x.IsPrivate() }, "RFC1918 stays private"},
		{"172.20.1.1", func(x netip.Addr) bool { return x.IsPrivate() }, "RFC1918 stays private"},
		{"192.168.9.9", func(x netip.Addr) bool { return x.IsPrivate() }, "RFC1918 stays private"},
		{"fd00:1::9", func(x netip.Addr) bool { return x.IsPrivate() }, "ULA stays private"},
		{"239.1.2.3", func(x netip.Addr) bool { return x.IsMulticast() }, "v4 multicast stays multicast"},
		{"ff05::1", func(x netip.Addr) bool { return x.IsMulticast() }, "v6 multicast stays multicast"},
		{"169.254.7.7", func(x netip.Addr) bool { return x.IsLinkLocalUnicast() }, "v4 link-local stays link-local"},
		{"fe80::abcd", func(x netip.Addr) bool { return x.IsLinkLocalUnicast() }, "v6 link-local stays link-local"},
		{"100.64.5.5", func(x netip.Addr) bool { return isCGNAT(x) }, "CGNAT stays CGNAT"},
		{"127.0.0.1", func(x netip.Addr) bool { return x.IsLoopback() }, "loopback kept"},
	}
	for _, c := range cases {
		got := a.mapAddr(netip.MustParseAddr(c.in))
		if !c.want(got) {
			t.Errorf("%s: mapAddr(%s) = %v, violates %q", c.why, c.in, got, c.why)
		}
		// A public input must NEVER survive as itself.
		if in := netip.MustParseAddr(c.in); (in.Is4() || in.Is6()) && got == in && in.IsGlobalUnicast() && !in.IsPrivate() {
			t.Errorf("%s: public address %s survived unchanged", c.why, c.in)
		}
	}
}

func TestPins_Honored(t *testing.T) {
	a := newAnonymizer()
	if got := a.mapAddr(netip.MustParseAddr("86.31.203.106")); got.String() != "198.51.100.6" {
		t.Fatalf("WAN2 pin: got %v, want 198.51.100.6", got)
	}
	if got := a.mapAddr(netip.MustParseAddr("135.181.211.203")); got.String() != "203.0.113.203" {
		t.Fatalf("dst pin: got %v, want 203.0.113.203", got)
	}
}

// v9 datagram builders (same wire shape as the box's template 256).
func templateFlowset(id uint16, fields [][2]uint16) []byte {
	body := cat(be16(id), be16(uint16(len(fields))))
	for _, f := range fields {
		body = cat(body, be16(f[0]), be16(f[1]))
	}
	return cat(be16(0), be16(uint16(len(body)+4)), body)
}

func dataFlowset(id uint16, recs ...[]byte) []byte {
	body := cat(recs...)
	return cat(be16(id), be16(uint16(len(body)+4)), body)
}

func v9(unixSecs uint32, flowsets ...[]byte) []byte {
	return cat(be16(9), be16(1), be32(1000), be32(unixSecs), be32(1), be32(0), cat(flowsets...))
}

func addr4(s string) []byte { b := netip.MustParseAddr(s).As4(); return b[:] }
func addr16(s string) []byte {
	b := netip.MustParseAddr(s).As16()
	return b[:]
}

// TestRewriteDatagram_AnonymisesEveryAddressElement builds a datagram with all six
// address element types (v4 src/dst/nexthop and v6 src/dst/nexthop) and asserts each
// is replaced by a documentation address while every non-address byte — ports,
// counts, the sysUpTime-relative switched fields — is preserved.
func TestRewriteDatagram_AnonymisesEveryAddressElement(t *testing.T) {
	a := newAnonymizer()

	// IPv4 template 256: SRC(8,4) DST(12,4) NEXTHOP(15,4) SRCPORT(7,2) DSTPORT(11,2)
	// FIRST(22,4) IN_BYTES(1,4).
	v4Fields := [][2]uint16{{8, 4}, {12, 4}, {15, 4}, {7, 2}, {11, 2}, {22, 4}, {1, 4}}
	v4rec := cat(addr4("86.31.203.106"), addr4("135.181.211.203"), addr4("192.168.1.1"),
		be16(443), be16(54321), be32(0xDEADBEEF), be32(15000))

	// IPv6 template 259: SRC(27,16) DST(28,16) NEXTHOP(62,16) IN_BYTES(1,4).
	v6Fields := [][2]uint16{{27, 16}, {28, 16}, {62, 16}, {1, 4}}
	v6rec := cat(addr16("2606:4700::1"), addr16("2a00:dd80::1"), addr16("fe80::1"), be32(200))

	pkt := v9(1700000000,
		templateFlowset(256, v4Fields),
		templateFlowset(259, v6Fields),
		dataFlowset(256, v4rec),
		dataFlowset(259, v6rec),
	)
	orig := make([]byte, len(pkt))
	copy(orig, pkt)

	const shift = int64(-100000000)
	if err := rewriteDatagram(a, pkt, shift); err != nil {
		t.Fatalf("rewriteDatagram: %v", err)
	}

	// Locate the two data flowsets in the rewritten packet by re-walking it.
	fs := map[uint16][]byte{}
	off := 20
	for off+4 <= len(pkt) {
		id := binary.BigEndian.Uint16(pkt[off:])
		l := int(binary.BigEndian.Uint16(pkt[off+2:]))
		if id >= 256 {
			fs[id] = pkt[off+4 : off+l]
		}
		off += l
	}

	// v4 record: three addresses rewritten, ports/first/bytes untouched.
	r4 := fs[256]
	src4, _ := netip.AddrFromSlice(r4[0:4])
	dst4, _ := netip.AddrFromSlice(r4[4:8])
	nh4, _ := netip.AddrFromSlice(r4[8:12])
	if src4.String() != "198.51.100.6" {
		t.Errorf("v4 src = %v, want pinned 198.51.100.6", src4)
	}
	if dst4.String() != "203.0.113.203" {
		t.Errorf("v4 dst = %v, want pinned 203.0.113.203", dst4)
	}
	if !nh4.IsPrivate() {
		t.Errorf("v4 nexthop = %v, want a private address (192.168.1.1 remapped)", nh4)
	}
	if p := binary.BigEndian.Uint16(r4[12:14]); p != 443 {
		t.Errorf("v4 srcport corrupted: %d", p)
	}
	if p := binary.BigEndian.Uint16(r4[14:16]); p != 54321 {
		t.Errorf("v4 dstport corrupted: %d", p)
	}
	if f := binary.BigEndian.Uint32(r4[16:20]); f != 0xDEADBEEF {
		t.Errorf("FIRST_SWITCHED altered: %#x, want it untouched (it is sysUpTime-relative, not absolute)", f)
	}
	if b := binary.BigEndian.Uint32(r4[20:24]); b != 15000 {
		t.Errorf("IN_BYTES altered: %d, want 15000", b)
	}

	// v6 record: three addresses rewritten to documentation/non-global; count intact.
	r6 := fs[259]
	src6, _ := netip.AddrFromSlice(r6[0:16])
	dst6, _ := netip.AddrFromSlice(r6[16:32])
	nh6, _ := netip.AddrFromSlice(r6[32:48])
	docV6 := netip.MustParsePrefix("2001:db8::/32")
	if !docV6.Contains(src6) || !docV6.Contains(dst6) {
		t.Errorf("v6 src/dst = %v/%v, want inside 2001:db8::/32", src6, dst6)
	}
	if !nh6.IsLinkLocalUnicast() {
		t.Errorf("v6 nexthop = %v, want a link-local address (fe80::1 remapped in-category)", nh6)
	}
	if b := binary.BigEndian.Uint32(r6[48:52]); b != 200 {
		t.Errorf("v6 IN_BYTES altered: %d, want 200", b)
	}

	// header export time shifted by exactly the constant; the rest of the header
	// (sysUpTime included) unchanged.
	gotSecs := binary.BigEndian.Uint32(pkt[8:12])
	if int64(gotSecs) != 1700000000+shift {
		t.Errorf("unix_secs = %d, want %d", gotSecs, 1700000000+shift)
	}
	if !bytesEqual(pkt[4:8], orig[4:8]) {
		t.Errorf("sysUpTime altered; only the absolute export time may shift")
	}
	// template flowset bytes are the contract and must be byte-identical.
	tOff := 20
	tLen := int(binary.BigEndian.Uint16(orig[22:]))
	if !bytesEqual(pkt[tOff:tOff+tLen], orig[tOff:tOff+tLen]) {
		t.Errorf("template flowset bytes changed; shapes must be preserved exactly")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
