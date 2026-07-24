package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// This file is the testable core of the anonymiser: the address bijection and the
// template-aware byte rewriter. It has no dependency on the raw capture, so its
// behaviour is pinned by unit tests that build datagrams in-memory — the capture
// itself is never committed and is unavailable in CI.
//
// The contract, stated once:
//
//   - Addresses are rewritten IN THE RAW BYTES, category-preserving and bijectively.
//     A public address becomes a documentation address (RFC 5737 for v4, RFC 3849
//     2001:db8::/32 for v6); a private/local address stays in an equivalent
//     non-global range so netip's IsPrivate/IsMulticast/IsLinkLocal predicates — and
//     therefore every direction and scope inference downstream — still hold. Two
//     flows that shared a real address still share the ONE anonymised address, so
//     every correlation and de-dup case in the fixture survives.
//   - The v9 header's absolute unix_secs is shifted by one constant. FIRST_SWITCHED
//     and LAST_SWITCHED are NOT touched: they are sysUpTime-relative milliseconds, so
//     leaving them byte-identical preserves both the relative flow duration and the
//     cross-datagram VLAN-duplicate key (the absolute First/Last that the decoder
//     derives shift uniformly by the same constant, so a duplicate pair still
//     collides). Byte/packet counts, template shapes, field widths, ifIndex values
//     and flowset framing are preserved byte-for-byte.

// address element types this rewriter locates and anonymises. All others are stepped
// over by their template-declared width, exactly as the decoder does.
const (
	elemIPv4Src     = 8
	elemIPv4Dst     = 12
	elemIPv4NextHop = 15
	elemIPv6Src     = 27
	elemIPv6Dst     = 28
	elemIPv6NextHop = 62
)

// tfield is one template element: its type and declared width.
type tfield struct {
	typ, length uint16
}

// tmpl is a learned template: its ordered elements and precomputed record width.
type tmpl struct {
	fields []tfield
	recLen int
}

// anonymizer holds the bijective address map and the per-category allocators. It is
// stateful: the SAME instance must rewrite every datagram of one fixture so a shared
// address maps to one anonymised value across the whole file.
type anonymizer struct {
	tmpl map[uint16]*tmpl
	m    map[netip.Addr]netip.Addr
	used map[netip.Addr]bool

	// per-category monotone counters. A category's outputs never collide (disjoint
	// target ranges) and are injective (a counter is used at most once), so the whole
	// map is a bijection.
	nV4Pub, nV4Priv, nV4CGN, nV4LL, nV4Mcast uint32
	nV6Pub, nV6ULA, nV6LL, nV6Mcast          uint32
}

// pinnedMap fixes the anonymised value of the addresses the fixture's assertions
// depend on, so the replay test can name them as documented constants rather than
// chasing an allocation order. Everything else is allocated sequentially.
//
//   - 86.31.203.106 is the box's WAN2 NAT address (on ixl1 as of 2026-07-24; it was
//     igb0 when this capture was taken, before the router moved to the SFP cage —
//     the ADDRESS is what the fixture pins, not the device); the egress-correction case
//     turns on the replay test's IfMap owning it, so it is pinned to a stable
//     documentation address.
//   - 135.181.211.203 is the destination of that mislabelled WAN2 flow; pinned only
//     for a readable fixture.
func pinnedMap() map[netip.Addr]netip.Addr {
	return map[netip.Addr]netip.Addr{
		netip.MustParseAddr("86.31.203.106"):   netip.MustParseAddr("198.51.100.6"),
		netip.MustParseAddr("135.181.211.203"): netip.MustParseAddr("203.0.113.203"),
	}
}

func newAnonymizer() *anonymizer {
	a := &anonymizer{
		tmpl: make(map[uint16]*tmpl),
		m:    make(map[netip.Addr]netip.Addr),
		used: make(map[netip.Addr]bool),
	}
	for in, out := range pinnedMap() {
		a.m[in.Unmap()] = out
		a.used[out] = true
	}
	return a
}

// category classifies an address by the property that must be preserved. The
// classes that carry no real-network identity — loopback and the unspecified
// address — are kept verbatim; every other class is remapped within an equivalent
// range.
type category int

const (
	catKeep category = iota
	catV4Pub
	catV4Priv
	catV4CGN
	catV4LL
	catV4Mcast
	catV6Pub
	catV6ULA
	catV6LL
	catV6Mcast
)

func isCGNAT(a netip.Addr) bool {
	if !a.Is4() {
		return false
	}
	b := a.As4()
	return b[0] == 100 && b[1] >= 64 && b[1] <= 127
}

func classify(a netip.Addr) category {
	a = a.Unmap()
	if a.IsUnspecified() || a.IsLoopback() {
		return catKeep
	}
	if a.Is4() {
		switch {
		case a.IsLinkLocalUnicast():
			return catV4LL
		case a.IsMulticast():
			return catV4Mcast
		case isCGNAT(a):
			return catV4CGN
		case a.IsPrivate():
			return catV4Priv
		default:
			return catV4Pub
		}
	}
	switch {
	case a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast():
		return catV6LL
	case a.IsMulticast():
		return catV6Mcast
	case a.IsPrivate(): // ULA fc00::/7
		return catV6ULA
	default:
		return catV6Pub
	}
}

// v4 documentation blocks (RFC 5737), allocated in this order.
var docV4Blocks = [][4]byte{
	{198, 51, 100, 0},
	{203, 0, 113, 0},
	{192, 0, 2, 0},
}

func v4At(base [4]byte, host uint32) netip.Addr {
	v := binary.BigEndian.Uint32(base[:]) + host
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// allocV4 draws the next host in a single /24-agnostic block, skipping any address
// already reserved (a pin target).
func (a *anonymizer) allocV4(base [4]byte, n *uint32) netip.Addr {
	for {
		*n++
		out := v4At(base, *n)
		if !a.used[out] {
			a.used[out] = true
			return out
		}
	}
}

// allocV4Pub walks the three RFC 5737 blocks, host .1..254 in each, skipping pins.
func (a *anonymizer) allocV4Pub() netip.Addr {
	for {
		a.nV4Pub++
		block := int((a.nV4Pub - 1) / 254)
		host := (a.nV4Pub-1)%254 + 1
		if block >= len(docV4Blocks) {
			panic("flowanon: exhausted RFC 5737 documentation space")
		}
		out := v4At(docV4Blocks[block], host)
		if !a.used[out] {
			a.used[out] = true
			return out
		}
	}
}

func v6With(prefix string, n uint32) netip.Addr {
	base := netip.MustParseAddr(prefix).As16()
	binary.BigEndian.PutUint32(base[12:], binary.BigEndian.Uint32(base[12:])+n)
	return netip.AddrFrom16(base)
}

func (a *anonymizer) allocV6(prefix string, n *uint32) netip.Addr {
	for {
		*n++
		out := v6With(prefix, *n)
		if !a.used[out] {
			a.used[out] = true
			return out
		}
	}
}

// mapAddr returns the stable anonymised form of in, preserving its category and
// family. Repeated calls with the same input return the same output.
func (a *anonymizer) mapAddr(in netip.Addr) netip.Addr {
	if !in.IsValid() {
		return in
	}
	in = in.Unmap()
	if v, ok := a.m[in]; ok {
		return v
	}
	var out netip.Addr
	switch classify(in) {
	case catKeep:
		out = in
	case catV4Pub:
		out = a.allocV4Pub()
	case catV4Priv:
		out = a.allocV4([4]byte{10, 0, 0, 0}, &a.nV4Priv)
	case catV4CGN:
		out = a.allocV4([4]byte{100, 64, 0, 0}, &a.nV4CGN)
	case catV4LL:
		out = a.allocV4([4]byte{169, 254, 0, 0}, &a.nV4LL)
	case catV4Mcast:
		out = a.allocV4([4]byte{239, 192, 0, 0}, &a.nV4Mcast)
	case catV6Pub:
		out = a.allocV6("2001:db8::", &a.nV6Pub)
	case catV6ULA:
		out = a.allocV6("fd00::", &a.nV6ULA)
	case catV6LL:
		out = a.allocV6("fe80::", &a.nV6LL)
	case catV6Mcast:
		out = a.allocV6("ff08::", &a.nV6Mcast)
	default:
		out = in
	}
	a.m[in] = out
	return out
}

// learnTemplates records every definition in a template flowset body, so a later
// data flowset naming one can be walked field by field.
func (a *anonymizer) learnTemplates(body []byte) {
	for len(body) >= 4 {
		id := binary.BigEndian.Uint16(body)
		count := int(binary.BigEndian.Uint16(body[2:]))
		body = body[4:]
		if len(body) < count*4 {
			return
		}
		fields := make([]tfield, count)
		recLen := 0
		for i := range fields {
			fields[i] = tfield{
				typ:    binary.BigEndian.Uint16(body[i*4:]),
				length: binary.BigEndian.Uint16(body[i*4+2:]),
			}
			recLen += int(fields[i].length)
		}
		body = body[count*4:]
		a.tmpl[id] = &tmpl{fields: fields, recLen: recLen}
	}
}

// rewriteData anonymises every address element of every record in one data flowset,
// in place.
func (a *anonymizer) rewriteData(id uint16, body []byte) {
	t := a.tmpl[id]
	if t == nil || t.recLen <= 0 {
		return
	}
	for len(body) >= t.recLen {
		rec := body[:t.recLen]
		off := 0
		for _, f := range t.fields {
			switch f.typ {
			case elemIPv4Src, elemIPv4Dst, elemIPv4NextHop:
				if f.length == 4 {
					if old, ok := netip.AddrFromSlice(rec[off : off+4]); ok {
						b := a.mapAddr(old).As4()
						copy(rec[off:off+4], b[:])
					}
				}
			case elemIPv6Src, elemIPv6Dst, elemIPv6NextHop:
				if f.length == 16 {
					if old, ok := netip.AddrFromSlice(rec[off : off+16]); ok {
						b := a.mapAddr(old.Unmap()).As16()
						copy(rec[off:off+16], b[:])
					}
				}
			}
			off += int(f.length)
		}
		body = body[t.recLen:]
	}
}

// rewriteDatagram anonymises one v9 datagram in place: it shifts the header's
// absolute export time by secShift and rewrites every address in every data
// flowset. Template and options flowsets are walked (to learn shapes) but their
// bytes are untouched — a template carries no address, and its shape is the contract
// the fixture exists to pin.
func rewriteDatagram(a *anonymizer, payload []byte, secShift int64) error {
	if len(payload) < 20 {
		return fmt.Errorf("flowanon: datagram shorter than a v9 header (%d bytes)", len(payload))
	}
	if v := binary.BigEndian.Uint16(payload); v != 9 {
		return fmt.Errorf("flowanon: not a v9 datagram (version %d)", v)
	}
	secs := int64(binary.BigEndian.Uint32(payload[8:12]))
	if secs != 0 {
		binary.BigEndian.PutUint32(payload[8:12], uint32(secs+secShift))
	}

	off := 20
	for off+4 <= len(payload) {
		id := binary.BigEndian.Uint16(payload[off:])
		length := int(binary.BigEndian.Uint16(payload[off+2:]))
		if length < 4 || off+length > len(payload) {
			return fmt.Errorf("flowanon: malformed flowset length %d at offset %d", length, off)
		}
		body := payload[off+4 : off+length]
		switch {
		case id == 0:
			a.learnTemplates(body)
		case id == 1:
			// options template: skipped, no addresses.
		case id >= 256:
			a.rewriteData(id, body)
		}
		off += length
	}
	return nil
}
