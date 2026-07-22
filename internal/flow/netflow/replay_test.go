package netflow

// These tests replay the committed golden fixture testdata/replay-v9.bin, which is a
// curated, anonymised subset of a REAL production capture (811,234 records, #346)
// produced by cmd/flowanon. Unlike decode_test.go — which builds every datagram by
// hand to pin exact offsets — these prove the decoder against real box bytes: the
// two live template shapes (256 IPv4 / 259 IPv6), the cold-start data-before-template
// path, and, as a hard safety gate, that the anonymiser left no real address behind.
//
// The raw capture is never committed; the fixture is. See cmd/flowanon for how the
// seven datagrams were selected and anonymised.

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"time"
)

const replayFixture = "testdata/replay-v9.bin"

// replayFrame is one datagram from the capture's frame wrapper:
// [unix-nanos u64][addr-len u8][addr][payload-len u32][payload].
type replayFrame struct {
	recv     time.Time
	exporter netip.Addr
	payload  []byte
}

func readReplayFrames(t *testing.T) []replayFrame {
	t.Helper()
	raw, err := os.ReadFile(replayFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var frames []replayFrame
	off := 0
	for off+13 <= len(raw) {
		nanos := int64(binary.BigEndian.Uint64(raw[off : off+8]))
		alen := int(raw[off+8])
		if off+9+alen+4 > len(raw) {
			t.Fatalf("fixture truncated in frame header at %d", off)
		}
		addr, ok := netip.AddrFromSlice(raw[off+9 : off+9+alen])
		if !ok {
			t.Fatalf("fixture frame at %d has bad address", off)
		}
		plen := int(binary.BigEndian.Uint32(raw[off+9+alen : off+9+alen+4]))
		start := off + 9 + alen + 4
		if start+plen > len(raw) {
			t.Fatalf("fixture truncated in frame payload at %d", off)
		}
		p := make([]byte, plen)
		copy(p, raw[start:start+plen])
		frames = append(frames, replayFrame{time.Unix(0, nanos), addr.Unmap(), p})
		off = start + plen
	}
	if len(frames) == 0 {
		t.Fatal("fixture has no frames")
	}
	return frames
}

// decodeReplay runs the fixture through one decoder in file order and returns the
// records and the final stats. File order is load-bearing: the data-only datagram is
// first, so a fresh decoder sees data before its template.
func decodeReplay(t *testing.T) ([]Record, Stats) {
	t.Helper()
	d := New()
	var recs []Record
	for i, f := range readReplayFrames(t) {
		dg, err := d.Decode(f.payload, f.exporter, f.recv)
		if err != nil {
			t.Fatalf("frame %d: Decode() error = %v (the fixture is real box bytes; a decode error is a decoder bug)", i, err)
		}
		recs = append(recs, dg.Records...)
	}
	return recs, d.Stats()
}

// The fixture leads with a data-only datagram, so replaying it through a cold decoder
// exercises the ~2-minute cold-start blackout: data whose template has not arrived is
// COUNTED (NoTemplate), never guessed at and never an error. This is the real path a
// receiver starting mid-cycle takes, captured from the box rather than hand-built.
func TestReplayV9_ColdStartDataBeforeTemplate(t *testing.T) {
	_, s := decodeReplay(t)
	if s.Datagrams != 7 {
		t.Fatalf("Datagrams = %d, want the 7 curated datagrams", s.Datagrams)
	}
	if s.NoTemplate == 0 {
		t.Fatal("NoTemplate = 0, want > 0: the first datagram carries data before any template is learned")
	}
	if s.Malformed != 0 || s.VarLenRejected != 0 || s.UnsupportedVersion != 0 {
		t.Fatalf("stats = %+v, want no malformed/varlen/unsupported: every datagram is real, well-formed v9", s)
	}
	if s.TemplatesLearned != 2 {
		t.Fatalf("TemplatesLearned = %d, want 2 (256 IPv4 and 259 IPv6, the box's only shapes)", s.TemplatesLearned)
	}
	if s.Records == 0 {
		t.Fatal("Records = 0, want the records that decoded once their templates were learned")
	}
}

// The box exports IPv6 flows under template 259 with 16-byte address elements. The
// fixture retains real ones; this proves the decoder reads them alongside the IPv4
// template without the two colliding in the cache.
func TestReplayV9_IPv6FlowsDecode(t *testing.T) {
	recs, _ := decodeReplay(t)
	var v6, tmpl259 int
	for _, r := range recs {
		if r.SrcAddr.Is6() && r.DstAddr.Is6() {
			v6++
		}
		if r.TemplateID == 259 {
			tmpl259++
		}
	}
	if v6 == 0 {
		t.Fatal("no IPv6 records decoded from the fixture")
	}
	if tmpl259 == 0 {
		t.Fatal("no template-259 records decoded; the IPv6 template did not decode")
	}
}

// The safety gate. Every address in the fixture — source, destination AND next-hop,
// v4 and v6 — must be a documentation address or a non-global one. A real routable
// address surviving here means the anonymiser missed a field, and a future re-capture
// would leak the real network. This walks the RAW record bytes (not just decoded
// src/dst) so a missed next-hop element cannot slip through.
func TestReplayV9_NoRealAddressSurvives(t *testing.T) {
	frames := readReplayFrames(t)

	// Learn every template first (the data-only datagram's template arrives later in
	// the file), then extract every address element from every record.
	templates := map[uint16][]tfield{}
	for _, f := range frames {
		walkFlowsets(t, f.payload, func(id uint16, body []byte) {
			if id == 0 {
				learnFixtureTemplates(body, templates)
			}
		})
	}

	docRanges := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	safe := func(a netip.Addr) bool {
		if !a.IsValid() {
			return true
		}
		a = a.Unmap()
		// A non-global address (private, CGNAT, multicast, link-local, loopback,
		// unspecified) carries no real routable identity and is allowed.
		if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() ||
			a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
			return true
		}
		if a.Is4() {
			b := a.As4()
			if b[0] == 100 && b[1] >= 64 && b[1] <= 127 { // CGNAT 100.64/10
				return true
			}
		}
		for _, p := range docRanges {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}

	seen := map[netip.Addr]bool{}
	total := 0
	for _, f := range frames {
		walkFlowsets(t, f.payload, func(id uint16, body []byte) {
			if id < 256 {
				return
			}
			for _, a := range extractAddresses(templates[id], body) {
				total++
				if seen[a] {
					continue
				}
				seen[a] = true
				if !safe(a) {
					t.Errorf("real address survived anonymisation: %v", a)
				}
			}
		})
	}
	if total == 0 {
		t.Fatal("extracted no addresses from the fixture; the walker or fixture is broken")
	}
	t.Logf("scanned %d address fields, %d distinct, all documentation/non-global", total, len(seen))
}

// walkFlowsets calls fn for each v9 flowset in payload. It is a deliberately small,
// independent re-implementation of the flowset frame walk, so the leak-guard does not
// depend on the very decoder it is guarding.
func walkFlowsets(t *testing.T, payload []byte, fn func(id uint16, body []byte)) {
	t.Helper()
	if len(payload) < 20 {
		t.Fatalf("fixture datagram shorter than a v9 header")
	}
	off := 20
	for off+4 <= len(payload) {
		id := binary.BigEndian.Uint16(payload[off:])
		length := int(binary.BigEndian.Uint16(payload[off+2:]))
		if length < 4 || off+length > len(payload) {
			t.Fatalf("fixture flowset length %d at %d is impossible", length, off)
		}
		fn(id, payload[off+4:off+length])
		off += length
	}
}

func learnFixtureTemplates(body []byte, into map[uint16][]tfield) {
	for len(body) >= 4 {
		id := binary.BigEndian.Uint16(body)
		count := int(binary.BigEndian.Uint16(body[2:]))
		body = body[4:]
		if len(body) < count*4 {
			return
		}
		fields := make([]tfield, count)
		for i := range fields {
			fields[i] = tfield{
				typ:    binary.BigEndian.Uint16(body[i*4:]),
				length: binary.BigEndian.Uint16(body[i*4+2:]),
			}
		}
		into[id] = fields
		body = body[count*4:]
	}
}

// tfield mirrors one template element for the leak-guard's own walker.
type tfield struct{ typ, length uint16 }

// extractAddresses returns every address element (v4/v6 src/dst/next-hop) from every
// record in a data flowset body.
func extractAddresses(fields []tfield, body []byte) []netip.Addr {
	if len(fields) == 0 {
		return nil
	}
	recLen := 0
	for _, f := range fields {
		recLen += int(f.length)
	}
	if recLen == 0 {
		return nil
	}
	var out []netip.Addr
	for len(body) >= recLen {
		rec := body[:recLen]
		off := 0
		for _, f := range fields {
			switch f.typ {
			case FieldIPv4SrcAddr, FieldIPv4DstAddr, 15: // 15 = IPV4_NEXT_HOP
				if f.length == 4 {
					if a, ok := netip.AddrFromSlice(rec[off : off+4]); ok {
						out = append(out, a)
					}
				}
			case FieldIPv6SrcAddr, FieldIPv6DstAddr, 62: // 62 = IPV6_NEXT_HOP
				if f.length == 16 {
					if a, ok := netip.AddrFromSlice(rec[off : off+16]); ok {
						out = append(out, a)
					}
				}
			}
			off += int(f.length)
		}
		body = body[recLen:]
	}
	return out
}
