package netflow

// Every datagram in these tests is assembled BYTE BY BYTE. A captured fixture
// would hide exactly the offsets these tests exist to pin — and a real capture
// carries real network addressing, which has no business in a repository. The
// builders below are deliberately dumb: they encode what the RFC says the wire
// looks like, not what the decoder happens to read.

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// --- wire builders ---------------------------------------------------------

func be16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

func be32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func cat(parts ...[]byte) []byte {
	out := []byte{}
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// tField is one (type, length) pair in a template definition.
type tField struct{ typ, length uint16 }

// tDef is one template: its id and its ordered field list.
type tDef struct {
	id     uint16
	fields []tField
}

// rawFlowset frames a body with the 4-byte flowset header. The length field
// counts the header, which is the off-by-four every hand-rolled NetFlow parser
// gets wrong at least once.
func rawFlowset(id uint16, body []byte) []byte {
	return cat(be16(id), be16(uint16(len(body)+4)), body)
}

func templateFlowset(defs ...tDef) []byte {
	body := []byte{}
	for _, d := range defs {
		body = cat(body, be16(d.id), be16(uint16(len(d.fields))))
		for _, f := range d.fields {
			body = cat(body, be16(f.typ), be16(f.length))
		}
	}
	return rawFlowset(0, body)
}

// dataFlowset frames records and pads the set to a 4-byte boundary, as
// ng_netflow does. The pad bytes are shorter than one record and MUST be read as
// padding — a decoder that treats them as a truncated record drops the flowset.
//
// Every template used with this builder is at least 4 bytes wide, which is what
// makes the pad unambiguous. RFC 3954 requires padding to be SHORTER than one
// record for exactly that reason: a sender emitting 2 bytes of padding after a
// 2-byte record has made a run of zeroes indistinguishable from a real record,
// and no decoder can recover that.
func dataFlowset(id uint16, recs ...[]byte) []byte {
	body := cat(recs...)
	for (len(body)+4)%4 != 0 {
		body = append(body, 0)
	}
	return rawFlowset(id, body)
}

type v9Head struct {
	count    uint16
	sysUp    uint32
	unixSecs uint32
	seq      uint32
	sourceID uint32
}

func v9Datagram(h v9Head, flowsets ...[]byte) []byte {
	return cat(
		be16(9), be16(h.count),
		be32(h.sysUp), be32(h.unixSecs), be32(h.seq), be32(h.sourceID),
		cat(flowsets...),
	)
}

// --- the box's real template shapes ----------------------------------------

// ipv4Template mirrors the 20-field IPv4 template ng_netflow sends as id 256
// (#346). Four of its elements — TOS(5), SRC_MASK(9), DST_MASK(13),
// IPV4_NEXT_HOP(15) — are ones the decoder does not model, so the happy path
// itself proves unknown fields are skipped by their DECLARED length. SRC_AS and
// DST_AS are len=4 here, not the usual 2.
func ipv4Template() tDef {
	return tDef{id: 256, fields: []tField{
		{1, 4}, {2, 4}, {4, 1}, {5, 1}, {6, 1},
		{7, 2}, {8, 4}, {9, 1}, {10, 2}, {11, 2},
		{12, 4}, {13, 1}, {14, 2}, {15, 4}, {16, 4},
		{17, 4}, {21, 4}, {22, 4}, {23, 4}, {24, 4},
	}}
}

// ipv6Template mirrors id 259: the same 20 elements with the three address
// fields widened to 16 bytes.
func ipv6Template() tDef {
	return tDef{id: 259, fields: []tField{
		{1, 4}, {2, 4}, {4, 1}, {5, 1}, {6, 1},
		{7, 2}, {27, 16}, {9, 1}, {10, 2}, {11, 2},
		{28, 16}, {13, 1}, {14, 2}, {62, 16}, {16, 4},
		{17, 4}, {21, 4}, {22, 4}, {23, 4}, {24, 4},
	}}
}

// flowVals is one record's contents, named so the encoder below reads as the
// template's field order rather than as a wall of magic numbers.
type flowVals struct {
	inBytes, inPkts   uint32
	proto             uint8
	tos               uint8
	tcpFlags          uint8
	srcPort           uint16
	src               string
	srcMask           uint8
	inputSNMP         uint16
	dstPort           uint16
	dst               string
	dstMask           uint8
	outputSNMP        uint16
	nextHop           string
	srcAS, dstAS      uint32
	last, first       uint32
	outBytes, outPkts uint32
}

func addrBytes(t *testing.T, s string, want int) []byte {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("bad test address %q: %v", s, err)
	}
	b := a.AsSlice()
	if len(b) != want {
		t.Fatalf("address %q encodes to %d bytes, test wants %d", s, len(b), want)
	}
	return b
}

func ipv4Record(t *testing.T, v flowVals) []byte {
	t.Helper()
	return cat(
		be32(v.inBytes), be32(v.inPkts), []byte{v.proto}, []byte{v.tos}, []byte{v.tcpFlags},
		be16(v.srcPort), addrBytes(t, v.src, 4), []byte{v.srcMask}, be16(v.inputSNMP), be16(v.dstPort),
		addrBytes(t, v.dst, 4), []byte{v.dstMask}, be16(v.outputSNMP), addrBytes(t, v.nextHop, 4), be32(v.srcAS),
		be32(v.dstAS), be32(v.last), be32(v.first), be32(v.outBytes), be32(v.outPkts),
	)
}

func ipv6Record(t *testing.T, v flowVals) []byte {
	t.Helper()
	return cat(
		be32(v.inBytes), be32(v.inPkts), []byte{v.proto}, []byte{v.tos}, []byte{v.tcpFlags},
		be16(v.srcPort), addrBytes(t, v.src, 16), []byte{v.srcMask}, be16(v.inputSNMP), be16(v.dstPort),
		addrBytes(t, v.dst, 16), []byte{v.dstMask}, be16(v.outputSNMP), addrBytes(t, v.nextHop, 16), be32(v.srcAS),
		be32(v.dstAS), be32(v.last), be32(v.first), be32(v.outBytes), be32(v.outPkts),
	)
}

// --- shared test constants --------------------------------------------------

var (
	testExporter = netip.MustParseAddr("192.0.2.1")
	// testExport is the firewall's wall clock at export. Written as an explicit
	// instant so every time expectation below can be spelled as another explicit
	// instant rather than as a re-run of the decoder's own arithmetic.
	testExport = time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	// testNow is the receive instant. It is deliberately NOT equal to testExport,
	// so a test that expects an export-derived time cannot pass by accident.
	testNow = time.Date(2026, 7, 21, 12, 0, 3, 0, time.UTC)
)

func testHead(sysUp uint32) v9Head {
	return v9Head{count: 1, sysUp: sysUp, unixSecs: uint32(testExport.Unix()), seq: 42, sourceID: 7}
}

// --- v9 ---------------------------------------------------------------------

func TestDecodeV9_TemplateThenDataHappyPath(t *testing.T) {
	d := New()
	v := flowVals{
		inBytes: 15000, inPkts: 12, proto: 6, tos: 8, tcpFlags: 0x18,
		srcPort: 54321, src: "192.0.2.55", srcMask: 24, inputSNMP: 3,
		dstPort: 443, dst: "198.51.100.7", dstMask: 32, outputSNMP: 1,
		nextHop: "192.0.2.254", srcAS: 0, dstAS: 15169,
		last: 3600000, first: 3599000,
	}
	pkt := v9Datagram(testHead(3600000),
		templateFlowset(ipv4Template()),
		dataFlowset(256, ipv4Record(t, v)),
	)

	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if dg.Version != V9 || dg.SourceID != 7 || dg.Sequence != 42 {
		t.Fatalf("header = v%d src=%d seq=%d, want v9 src=7 seq=42", dg.Version, dg.SourceID, dg.Sequence)
	}
	if !dg.ExportTime.Equal(testExport) {
		t.Fatalf("ExportTime = %v, want %v", dg.ExportTime, testExport)
	}
	if len(dg.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(dg.Records))
	}
	r := dg.Records[0]
	for _, c := range []struct {
		name      string
		got, want any
	}{
		{"Bytes", r.Bytes, uint64(15000)},
		{"Packets", r.Packets, uint64(12)},
		{"Proto", r.Proto, uint8(6)},
		{"TCPFlags", r.TCPFlags, uint8(0x18)},
		{"SrcPort", r.SrcPort, uint16(54321)},
		{"DstPort", r.DstPort, uint16(443)},
		{"SrcAddr", r.SrcAddr, netip.MustParseAddr("192.0.2.55")},
		{"DstAddr", r.DstAddr, netip.MustParseAddr("198.51.100.7")},
		{"InIfIndex", r.InIfIndex, uint32(3)},
		{"OutIfIndex", r.OutIfIndex, uint32(1)},
		{"DstAS", r.DstAS, uint32(15169)},
		{"TemplateID", r.TemplateID, uint16(256)},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}

	s := d.Stats()
	if s.Datagrams != 1 || s.Records != 1 || s.TemplatesLearned != 1 {
		t.Fatalf("stats = %+v, want 1 datagram / 1 record / 1 template learned", s)
	}
	if s.NoTemplate != 0 || s.Malformed != 0 || s.UnexpectedOutBytes != 0 {
		t.Fatalf("stats = %+v, want no drops on a clean datagram", s)
	}
}

// The box uses template 256 for IPv4 and 259 for IPv6, 20 fields each. The two
// live in the same cache and must not collide.
func TestDecodeV9_IPv6TemplateDecodesAlongsideIPv4(t *testing.T) {
	d := New()
	v4 := flowVals{inBytes: 100, inPkts: 1, proto: 17, srcPort: 5353, src: "192.0.2.55",
		dstPort: 53, dst: "198.51.100.7", nextHop: "192.0.2.254"}
	v6 := flowVals{inBytes: 200, inPkts: 2, proto: 6, srcPort: 40000, src: "2001:db8::5",
		dstPort: 443, dst: "2001:db8:1::7", nextHop: "2001:db8::1"}

	pkt := v9Datagram(testHead(1000),
		templateFlowset(ipv4Template(), ipv6Template()),
		dataFlowset(256, ipv4Record(t, v4)),
		dataFlowset(259, ipv6Record(t, v6)),
	)
	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(dg.Records) != 2 {
		t.Fatalf("got %d records, want 2", len(dg.Records))
	}
	if dg.Records[0].SrcAddr != netip.MustParseAddr("192.0.2.55") {
		t.Errorf("v4 SrcAddr = %v", dg.Records[0].SrcAddr)
	}
	if dg.Records[1].SrcAddr != netip.MustParseAddr("2001:db8::5") {
		t.Errorf("v6 SrcAddr = %v", dg.Records[1].SrcAddr)
	}
	if dg.Records[1].DstAddr != netip.MustParseAddr("2001:db8:1::7") {
		t.Errorf("v6 DstAddr = %v", dg.Records[1].DstAddr)
	}
	if dg.Records[1].Bytes != 200 || dg.Records[1].DstPort != 443 {
		t.Errorf("v6 record = %+v, want 200 bytes to port 443", dg.Records[1])
	}
	if s := d.Stats(); s.TemplatesLearned != 2 {
		t.Fatalf("TemplatesLearned = %d, want 2", s.TemplatesLearned)
	}
}

// A v4-mapped IPv6 address and its plain v4 form are the SAME host. Without
// Unmap they are different netip.Addrs and every downstream join
// (flow.CanonicalTuple, enrich scope lookups) silently misses them.
func TestDecodeV9_V4MappedAddressUnmapsToPlainV4(t *testing.T) {
	d := New()
	v := flowVals{inBytes: 1, inPkts: 1, proto: 6, src: "::ffff:192.0.2.55",
		dst: "::ffff:198.51.100.7", nextHop: "::ffff:192.0.2.254"}
	pkt := v9Datagram(testHead(1000),
		templateFlowset(ipv6Template()),
		dataFlowset(259, ipv6Record(t, v)),
	)
	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got, want := dg.Records[0].SrcAddr, netip.MustParseAddr("192.0.2.55"); got != want {
		t.Errorf("SrcAddr = %v (is4=%v), want %v", got, got.Is4(), want)
	}
	if got, want := dg.Records[0].DstAddr, netip.MustParseAddr("198.51.100.7"); got != want {
		t.Errorf("DstAddr = %v, want %v", got, want)
	}
}

// Normal for up to ~2 minutes from a cold start: ng_netflow re-sends templates
// on a timer, so a receiver that starts mid-cycle sees data first. It is a
// counted drop, never an error.
func TestDecodeV9_DataBeforeTemplateCountsNoTemplate(t *testing.T) {
	d := New()
	v := flowVals{inBytes: 1, inPkts: 1, src: "192.0.2.55", dst: "198.51.100.7", nextHop: "192.0.2.254"}
	pkt := v9Datagram(testHead(1000), dataFlowset(256, ipv4Record(t, v)))

	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil: a missing template is expected, not malformed", err)
	}
	if len(dg.Records) != 0 {
		t.Fatalf("got %d records, want 0", len(dg.Records))
	}
	s := d.Stats()
	if s.NoTemplate != 1 {
		t.Fatalf("NoTemplate = %d, want 1", s.NoTemplate)
	}
	if s.Malformed != 0 {
		t.Fatalf("Malformed = %d, want 0", s.Malformed)
	}
	if s.Datagrams != 1 {
		t.Fatalf("Datagrams = %d, want 1: the datagram was still accepted", s.Datagrams)
	}
}

// The desync catcher. An element the decoder does not model must be stepped over
// by its TEMPLATE-DECLARED length; guessing a width shifts every following field
// and corrupts the whole record silently.
func TestDecodeV9_UnknownFieldSkippedByDeclaredLength(t *testing.T) {
	d := New()
	// type 999 is not a real element and is deliberately an odd 3 bytes wide, so
	// any assumed width (1, 2, 4) desynchronises the port that follows it.
	tmpl := tDef{id: 300, fields: []tField{
		{7, 2},   // L4_SRC_PORT
		{999, 3}, // unknown, 3 bytes
		{11, 2},  // L4_DST_PORT
		{4, 1},   // PROTOCOL
	}}
	rec := cat(be16(1234), []byte{0xde, 0xad, 0xbe}, be16(443), []byte{6})
	pkt := v9Datagram(testHead(1000), templateFlowset(tmpl), dataFlowset(300, rec))

	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(dg.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(dg.Records))
	}
	r := dg.Records[0]
	if r.SrcPort != 1234 || r.DstPort != 443 || r.Proto != 6 {
		t.Fatalf("record = src:%d dst:%d proto:%d, want src:1234 dst:443 proto:6 "+
			"(a wrong dst/proto means the unknown field was not skipped by its declared 3 bytes)",
			r.SrcPort, r.DstPort, r.Proto)
	}
}

// SRC_AS/DST_AS are len=4 on this export, not the usual 2. The integer reader
// must take its width from the template, so a 32-bit ASN survives intact.
func TestDecodeV9_ThirtyTwoBitASNumbers(t *testing.T) {
	d := New()
	tmpl := tDef{id: 301, fields: []tField{{16, 4}, {17, 4}}}
	rec := cat(be32(4200000000), be32(65536))
	pkt := v9Datagram(testHead(1000), templateFlowset(tmpl), dataFlowset(301, rec))

	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	r := dg.Records[0]
	if r.SrcAS != 4200000000 || r.DstAS != 65536 {
		t.Fatalf("AS = src:%d dst:%d, want src:4200000000 dst:65536 (truncated to 16 bits?)", r.SrcAS, r.DstAS)
	}
}

// Any element width from 1 to 8 bytes must read as a big-endian left-padded
// integer. ng_netflow uses 2-byte SNMP indices and 4-byte counters, but the
// template is the authority and a 1- or 8-byte declaration is legal.
func TestDecodeV9_IntegerWidthsOneToEight(t *testing.T) {
	d := New()
	tmpl := tDef{id: 302, fields: []tField{
		{10, 1}, // INPUT_SNMP, 1 byte
		{14, 3}, // OUTPUT_SNMP, 3 bytes
		{1, 8},  // IN_BYTES, 8 bytes
		{2, 2},  // IN_PKTS, 2 bytes
	}}
	rec := cat([]byte{0x09}, []byte{0x01, 0x00, 0x02},
		[]byte{0, 0, 0, 1, 0, 0, 0, 0}, be16(500))
	pkt := v9Datagram(testHead(1000), templateFlowset(tmpl), dataFlowset(302, rec))

	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	r := dg.Records[0]
	if r.InIfIndex != 9 {
		t.Errorf("InIfIndex = %d, want 9", r.InIfIndex)
	}
	if r.OutIfIndex != 0x010002 {
		t.Errorf("OutIfIndex = %#x, want 0x010002", r.OutIfIndex)
	}
	if r.Bytes != 1<<32 {
		t.Errorf("Bytes = %d, want %d", r.Bytes, uint64(1)<<32)
	}
	if r.Packets != 500 {
		t.Errorf("Packets = %d, want 500", r.Packets)
	}
}

// OUT_BYTES/OUT_PKTS are declared by this export but verified always-zero across
// 84,513 records (#346). Reading them as a volume fallback would silently double
// a real counter the day that changes, so they are counted and ignored.
func TestDecodeV9_NonZeroOutBytesCountedNotAdded(t *testing.T) {
	d := New()
	v := flowVals{
		inBytes: 15000, inPkts: 12, proto: 6, src: "192.0.2.55", dst: "198.51.100.7",
		nextHop: "192.0.2.254", outBytes: 9999, outPkts: 7,
	}
	pkt := v9Datagram(testHead(1000), templateFlowset(ipv4Template()), dataFlowset(256, ipv4Record(t, v)))

	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	r := dg.Records[0]
	if r.Bytes != 15000 {
		t.Fatalf("Bytes = %d, want 15000: OUT_BYTES must never be added to the volume", r.Bytes)
	}
	if r.Packets != 12 {
		t.Fatalf("Packets = %d, want 12: OUT_PKTS must never be added to the volume", r.Packets)
	}
	if s := d.Stats(); s.UnexpectedOutBytes != 1 {
		t.Fatalf("UnexpectedOutBytes = %d, want 1", s.UnexpectedOutBytes)
	}
}

// One record with both OUT_BYTES and OUT_PKTS non-zero is ONE unexpected record,
// not two: the counter's unit is the record.
func TestDecodeV9_UnexpectedOutBytesCountsRecordsNotFields(t *testing.T) {
	d := New()
	base := flowVals{inBytes: 1, inPkts: 1, src: "192.0.2.55", dst: "198.51.100.7", nextHop: "192.0.2.254"}
	both := base
	both.outBytes, both.outPkts = 5, 5
	pkt := v9Datagram(testHead(1000), templateFlowset(ipv4Template()),
		dataFlowset(256, ipv4Record(t, both), ipv4Record(t, base)))

	if _, err := d.Decode(pkt, testExporter, testNow); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if s := d.Stats(); s.UnexpectedOutBytes != 1 {
		t.Fatalf("UnexpectedOutBytes = %d, want 1 (one offending record of two)", s.UnexpectedOutBytes)
	}
}

// FIRST_SWITCHED/LAST_SWITCHED are sysUpTime-relative MILLISECONDS. The absolute
// instants below are written out longhand on purpose: recomputing them with the
// decoder's own formula would make this test agree with any arithmetic at all.
func TestDecodeV9_AbsoluteTimesFromSysUpTime(t *testing.T) {
	d := New()
	const sysUp = 3600000 // 1 hour of uptime, in ms
	v := flowVals{
		inBytes: 1, inPkts: 1, src: "192.0.2.55", dst: "198.51.100.7", nextHop: "192.0.2.254",
		first: sysUp - 90500, // 90.5 s before the export
		last:  sysUp - 1000,  // 1 s before the export
	}
	pkt := v9Datagram(testHead(sysUp), templateFlowset(ipv4Template()), dataFlowset(256, ipv4Record(t, v)))

	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	r := dg.Records[0]
	wantFirst := time.Date(2026, 7, 21, 11, 58, 29, 500000000, time.UTC)
	wantLast := time.Date(2026, 7, 21, 11, 59, 59, 0, time.UTC)
	if !r.First.Equal(wantFirst) {
		t.Errorf("First = %v, want %v", r.First.UTC(), wantFirst)
	}
	if !r.Last.Equal(wantLast) {
		t.Errorf("Last = %v, want %v", r.Last.UTC(), wantLast)
	}
}

// sysUpTime is a 32-bit millisecond counter that wraps every ~49.7 days, and a
// reboot mid-export resets it. Either way "switched" can exceed it, and the
// subtraction would place the flow in the future.
func TestDecodeV9_SwitchedBeyondSysUpTimeClampsToExportTime(t *testing.T) {
	d := New()
	const sysUp = 1000
	v := flowVals{
		inBytes: 1, inPkts: 1, src: "192.0.2.55", dst: "198.51.100.7", nextHop: "192.0.2.254",
		first: sysUp + 5000, last: sysUp + 9000,
	}
	pkt := v9Datagram(testHead(sysUp), templateFlowset(ipv4Template()), dataFlowset(256, ipv4Record(t, v)))

	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	r := dg.Records[0]
	if !r.First.Equal(testExport) || !r.Last.Equal(testExport) {
		t.Fatalf("first=%v last=%v, want both clamped to the export instant %v",
			r.First.UTC(), r.Last.UTC(), testExport)
	}
}

// A template that carries neither switched element leaves the times ZERO rather
// than defaulting to the export instant: an absent timestamp and a timestamp
// equal to the export are different facts downstream.
func TestDecodeV9_AbsentSwitchedElementsLeaveZeroTimes(t *testing.T) {
	d := New()
	tmpl := tDef{id: 303, fields: []tField{{1, 4}, {2, 4}}}
	pkt := v9Datagram(testHead(1000), templateFlowset(tmpl), dataFlowset(303, cat(be32(10), be32(1))))

	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	r := dg.Records[0]
	if !r.First.IsZero() || !r.Last.IsZero() {
		t.Fatalf("first=%v last=%v, want both zero when the template omits them", r.First, r.Last)
	}
}

// A firewall exporting before its clock is set sends unix_secs=0. Dating the
// whole datagram to 1970 would poison every downstream rollup, so the receive
// instant is used instead — wrong by the network delay, which is the far smaller
// error.
func TestDecodeV9_ZeroUnixSecsFallsBackToReceiveTime(t *testing.T) {
	d := New()
	h := testHead(1000)
	h.unixSecs = 0
	v := flowVals{inBytes: 1, inPkts: 1, src: "192.0.2.55", dst: "198.51.100.7",
		nextHop: "192.0.2.254", first: 500, last: 1000}
	pkt := v9Datagram(h, templateFlowset(ipv4Template()), dataFlowset(256, ipv4Record(t, v)))

	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if !dg.ExportTime.Equal(testNow) {
		t.Fatalf("ExportTime = %v, want the receive instant %v", dg.ExportTime, testNow)
	}
	want := time.Date(2026, 7, 21, 12, 0, 2, 500000000, time.UTC)
	if !dg.Records[0].First.Equal(want) {
		t.Fatalf("First = %v, want %v", dg.Records[0].First.UTC(), want)
	}
}

// Options templates (id 1) are skipped by length and never interpreted: this
// export carries no scoped data we consume, and mis-parsing one would
// desynchronise every flowset behind it.
func TestDecodeV9_OptionsTemplateSkippedByLength(t *testing.T) {
	d := New()
	// A plausible options-template body. Its contents are irrelevant — that is the
	// point — but the data flowset behind it must still decode.
	opts := rawFlowset(1, cat(be16(400), be16(4), be16(4), be16(1), be16(4), be16(2), be16(42), be16(4)))
	v := flowVals{inBytes: 77, inPkts: 1, src: "192.0.2.55", dst: "198.51.100.7", nextHop: "192.0.2.254"}
	pkt := v9Datagram(testHead(1000), templateFlowset(ipv4Template()), opts, dataFlowset(256, ipv4Record(t, v)))

	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(dg.Records) != 1 || dg.Records[0].Bytes != 77 {
		t.Fatalf("records = %+v, want one 77-byte record decoded after the options template", dg.Records)
	}
	if s := d.Stats(); s.Malformed != 0 || s.TemplatesLearned != 1 {
		t.Fatalf("stats = %+v, want the options template ignored, not learned or flagged", s)
	}
}

func TestDecode_TruncatedAndUnsupported(t *testing.T) {
	full := v9Datagram(testHead(1000), templateFlowset(ipv4Template()))
	for _, c := range []struct {
		name    string
		payload []byte
		want    error
	}{
		{"empty", nil, ErrShortPacket},
		{"one byte", []byte{0x00}, ErrShortPacket},
		{"v9 header cut short", full[:19], ErrShortPacket},
		{"v5 header cut short", cat(be16(5), be16(1), make([]byte, 10)), ErrShortPacket},
		{"unsupported version 3", cat(be16(3), make([]byte, 30)), ErrUnsupportedVersion},
		{"unsupported version 10 (ipfix)", cat(be16(10), make([]byte, 30)), ErrUnsupportedVersion},
		{"flowset length overruns the datagram",
			v9Datagram(testHead(1000), cat(be16(256), be16(400), make([]byte, 40))), ErrMalformed},
		{"flowset length below its own header",
			v9Datagram(testHead(1000), cat(be16(256), be16(3), make([]byte, 40))), ErrMalformed},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := New()
			if _, err := d.Decode(c.payload, testExporter, testNow); !errors.Is(err, c.want) {
				t.Fatalf("Decode() error = %v, want %v", err, c.want)
			}
		})
	}
}

// A flowset id below 256 that is neither 0 nor 1 is reserved. Skipping it by
// length keeps a future control flowset from taking the datagram down with it.
func TestDecodeV9_ReservedFlowsetIDSkippedByLength(t *testing.T) {
	d := New()
	reserved := rawFlowset(5, make([]byte, 8))
	v := flowVals{inBytes: 9, inPkts: 1, src: "192.0.2.55", dst: "198.51.100.7", nextHop: "192.0.2.254"}
	pkt := v9Datagram(testHead(1000), templateFlowset(ipv4Template()), reserved, dataFlowset(256, ipv4Record(t, v)))

	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(dg.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(dg.Records))
	}
}

// The header's count covers templates AND records and a miscounting sender must
// not be able to steer iteration: flowset lengths are the only structure trusted.
func TestDecodeV9_HeaderCountIsAdvisory(t *testing.T) {
	d := New()
	h := testHead(1000)
	h.count = 999
	v := flowVals{inBytes: 5, inPkts: 1, src: "192.0.2.55", dst: "198.51.100.7", nextHop: "192.0.2.254"}
	pkt := v9Datagram(h, templateFlowset(ipv4Template()), dataFlowset(256, ipv4Record(t, v), ipv4Record(t, v)))

	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(dg.Records) != 2 {
		t.Fatalf("got %d records, want the 2 the flowset actually contains", len(dg.Records))
	}
}

// Every datagram handed to the decoder lands in EXACTLY one bucket. Without that
// invariant a fleet-wide "received vs decoded" panel cannot be built, and a
// silent drop is indistinguishable from a quiet network.
func TestDecode_StatsAccountForEveryDatagram(t *testing.T) {
	d := New()
	good := v9Datagram(testHead(1000), templateFlowset(ipv4Template()))
	varLen := v9Datagram(testHead(1000), templateFlowset(tDef{id: 310, fields: []tField{{7, 0xffff}}}))
	payloads := [][]byte{
		good,
		{0x00},                         // short
		cat(be16(3), make([]byte, 30)), // unsupported
		varLen,                         // variable length
		v9Datagram(testHead(1000), cat(be16(256), be16(999))), // malformed length
	}
	for _, p := range payloads {
		_, _ = d.Decode(p, testExporter, testNow)
	}
	s := d.Stats()
	total := s.Datagrams + s.Malformed + s.UnsupportedVersion + s.VarLenRejected
	if total != uint64(len(payloads)) {
		t.Fatalf("stats = %+v: buckets sum to %d, want %d — every datagram must land in exactly one",
			s, total, len(payloads))
	}
	if s.Datagrams != 1 || s.UnsupportedVersion != 1 || s.VarLenRejected != 1 || s.Malformed != 2 {
		t.Fatalf("stats = %+v, want 1 accepted / 1 unsupported / 1 varlen / 2 malformed", s)
	}
}

func TestStats_ReturnsSnapshotByValue(t *testing.T) {
	d := New()
	before := d.Stats()
	pkt := v9Datagram(testHead(1000), templateFlowset(ipv4Template()))
	if _, err := d.Decode(pkt, testExporter, testNow); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if before.Datagrams != 0 || before.TemplatesLearned != 0 {
		t.Fatalf("an earlier Stats() snapshot changed under a later Decode: %+v", before)
	}
	if after := d.Stats(); after.Datagrams != 1 {
		t.Fatalf("Datagrams = %d, want 1", after.Datagrams)
	}
}

// --- v5 ---------------------------------------------------------------------

type v5Vals struct {
	src, dst, nextHop string
	input, output     uint16
	pkts, octets      uint32
	first, last       uint32
	srcPort, dstPort  uint16
	tcpFlags, proto   uint8
	srcAS, dstAS      uint16
}

func v5Record(t *testing.T, v v5Vals) []byte {
	t.Helper()
	return cat(
		addrBytes(t, v.src, 4), addrBytes(t, v.dst, 4), addrBytes(t, v.nextHop, 4),
		be16(v.input), be16(v.output),
		be32(v.pkts), be32(v.octets), be32(v.first), be32(v.last),
		be16(v.srcPort), be16(v.dstPort),
		[]byte{0}, []byte{v.tcpFlags}, []byte{v.proto}, []byte{0},
		be16(v.srcAS), be16(v.dstAS),
		[]byte{24}, []byte{32}, be16(0),
	)
}

func v5Datagram(count uint16, sysUp, secs, nsecs, seq uint32, recs ...[]byte) []byte {
	return cat(
		be16(5), be16(count), be32(sysUp), be32(secs), be32(nsecs), be32(seq),
		[]byte{0}, []byte{0}, be16(0),
		cat(recs...),
	)
}

func TestDecodeV5_HappyPath(t *testing.T) {
	d := New()
	const sysUp = 3600000
	recs := [][]byte{
		v5Record(t, v5Vals{src: "192.0.2.55", dst: "198.51.100.7", nextHop: "192.0.2.254",
			input: 3, output: 1, pkts: 12, octets: 15000, first: sysUp - 1000, last: sysUp,
			srcPort: 54321, dstPort: 443, tcpFlags: 0x18, proto: 6, srcAS: 0, dstAS: 15169}),
		v5Record(t, v5Vals{src: "192.0.2.56", dst: "198.51.100.8", nextHop: "192.0.2.254",
			input: 4, output: 1, pkts: 1, octets: 60, first: sysUp, last: sysUp,
			srcPort: 12345, dstPort: 53, proto: 17}),
	}
	pkt := v5Datagram(2, sysUp, uint32(testExport.Unix()), 0, 9001, recs...)

	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if dg.Version != V5 || dg.Sequence != 9001 || dg.SourceID != 0 {
		t.Fatalf("header = v%d seq=%d src=%d, want v5 seq=9001 src=0", dg.Version, dg.Sequence, dg.SourceID)
	}
	if !dg.ExportTime.Equal(testExport) {
		t.Fatalf("ExportTime = %v, want %v", dg.ExportTime, testExport)
	}
	if len(dg.Records) != 2 {
		t.Fatalf("got %d records, want 2", len(dg.Records))
	}
	r := dg.Records[0]
	if r.SrcAddr != netip.MustParseAddr("192.0.2.55") || r.DstAddr != netip.MustParseAddr("198.51.100.7") {
		t.Errorf("addrs = %v -> %v", r.SrcAddr, r.DstAddr)
	}
	if r.Bytes != 15000 || r.Packets != 12 || r.Proto != 6 || r.TCPFlags != 0x18 {
		t.Errorf("record = %+v, want 15000 bytes / 12 pkts / proto 6 / flags 0x18", r)
	}
	if r.SrcPort != 54321 || r.DstPort != 443 || r.InIfIndex != 3 || r.OutIfIndex != 1 {
		t.Errorf("record = %+v, want ports 54321->443 on ifaces 3->1", r)
	}
	if r.DstAS != 15169 || r.TemplateID != 0 {
		t.Errorf("record = %+v, want DstAS 15169 and TemplateID 0", r)
	}
	wantFirst := time.Date(2026, 7, 21, 11, 59, 59, 0, time.UTC)
	if !r.First.Equal(wantFirst) || !r.Last.Equal(testExport) {
		t.Errorf("first=%v last=%v, want %v and %v", r.First.UTC(), r.Last.UTC(), wantFirst, testExport)
	}
	if s := d.Stats(); s.Datagrams != 1 || s.Records != 2 {
		t.Fatalf("stats = %+v, want 1 datagram / 2 records", s)
	}
}

// v5 has no per-flowset length, so the header count is the ONLY structure. A
// count that overruns the datagram is unrecoverable, not skippable.
func TestDecodeV5_CountOverrunningPayloadIsMalformed(t *testing.T) {
	d := New()
	rec := v5Record(t, v5Vals{src: "192.0.2.55", dst: "198.51.100.7", nextHop: "192.0.2.254"})
	pkt := v5Datagram(5, 1000, uint32(testExport.Unix()), 0, 1, rec)

	if _, err := d.Decode(pkt, testExporter, testNow); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Decode() error = %v, want %v", err, ErrMalformed)
	}
	if s := d.Stats(); s.Malformed != 1 {
		t.Fatalf("Malformed = %d, want 1", s.Malformed)
	}
}

// unix_nsecs is the sub-second residual and is part of the export instant.
func TestDecodeV5_SubSecondExportTime(t *testing.T) {
	d := New()
	pkt := v5Datagram(0, 1000, uint32(testExport.Unix()), 250000000, 1)
	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	want := time.Date(2026, 7, 21, 12, 0, 0, 250000000, time.UTC)
	if !dg.ExportTime.Equal(want) {
		t.Fatalf("ExportTime = %v, want %v", dg.ExportTime, want)
	}
}

// --- concurrency ------------------------------------------------------------

// The decoder is called from a UDP worker POOL, so the template cache is shared
// mutable state on the hot path. Run under -race.
func TestDecode_ConcurrentDecodesAreRaceFree(t *testing.T) {
	const (
		workers = 8
		rounds  = 50
	)
	d := New()
	v := flowVals{inBytes: 100, inPkts: 1, proto: 6, src: "192.0.2.55", dst: "198.51.100.7",
		nextHop: "192.0.2.254", first: 500, last: 1000}
	// One exporter per worker, so the expected template count is exact: the same
	// template id from a different exporter is a DIFFERENT cache entry.
	pkt := v9Datagram(testHead(1000), templateFlowset(ipv4Template()), dataFlowset(256, ipv4Record(t, v)))

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			exporter := netip.AddrFrom4([4]byte{198, 51, 100, byte(w)})
			for i := 0; i < rounds; i++ {
				dg, err := d.Decode(pkt, exporter, testNow)
				if err != nil {
					t.Errorf("worker %d: Decode() error = %v", w, err)
					return
				}
				if len(dg.Records) != 1 {
					t.Errorf("worker %d: got %d records, want 1", w, len(dg.Records))
					return
				}
			}
		}(w)
	}
	wg.Wait()

	s := d.Stats()
	if s.Datagrams != workers*rounds || s.Records != workers*rounds {
		t.Fatalf("stats = %+v, want %d datagrams and records", s, workers*rounds)
	}
	if s.TemplatesLearned != workers {
		t.Fatalf("TemplatesLearned = %d, want %d (one per exporter)", s.TemplatesLearned, workers)
	}
	if s.TemplatesReplaced != 0 {
		t.Fatalf("TemplatesReplaced = %d, want 0: an identical re-send is a refresh", s.TemplatesReplaced)
	}
}
