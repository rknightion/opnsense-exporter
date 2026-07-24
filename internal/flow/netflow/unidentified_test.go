package netflow

import (
	"net/netip"
	"testing"
	"time"
)

// These tests pin the three things the decoder used to step over in total silence
// (#360): unknown template elements, options templates and unknown control
// flowsets. "Stepped over" is correct and is NOT what changed — the tests below
// still assert the records behind each one decode. What changed is that the
// decoder now says so.

func unidentifiedKinds(dg *Datagram) []string {
	out := make([]string, 0, len(dg.Unidentified))
	for _, u := range dg.Unidentified {
		out = append(out, u.Kind)
	}
	return out
}

func hasUnidentified(dg *Datagram, kind string, detail uint16) bool {
	for _, u := range dg.Unidentified {
		if u.Kind == kind && u.Detail == detail {
			return true
		}
	}
	return false
}

func TestDecode_UnknownTemplateElementIsCountedAndReported(t *testing.T) {
	d := New()
	peer := netip.MustParseAddr("192.0.2.1")

	// Field 61 (DIRECTION) is declared by the RFC and deliberately not modelled:
	// Record has nowhere to put it. It is the canonical "we would want to know".
	tmpl := templateFlowset(tDef{id: 300, fields: []tField{
		{FieldInBytes, 4}, {FieldInPkts, 4}, {FieldDirection, 1},
	}})
	dg, err := d.Decode(v9Datagram(v9Head{sysUp: 1000, unixSecs: 1700000000}, tmpl), peer, time.Now())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got := d.Stats().UnknownFields; got != 1 {
		t.Fatalf("UnknownFields = %d, want 1 (%v)", got, unidentifiedKinds(dg))
	}
	if !hasUnidentified(dg, UnidentifiedField, FieldDirection) {
		t.Fatalf("datagram did not report element %d as unidentified: %+v", FieldDirection, dg.Unidentified)
	}
}

// A re-send of an already-known shape must NOT re-report. ng_netflow re-sends every
// template about every two minutes, so counting each one would turn the counter into
// a clock and would make the unidentified capture mode dump a datagram every two
// minutes forever — the same reasoning that makes TemplatesReplaced a drift signal
// rather than a refresh count.
func TestDecode_UnknownTemplateElementIsNotReportedOnEveryResend(t *testing.T) {
	d := New()
	peer := netip.MustParseAddr("192.0.2.1")
	tmpl := templateFlowset(tDef{id: 300, fields: []tField{
		{FieldInBytes, 4}, {FieldDirection, 1},
	}})
	payload := v9Datagram(v9Head{sysUp: 1000, unixSecs: 1700000000}, tmpl)

	if _, err := d.Decode(payload, peer, time.Now()); err != nil {
		t.Fatalf("Decode 1: %v", err)
	}
	dg, err := d.Decode(payload, peer, time.Now())
	if err != nil {
		t.Fatalf("Decode 2: %v", err)
	}
	if got := d.Stats().UnknownFields; got != 1 {
		t.Fatalf("UnknownFields = %d after a re-send, want 1", got)
	}
	if len(dg.Unidentified) != 0 {
		t.Fatalf("re-send reported %+v, want nothing", dg.Unidentified)
	}
}

// A replacement — same id, different shape — IS a re-report: the elements we cannot
// read have changed, which is exactly the drift worth capturing.
func TestDecode_UnknownTemplateElementIsReportedAgainOnAReplacement(t *testing.T) {
	d := New()
	peer := netip.MustParseAddr("192.0.2.1")
	first := v9Datagram(v9Head{sysUp: 1000, unixSecs: 1700000000},
		templateFlowset(tDef{id: 300, fields: []tField{{FieldInBytes, 4}, {FieldDirection, 1}}}))
	second := v9Datagram(v9Head{sysUp: 1000, unixSecs: 1700000000},
		templateFlowset(tDef{id: 300, fields: []tField{{FieldInBytes, 4}, {FieldDirection, 1}, {89, 1}}}))

	if _, err := d.Decode(first, peer, time.Now()); err != nil {
		t.Fatalf("Decode 1: %v", err)
	}
	dg, err := d.Decode(second, peer, time.Now())
	if err != nil {
		t.Fatalf("Decode 2: %v", err)
	}
	if got := d.Stats().UnknownFields; got != 3 {
		t.Fatalf("UnknownFields = %d, want 3 (1 from the first shape, 2 from the replacement)", got)
	}
	if !hasUnidentified(dg, UnidentifiedField, 89) {
		t.Fatalf("replacement did not report element 89: %+v", dg.Unidentified)
	}
}

// The production IPv4 template declares four elements the decoder does not model
// (TOS, SRC_MASK, DST_MASK, IPV4_NEXT_HOP). A non-zero count on a healthy box is
// therefore EXPECTED, and the metric's help says so — it is a change in the set that
// matters, not its existence.
func TestDecode_ProductionTemplateReportsItsFourUnmodelledElements(t *testing.T) {
	d := New()
	peer := netip.MustParseAddr("192.0.2.1")
	dg, err := d.Decode(
		v9Datagram(v9Head{sysUp: 1000, unixSecs: 1700000000}, templateFlowset(ipv4Template())),
		peer, time.Now())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got := d.Stats().UnknownFields; got != 4 {
		t.Fatalf("UnknownFields = %d, want 4 (TOS, SRC_MASK, DST_MASK, IPV4_NEXT_HOP)", got)
	}
	for _, id := range []uint16{5, 9, 13, 15} {
		if !hasUnidentified(dg, UnidentifiedField, id) {
			t.Errorf("element %d not reported: %+v", id, dg.Unidentified)
		}
	}
}

func TestDecode_OptionsTemplateIsCountedAndTheRestOfTheDatagramStillDecodes(t *testing.T) {
	d := New()
	peer := netip.MustParseAddr("192.0.2.1")

	// Learn first, so the data flowset in the mixed datagram below is readable.
	if _, err := d.Decode(
		v9Datagram(v9Head{sysUp: 1000, unixSecs: 1700000000}, templateFlowset(ipv4Template())),
		peer, time.Now()); err != nil {
		t.Fatalf("learn: %v", err)
	}

	// An options-template flowset body the decoder never interprets. Its contents are
	// irrelevant by construction: the point is that it is stepped over by LENGTH.
	opts := rawFlowset(flowsetOptionsTemplate, []byte{0x01, 0x2c, 0x00, 0x04, 0x00, 0x08})
	data := dataFlowset(256, ipv4Record(t, flowVals{
		inBytes: 100, inPkts: 2, proto: 6, src: "192.0.2.10", dst: "198.51.100.5",
		srcPort: 1234, dstPort: 443, inputSNMP: 1, outputSNMP: 2, nextHop: "0.0.0.0",
		first: 500, last: 900,
	}))

	dg, err := d.Decode(v9Datagram(v9Head{sysUp: 1000, unixSecs: 1700000000}, opts, data), peer, time.Now())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got := d.Stats().OptionsTemplates; got != 1 {
		t.Fatalf("OptionsTemplates = %d, want 1", got)
	}
	if !hasUnidentified(dg, UnidentifiedOptions, flowsetOptionsTemplate) {
		t.Fatalf("options template not reported: %+v", dg.Unidentified)
	}
	if len(dg.Records) != 1 {
		t.Fatalf("records = %d, want 1: an options template must not cost the data behind it", len(dg.Records))
	}
}

func TestDecode_UnknownControlFlowsetIsCountedAndTheRestOfTheDatagramStillDecodes(t *testing.T) {
	d := New()
	peer := netip.MustParseAddr("192.0.2.1")
	if _, err := d.Decode(
		v9Datagram(v9Head{sysUp: 1000, unixSecs: 1700000000}, templateFlowset(ipv4Template())),
		peer, time.Now()); err != nil {
		t.Fatalf("learn: %v", err)
	}

	const unknownSet = 7 // inside the reserved 2-255 range, meaningless to this decoder
	weird := rawFlowset(unknownSet, []byte{0xde, 0xad, 0xbe, 0xef})
	data := dataFlowset(256, ipv4Record(t, flowVals{
		inBytes: 64, inPkts: 1, proto: 17, src: "192.0.2.11", dst: "198.51.100.6",
		srcPort: 53, dstPort: 53, inputSNMP: 1, outputSNMP: 2, nextHop: "0.0.0.0",
		first: 500, last: 900,
	}))

	dg, err := d.Decode(v9Datagram(v9Head{sysUp: 1000, unixSecs: 1700000000}, weird, data), peer, time.Now())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got := d.Stats().UnknownFlowsets; got != 1 {
		t.Fatalf("UnknownFlowsets = %d, want 1", got)
	}
	if !hasUnidentified(dg, UnidentifiedFlowset, unknownSet) {
		t.Fatalf("unknown flowset not reported: %+v", dg.Unidentified)
	}
	if len(dg.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(dg.Records))
	}
}

// A datagram the decoder fully understands must report NOTHING, or the unidentified
// capture mode degenerates into capturing everything.
func TestDecode_FullyUnderstoodDatagramReportsNothing(t *testing.T) {
	d := New()
	peer := netip.MustParseAddr("192.0.2.1")
	if _, err := d.Decode(
		v9Datagram(v9Head{sysUp: 1000, unixSecs: 1700000000}, templateFlowset(ipv4Template())),
		peer, time.Now()); err != nil {
		t.Fatalf("learn: %v", err)
	}
	data := dataFlowset(256, ipv4Record(t, flowVals{
		inBytes: 64, inPkts: 1, proto: 6, src: "192.0.2.12", dst: "198.51.100.7",
		srcPort: 80, dstPort: 8080, inputSNMP: 1, outputSNMP: 2, nextHop: "0.0.0.0",
		first: 500, last: 900,
	}))
	dg, err := d.Decode(v9Datagram(v9Head{sysUp: 1000, unixSecs: 1700000000}, data), peer, time.Now())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(dg.Unidentified) != 0 {
		t.Fatalf("a fully understood datagram reported %+v", dg.Unidentified)
	}
}

// A data flowset with no template yet is deliberately NOT unidentified. It is
// already counted (Stats.NoTemplate) and it is the EXPECTED state for the ~2 minutes
// after either end restarts — treating it as surprising would make the unidentified
// capture mode dump the entire stream on every restart and consume the byte cap on a
// condition that resolves itself.
func TestDecode_MissingTemplateIsCountedButNotUnidentified(t *testing.T) {
	d := New()
	peer := netip.MustParseAddr("192.0.2.1")
	data := dataFlowset(256, make([]byte, 57))
	dg, err := d.Decode(v9Datagram(v9Head{sysUp: 1000, unixSecs: 1700000000}, data), peer, time.Now())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got := d.Stats().NoTemplate; got != 1 {
		t.Fatalf("NoTemplate = %d, want 1", got)
	}
	if len(dg.Unidentified) != 0 {
		t.Fatalf("a cold-start no-template flowset reported %+v, want nothing", dg.Unidentified)
	}
}

// The socket is unauthenticated, so the report a datagram can produce must be
// bounded by OUR code, not by what a sender chooses to pack into 65535 bytes. The
// COUNTERS stay exact — they are what an operator acts on; only the sample is capped.
func TestDecode_UnidentifiedReportIsDedupedAndBounded(t *testing.T) {
	d := New()
	peer := netip.MustParseAddr("192.0.2.1")

	// 200 unknown control flowsets: 100 repeats of one id, then 100 distinct ids.
	sets := make([][]byte, 0, 200)
	for range 100 {
		sets = append(sets, rawFlowset(7, []byte{0, 0, 0, 0}))
	}
	for i := range 100 {
		sets = append(sets, rawFlowset(uint16(100+i), []byte{0, 0, 0, 0}))
	}
	dg, err := d.Decode(v9Datagram(v9Head{sysUp: 1000, unixSecs: 1700000000}, sets...), peer, time.Now())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got := d.Stats().UnknownFlowsets; got != 200 {
		t.Fatalf("UnknownFlowsets = %d, want 200 - the counter must stay exact", got)
	}
	if got := len(dg.Unidentified); got != maxUnidentifiedPerDatagram {
		t.Fatalf("reported %d items, want the %d cap", got, maxUnidentifiedPerDatagram)
	}
	// Deduplication is what stops the 100 repeats of id 7 from filling the cap and
	// burying every distinct id behind them.
	sevens := 0
	for _, u := range dg.Unidentified {
		if u.Detail == 7 {
			sevens++
		}
	}
	if sevens != 1 {
		t.Fatalf("flowset id 7 reported %d times, want 1", sevens)
	}
}
