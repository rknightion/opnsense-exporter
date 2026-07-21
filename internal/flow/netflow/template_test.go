package netflow

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

// simpleTemplate is a two-field template used wherever the SHAPE matters and the
// field semantics do not.
func simpleTemplate(id uint16, fields ...tField) tDef {
	if len(fields) == 0 {
		fields = []tField{{7, 2}, {11, 2}}
	}
	return tDef{id: id, fields: fields}
}

func learnDatagram(id uint16, fields ...tField) []byte {
	return v9Datagram(testHead(1000), templateFlowset(simpleTemplate(id, fields...)))
}

// ng_netflow re-sends every template roughly every 2 minutes (#346). Counting
// those refreshes as replacements would turn the replacement counter into a
// clock instead of a drift signal.
func TestTemplateCache_IdenticalReSendIsARefreshNotAReplacement(t *testing.T) {
	d := New()
	pkt := learnDatagram(256)
	for i := 0; i < 5; i++ {
		if _, err := d.Decode(pkt, testExporter, testNow); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
	}
	s := d.Stats()
	if s.TemplatesLearned != 1 {
		t.Fatalf("TemplatesLearned = %d, want 1", s.TemplatesLearned)
	}
	if s.TemplatesReplaced != 0 {
		t.Fatalf("TemplatesReplaced = %d, want 0 for an identical re-send", s.TemplatesReplaced)
	}
}

// A re-send with a DIFFERENT shape genuinely replaces the cached layout, and the
// records behind it must decode with the NEW one. Decoding them with the old
// shape is silent corruption, not a parse error.
func TestTemplateCache_DifferentShapeReplacesAndTakesEffect(t *testing.T) {
	d := New()
	if _, err := d.Decode(learnDatagram(256, tField{7, 2}), testExporter, testNow); err != nil {
		t.Fatalf("first Decode() error = %v", err)
	}
	// New shape: source port widened to 4 bytes, plus a protocol byte.
	pkt := v9Datagram(testHead(1000),
		templateFlowset(simpleTemplate(256, tField{7, 4}, tField{4, 1})),
		dataFlowset(256, cat(be32(443), []byte{6})),
	)
	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("second Decode() error = %v", err)
	}
	s := d.Stats()
	if s.TemplatesReplaced != 1 {
		t.Fatalf("TemplatesReplaced = %d, want 1", s.TemplatesReplaced)
	}
	if s.TemplatesLearned != 1 {
		t.Fatalf("TemplatesLearned = %d, want 1: a replacement is not a new template", s.TemplatesLearned)
	}
	if len(dg.Records) != 1 || dg.Records[0].SrcPort != 443 || dg.Records[0].Proto != 6 {
		t.Fatalf("records = %+v, want the data read with the NEW shape", dg.Records)
	}
}

// Template ids are only unique within an (exporter, source_id) observation
// domain. Keying on the id alone decodes one exporter's records with another's
// field layout — corruption that no length check can catch.
func TestTemplateCache_KeyedByExporterAndSourceID(t *testing.T) {
	other := netip.MustParseAddr("192.0.2.2")

	t.Run("exporter", func(t *testing.T) {
		d := New()
		if _, err := d.Decode(learnDatagram(256, tField{7, 2}), testExporter, testNow); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		// A different exporter using id 256 for a 4-byte field must NOT be answered
		// from the first exporter's entry.
		pkt := v9Datagram(testHead(1000), dataFlowset(256, be32(0xdeadbeef)))
		dg, err := d.Decode(pkt, other, testNow)
		if err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if len(dg.Records) != 0 {
			t.Fatalf("got %d records, want 0: template 256 is not known for this exporter", len(dg.Records))
		}
		if s := d.Stats(); s.NoTemplate != 1 {
			t.Fatalf("NoTemplate = %d, want 1", s.NoTemplate)
		}
	})

	t.Run("source id", func(t *testing.T) {
		d := New()
		if _, err := d.Decode(learnDatagram(256), testExporter, testNow); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		h := testHead(1000)
		h.sourceID = 99 // same box, different ng_netflow instance
		pkt := v9Datagram(h, dataFlowset(256, be32(0xdeadbeef)))
		dg, err := d.Decode(pkt, testExporter, testNow)
		if err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if len(dg.Records) != 0 {
			t.Fatalf("got %d records, want 0: template 256 is not known for source_id 99", len(dg.Records))
		}
		if s := d.Stats(); s.NoTemplate != 1 {
			t.Fatalf("NoTemplate = %d, want 1", s.NoTemplate)
		}
	})

	t.Run("both learned independently", func(t *testing.T) {
		d := New()
		pkt := learnDatagram(256)
		if _, err := d.Decode(pkt, testExporter, testNow); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if _, err := d.Decode(pkt, other, testNow); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		s := d.Stats()
		if s.TemplatesLearned != 2 || s.TemplatesReplaced != 0 {
			t.Fatalf("stats = %+v, want 2 templates learned and none replaced", s)
		}
	})
}

// One template flowset may carry several templates back to back; the box sends
// 256 (IPv4) and 259 (IPv6) this way.
func TestTemplateCache_MultipleTemplatesInOneFlowset(t *testing.T) {
	d := New()
	pkt := v9Datagram(testHead(1000),
		templateFlowset(
			simpleTemplate(256, tField{7, 2}),
			simpleTemplate(259, tField{11, 4}),
			simpleTemplate(260, tField{4, 1}),
		),
		dataFlowset(259, be32(8080)),
	)
	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if s := d.Stats(); s.TemplatesLearned != 3 {
		t.Fatalf("TemplatesLearned = %d, want 3", s.TemplatesLearned)
	}
	if len(dg.Records) != 1 || dg.Records[0].DstPort != 8080 {
		t.Fatalf("records = %+v, want one record with DstPort 8080", dg.Records)
	}
}

// A 0xffff element length is IPFIX variable-length encoding. ng_netflow never
// emits one, and silently mis-parsing one desynchronises every subsequent
// record, so the whole datagram is rejected rather than guessed at.
func TestTemplate_VariableLengthFieldRejectsTheDatagram(t *testing.T) {
	d := New()
	pkt := v9Datagram(testHead(1000), templateFlowset(simpleTemplate(256, tField{7, 2}, tField{11, 0xffff})))

	if _, err := d.Decode(pkt, testExporter, testNow); !errors.Is(err, ErrVariableLength) {
		t.Fatalf("Decode() error = %v, want %v", err, ErrVariableLength)
	}
	s := d.Stats()
	if s.VarLenRejected != 1 {
		t.Fatalf("VarLenRejected = %d, want 1", s.VarLenRejected)
	}
	if s.Malformed != 0 {
		t.Fatalf("Malformed = %d, want 0: a var-len rejection is its own bucket", s.Malformed)
	}
	if s.TemplatesLearned != 0 {
		t.Fatalf("TemplatesLearned = %d, want 0: a rejected template must not be cached", s.TemplatesLearned)
	}
}

// Data behind a rejected template has no usable layout. It must read as
// "template not known", never as a decode against a partial shape.
func TestTemplate_DataBehindARejectedTemplateIsNotDecoded(t *testing.T) {
	d := New()
	bad := v9Datagram(testHead(1000), templateFlowset(simpleTemplate(256, tField{7, 0xffff})))
	if _, err := d.Decode(bad, testExporter, testNow); !errors.Is(err, ErrVariableLength) {
		t.Fatalf("Decode() error = %v, want %v", err, ErrVariableLength)
	}
	dg, err := d.Decode(v9Datagram(testHead(1000), dataFlowset(256, be16(1))), testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(dg.Records) != 0 {
		t.Fatalf("got %d records, want 0", len(dg.Records))
	}
	if s := d.Stats(); s.NoTemplate != 1 {
		t.Fatalf("NoTemplate = %d, want 1", s.NoTemplate)
	}
}

func TestTemplate_StructurallyImpossibleDefinitions(t *testing.T) {
	for _, c := range []struct {
		name string
		body []byte
	}{
		// A zero-field template has a zero-length record; the data reader would
		// loop forever over any flowset naming it.
		{"zero field count", cat(be16(256), be16(0))},
		// Likewise a template whose every element is zero bytes wide.
		{"zero-length element", cat(be16(256), be16(1), be16(7), be16(0))},
		// field_count promises more (type, length) pairs than the flowset carries.
		{"field count overruns the flowset", cat(be16(256), be16(4), be16(7), be16(2))},
		// Ids 0-255 are reserved for flowset types, so no data flowset can ever
		// name one: a template claiming one is a broken sender.
		{"reserved template id", cat(be16(255), be16(1), be16(7), be16(2))},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := New()
			pkt := v9Datagram(testHead(1000), rawFlowset(0, c.body))
			if _, err := d.Decode(pkt, testExporter, testNow); !errors.Is(err, ErrMalformed) {
				t.Fatalf("Decode() error = %v, want %v", err, ErrMalformed)
			}
			if s := d.Stats(); s.Malformed != 1 || s.TemplatesLearned != 0 {
				t.Fatalf("stats = %+v, want 1 malformed and no template learned", s)
			}
		})
	}
}

// A template flowset padded to a 4-byte boundary leaves up to 3 trailing bytes.
// They are alignment, not a truncated template definition.
func TestTemplate_TrailingPaddingIsNotATemplate(t *testing.T) {
	d := New()
	// One 1-field template is 8 bytes; 2 bytes of padding follow it.
	body := cat(be16(256), be16(1), be16(7), be16(4), []byte{0, 0})
	pkt := v9Datagram(testHead(1000), rawFlowset(0, body), dataFlowset(256, be32(4433)))

	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if s := d.Stats(); s.TemplatesLearned != 1 || s.Malformed != 0 {
		t.Fatalf("stats = %+v, want 1 template learned and no malformed", s)
	}
	if len(dg.Records) != 1 || dg.Records[0].SrcPort != 4433 {
		t.Fatalf("records = %+v, want one record with SrcPort 4433", dg.Records)
	}
}

// Templates learned before a later flowset turns out to be malformed are kept:
// they were fully parsed and are independently valid, and discarding them would
// re-open the cold-start window every time a sender emits one bad flowset.
func TestTemplate_LearnedTemplateSurvivesALaterMalformedFlowset(t *testing.T) {
	d := New()
	pkt := v9Datagram(testHead(1000),
		templateFlowset(simpleTemplate(256, tField{7, 4})),
		cat(be16(256), be16(9999)), // length overruns the datagram
	)
	if _, err := d.Decode(pkt, testExporter, testNow); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Decode() error = %v, want %v", err, ErrMalformed)
	}
	dg, err := d.Decode(v9Datagram(testHead(1000), dataFlowset(256, be32(22))), testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(dg.Records) != 1 || dg.Records[0].SrcPort != 22 {
		t.Fatalf("records = %+v, want the earlier template still cached", dg.Records)
	}
}

// A zero-width cached template must not wedge the record loop. learnTemplates
// makes this unreachable through the wire path, which is exactly why it is
// asserted here against the cache directly: the loop it protects runs on an
// UNAUTHENTICATED path, and "unreachable today" is not a property a UDP listener
// gets to rely on. A failure here hangs rather than reporting, so the test is
// run under a deadline.
func TestDecodeV9_ZeroWidthTemplateCannotWedgeTheRecordLoop(t *testing.T) {
	d := New()
	d.templates[templateKey{exporter: testExporter, sourceID: 7, id: 256}] = &template{
		fields: []templateField{{typ: FieldL4SrcPort, length: 0}},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		dg, err := d.Decode(v9Datagram(testHead(1000), dataFlowset(256, be32(1))), testExporter, testNow)
		if err != nil {
			t.Errorf("Decode() error = %v", err)
			return
		}
		if len(dg.Records) != 0 {
			t.Errorf("got %d records, want 0", len(dg.Records))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Decode did not return: a zero-width record wedged the flowset loop")
	}
	if s := d.Stats(); s.Malformed != 1 {
		t.Fatalf("Malformed = %d, want 1", s.Malformed)
	}
}

// A data flowset whose remainder is shorter than one record ends in padding.
// ng_netflow pads every set to a 4-byte boundary and the box's 57-byte IPv4
// record guarantees a 3-byte tail on an odd count.
func TestDecodeV9_TrailingPaddingInADataFlowsetIsNotARecord(t *testing.T) {
	d := New()
	v := flowVals{inBytes: 42, inPkts: 1, src: "192.0.2.55", dst: "198.51.100.7", nextHop: "192.0.2.254"}
	rec := ipv4Record(t, v)
	if len(rec) != 57 {
		t.Fatalf("the box's IPv4 record is 57 bytes; this test builds %d", len(rec))
	}
	pkt := v9Datagram(testHead(1000), templateFlowset(ipv4Template()), dataFlowset(256, rec))

	dg, err := d.Decode(pkt, testExporter, testNow)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(dg.Records) != 1 {
		t.Fatalf("got %d records, want 1: the 3 pad bytes must not be read as a record", len(dg.Records))
	}
	if s := d.Stats(); s.Malformed != 0 {
		t.Fatalf("Malformed = %d, want 0", s.Malformed)
	}
}
