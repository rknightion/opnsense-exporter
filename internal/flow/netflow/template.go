package netflow

import (
	"encoding/binary"
	"net/netip"
)

// templateKey identifies one learned template.
//
// All THREE components are part of the identity. A template id is only unique
// within an (exporter, source_id) observation domain: two firewalls, or two
// ng_netflow instances on one firewall, legitimately use id 256 for different
// shapes. Keying on the id alone would decode one sender's records against the
// other's field layout — corruption no length check can catch, because both
// layouts are the same number of bytes as often as not.
type templateKey struct {
	exporter netip.Addr
	sourceID uint32
	id       uint16
}

// templateField is one element specification: a v9 field type and the width the
// sender declared for it. The width is authoritative — the decoder never assumes
// a canonical width for a type, because this export declares SRC_AS/DST_AS as 4
// bytes where the usual value is 2 (#346).
type templateField struct {
	typ    uint16
	length uint16
}

// template is a decoded v9 template: the ordered element list and the fixed
// record width it implies. recLen is precomputed because it is the loop bound
// for every data record decoded against this template.
type template struct {
	fields []templateField
	recLen int
}

// sameShape reports whether two templates declare an identical element list.
// Identity, not equivalence: a template that reorders its fields or retypes one
// is a different shape even at the same total width, because it decodes to
// different values.
func (t *template) sameShape(o *template) bool {
	if len(t.fields) != len(o.fields) {
		return false
	}
	for i := range t.fields {
		if t.fields[i] != o.fields[i] {
			return false
		}
	}
	return true
}

// learnTemplates parses a template flowset body and caches every definition in
// it. Callers hold d.mu.
//
// It returns an error for a structurally impossible definition rather than
// skipping it: once a field_count or an element width is not believable, the
// offsets behind it in this flowset are not either, and a decoder that keeps
// going invents records. Definitions parsed BEFORE the bad one stay cached —
// they are independently valid, and discarding them would re-open the ~2 minute
// cold-start window every time a sender emits one bad flowset.
func (d *Decoder) learnTemplates(set []byte, exporter netip.Addr, sourceID uint32) error {
	// A template definition header is 4 bytes; a shorter tail is the flowset's
	// alignment padding, not a truncated definition.
	for len(set) >= 4 {
		id := binary.BigEndian.Uint16(set)
		count := int(binary.BigEndian.Uint16(set[2:]))
		set = set[4:]

		if count == 0 {
			// A zero-field template has a zero-width record, which would make the
			// data reader loop forever over any flowset naming it.
			return ErrMalformed
		}
		if len(set) < count*4 {
			return ErrMalformed
		}

		fields := make([]templateField, count)
		recLen := 0
		for i := range fields {
			f := templateField{
				typ:    binary.BigEndian.Uint16(set[i*4:]),
				length: binary.BigEndian.Uint16(set[i*4+2:]),
			}
			if f.length == varLenSentinel {
				// IPFIX variable-length encoding. ng_netflow never emits it, and a
				// decoder that guessed at one would desynchronise every subsequent
				// record in the set — so the datagram is rejected, loudly and counted,
				// rather than half-read.
				return ErrVariableLength
			}
			if f.length == 0 {
				return ErrMalformed
			}
			fields[i] = f
			recLen += int(f.length)
		}
		set = set[count*4:]

		if id < firstDataFlowsetID {
			// Ids 0-255 are reserved for flowset types, so no data flowset can ever
			// name one. A template claiming one is a broken sender, not a shape we
			// could store and never use.
			return ErrMalformed
		}
		d.store(templateKey{exporter: exporter, sourceID: sourceID, id: id}, &template{fields: fields, recLen: recLen})
	}
	return nil
}

// store caches a template, distinguishing a refresh from a replacement. Callers
// hold d.mu.
//
// ng_netflow re-sends every template roughly every 2 minutes (#346), so the
// overwhelming majority of definitions arriving here are re-sends of a shape
// already held. Counting those as replacements would make TemplatesReplaced a
// clock rather than the drift signal it exists to be: a non-zero rate there must
// mean the sender genuinely changed its export shape.
func (d *Decoder) store(k templateKey, t *template) {
	old, ok := d.templates[k]
	switch {
	case !ok:
		d.stats.TemplatesLearned++
	case old.sameShape(t):
		// Refresh. Nothing to do — keeping the existing pointer avoids churning a
		// slice that every in-flight record decode is reading from.
		return
	default:
		d.stats.TemplatesReplaced++
	}
	d.templates[k] = t
}

// lookup returns the cached template for a data flowset, if one has been
// learned. Callers hold d.mu.
func (d *Decoder) lookup(exporter netip.Addr, sourceID uint32, id uint16) (*template, bool) {
	t, ok := d.templates[templateKey{exporter: exporter, sourceID: sourceID, id: id}]
	return t, ok
}
