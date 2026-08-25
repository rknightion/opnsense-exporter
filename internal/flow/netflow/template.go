package netflow

import (
	"container/list"
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

	// elem is this template's node in Decoder.order, the LRU list that bounds
	// the cache (#564). It is set exactly once, the moment the template is
	// first stored, and never nil afterwards — a replacement re-shapes the
	// template in place and reuses the same node, since the key (and so the
	// node's identity) has not changed.
	elem *list.Element
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
//
// It also returns every element the decoder does not model, so the caller can
// report them (#360). They are collected only for definitions that were actually
// STORED — a re-send of a shape already held tells us nothing new, and reporting one
// every ~2 minutes forever would make the counter a clock and the debug capture a
// full stream dump.
func (d *Decoder) learnTemplates(set []byte, exporter netip.Addr, sourceID uint32) ([]Unidentified, error) {
	var unknown []Unidentified
	// A template definition header is 4 bytes; a shorter tail is the flowset's
	// alignment padding, not a truncated definition.
	for len(set) >= 4 {
		id := binary.BigEndian.Uint16(set)
		count := int(binary.BigEndian.Uint16(set[2:]))
		set = set[4:]

		if count == 0 {
			// A zero-field template has a zero-width record, which would make the
			// data reader loop forever over any flowset naming it.
			return nil, ErrMalformed
		}
		if count > maxFieldsPerTemplate {
			return nil, ErrMalformed
		}
		if len(set) < count*4 {
			return nil, ErrMalformed
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
				return nil, ErrVariableLength
			}
			if f.length == 0 {
				return nil, ErrMalformed
			}
			fields[i] = f
			recLen += int(f.length)
		}
		set = set[count*4:]

		if id < firstDataFlowsetID {
			// Ids 0-255 are reserved for flowset types, so no data flowset can ever
			// name one. A template claiming one is a broken sender, not a shape we
			// could store and never use.
			return nil, ErrMalformed
		}
		if d.store(templateKey{exporter: exporter, sourceID: sourceID, id: id},
			&template{fields: fields, recLen: recLen}) {
			// Reported only for a shape we actually took on, and only once per
			// element — see the doc comment.
			for _, f := range fields {
				if !modelledFields[f.typ] {
					d.stats.UnknownFields++
					unknown = append(unknown, Unidentified{Kind: UnidentifiedField, Detail: f.typ})
				}
			}
		}
	}
	return unknown, nil
}

// store caches a template, distinguishing a refresh from a replacement. It reports
// whether the shape was actually taken on — false for a re-send of a shape already
// held — which is what gates the unmodelled-element reporting in learnTemplates.
// Callers hold d.mu.
//
// ng_netflow re-sends every template roughly every 2 minutes (#346), so the
// overwhelming majority of definitions arriving here are re-sends of a shape
// already held. Counting those as replacements would make TemplatesReplaced a
// clock rather than the drift signal it exists to be: a non-zero rate there must
// mean the sender genuinely changed its export shape.
//
// A genuinely NEW key is the only path that can grow the cache, so it is the
// only path checked against maxCachedTemplates (#564): a refresh or a
// same-key replacement reuses the existing map entry and list node and never
// consumes capacity, however full the cache already is — an attacker cannot
// turn a legitimate sender's own re-send into eviction pressure, and a
// legitimate re-send is never itself rejected.
func (d *Decoder) store(k templateKey, t *template) bool {
	old, ok := d.templates[k]
	switch {
	case !ok:
		for len(d.templates) >= maxCachedTemplates || d.templateFields+len(t.fields) > maxCachedTemplateFields {
			d.evictLRU()
		}
		d.stats.TemplatesLearned++
		t.elem = d.order.PushFront(k)
		d.templates[k] = t
		d.templateFields += len(t.fields)
		return true
	case old.sameShape(t):
		// Refresh. Nothing to do to the template itself — keeping the existing
		// pointer avoids churning a slice that every in-flight record decode is
		// reading from — but it IS recent activity, so the LRU list moves on.
		d.order.MoveToFront(old.elem)
		return false
	default:
		d.stats.TemplatesReplaced++
		d.removeTemplate(k, false)
		for d.templateFields+len(t.fields) > maxCachedTemplateFields {
			d.evictLRU()
		}
		t.elem = d.order.PushFront(k)
		d.templates[k] = t
		d.templateFields += len(t.fields)
	}
	return true
}

// evictLRU removes the least-recently-used template — the back of d.order — to
// make room for a new key at the ceiling (#564). Callers hold d.mu and must
// call this only when d.templates is at capacity; it is a silent no-op on an
// empty cache (unreachable in practice, since store only calls it when full).
func (d *Decoder) evictLRU() {
	back := d.order.Back()
	if back == nil {
		return
	}
	key, _ := back.Value.(templateKey)
	d.removeTemplate(key, true)
}

func (d *Decoder) removeTemplate(key templateKey, evicted bool) {
	t, ok := d.templates[key]
	if !ok {
		return
	}
	if t.elem != nil {
		d.order.Remove(t.elem)
	}
	d.templateFields -= len(t.fields)
	delete(d.templates, key)
	if evicted {
		d.stats.TemplatesEvicted++
	}
}

// lookup returns the cached template for a data flowset, if one has been
// learned. Callers hold d.mu.
//
// A hit is activity: it moves the entry to the front of the LRU list (#564),
// so an observation domain that is actively sending data — but for whatever
// reason has not resent its template recently — is not the one evicted just
// because it went quiet on the template flowset alone.
func (d *Decoder) lookup(exporter netip.Addr, sourceID uint32, id uint16) (*template, bool) {
	t, ok := d.templates[templateKey{exporter: exporter, sourceID: sourceID, id: id}]
	// t.elem is nil only for a template inserted directly into the map rather
	// than through store() — every production path goes through store(), but a
	// handful of existing tests build a template literal to pin decode behavior
	// in isolation from the cache. Guard rather than require every such test to
	// know about the LRU list.
	if ok && t.elem != nil {
		d.order.MoveToFront(t.elem)
	}
	return t, ok
}
