package netflow

import (
	"net/netip"
	"testing"
)

// learnFrom is learnDatagram, but lets the caller pick the observation domain
// (exporter, source_id) a template is learned against — learnDatagram always
// uses testExporter and testHead's fixed source id, which is not enough to
// drive the per-exporter and per-source-id ceiling tests below.
func learnFrom(t *testing.T, d *Decoder, exporter netip.Addr, sourceID uint32, templateID uint16) {
	t.Helper()
	pkt := v9Datagram(v9Head{sourceID: sourceID, sysUp: 1000},
		templateFlowset(simpleTemplate(templateID)))
	if _, err := d.Decode(pkt, exporter, testNow); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
}

// An unauthenticated sender can mint arbitrary source ids, template ids, or (if
// it can reach the socket from several addresses) exporter identities. Whichever
// dimension it varies, the cache must never grow past its global ceiling — this
// is the direct regression test for the issue's validation, which inserted
// 20,000 templates with unique source ids and watched the map grow unbounded.
func TestTemplateCache_BoundedAcrossSourceIDs(t *testing.T) {
	d := New()
	const attempts = maxCachedTemplates * 5
	for i := 0; i < attempts; i++ {
		learnFrom(t, d, testExporter, uint32(i), 256)
	}
	if got := len(d.templates); got != maxCachedTemplates {
		t.Fatalf("len(d.templates) = %d, want exactly %d (the ceiling)", got, maxCachedTemplates)
	}
	s := d.Stats()
	if want := uint64(attempts) - maxCachedTemplates; s.TemplatesEvicted != want {
		t.Fatalf("TemplatesEvicted = %d, want %d", s.TemplatesEvicted, want)
	}
}

func TestTemplateCache_BoundedAcrossTemplateIDs(t *testing.T) {
	d := New()
	const attempts = maxCachedTemplates * 5
	for i := 0; i < attempts; i++ {
		// Template ids below firstDataFlowsetID (256) are rejected as malformed, so
		// walk the id space starting there.
		learnFrom(t, d, testExporter, 1, uint16(firstDataFlowsetID+i))
	}
	if got := len(d.templates); got != maxCachedTemplates {
		t.Fatalf("len(d.templates) = %d, want exactly %d (the ceiling)", got, maxCachedTemplates)
	}
}

func TestTemplateCache_BoundedAcrossExporters(t *testing.T) {
	d := New()
	const attempts = maxCachedTemplates * 5
	for i := 0; i < attempts; i++ {
		exporter := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		learnFrom(t, d, exporter, 1, 256)
	}
	if got := len(d.templates); got != maxCachedTemplates {
		t.Fatalf("len(d.templates) = %d, want exactly %d (the ceiling)", got, maxCachedTemplates)
	}
}

// The most likely way to break this: a naive capacity check that fires on
// EVERY store, including a refresh of a key already held. A legitimate sender
// re-sending its own template (ng_netflow does this every ~2 minutes, #346)
// must never evict another entry or be counted as new capacity consumed, even
// with the cache completely full.
func TestTemplateCache_RefreshAtCeilingDoesNotEvictOrConsumeCapacity(t *testing.T) {
	d := New()
	for i := 0; i < maxCachedTemplates; i++ {
		learnFrom(t, d, testExporter, uint32(i), 256)
	}
	if got := len(d.templates); got != maxCachedTemplates {
		t.Fatalf("setup: len(d.templates) = %d, want %d", got, maxCachedTemplates)
	}
	before := d.Stats()

	// Re-send the very first key learned (source id 0) — the one an LRU policy
	// would otherwise consider "oldest" and evict first.
	learnFrom(t, d, testExporter, 0, 256)

	after := d.Stats()
	if got := len(d.templates); got != maxCachedTemplates {
		t.Fatalf("len(d.templates) after refresh = %d, want unchanged %d", got, maxCachedTemplates)
	}
	if after.TemplatesEvicted != before.TemplatesEvicted {
		t.Fatalf("TemplatesEvicted grew from %d to %d on a same-key refresh", before.TemplatesEvicted, after.TemplatesEvicted)
	}
	if after.TemplatesLearned != before.TemplatesLearned {
		t.Fatalf("TemplatesLearned grew from %d to %d on a same-key refresh", before.TemplatesLearned, after.TemplatesLearned)
	}
	// The refreshed key must still be present and lookup-able — proof the
	// refresh landed on the EXISTING entry rather than being silently dropped
	// for want of capacity.
	if _, ok := d.lookup(testExporter, 0, 256); !ok {
		t.Fatal("refreshed key evicted or dropped instead of updated in place")
	}
}

// Eviction must be deterministic, not "whichever map iteration order Go
// happens to pick" — otherwise a test (and an operator) cannot reason about
// which observation domain loses its template. Touching a key (via a refresh
// or a data lookup) must count as recent activity, so an actively-used
// domain survives a flood of one-shot novel keys from elsewhere.
func TestTemplateCache_EvictsLeastRecentlyUsedFirst(t *testing.T) {
	d := New()
	for i := 0; i < maxCachedTemplates; i++ {
		learnFrom(t, d, testExporter, uint32(i), 256)
	}
	// Touch source id 0 so it is no longer the least-recently-used entry.
	if _, ok := d.lookup(testExporter, 0, 256); !ok {
		t.Fatal("setup: source id 0 not found before touching it")
	}
	// One more distinct key pushes the cache over budget by exactly one entry.
	learnFrom(t, d, testExporter, uint32(maxCachedTemplates), 256)

	if _, ok := d.lookup(testExporter, 0, 256); !ok {
		t.Fatal("recently-touched key (source id 0) was evicted; LRU should have spared it")
	}
	if _, ok := d.lookup(testExporter, 1, 256); ok {
		t.Fatal("source id 1 (untouched, second-oldest) should have been evicted, but is still cached")
	}
}

func TestMaxCachedTemplatesSaneBudget(t *testing.T) {
	if maxCachedTemplates <= 0 {
		t.Fatalf("maxCachedTemplates = %d, must be positive", maxCachedTemplates)
	}
}

func TestTemplateRejectsExcessiveFieldCountBeforeAllocation(t *testing.T) {
	fields := make([]tField, maxFieldsPerTemplate+1)
	for i := range fields {
		fields[i] = tField{typ: 900, length: 1}
	}
	pkt := v9Datagram(testHead(1000), templateFlowset(tDef{id: 256, fields: fields}))
	d := New()
	if _, err := d.Decode(pkt, testExporter, testNow); err == nil {
		t.Fatal("oversized template was accepted")
	}
	if len(d.templates) != 0 {
		t.Fatalf("oversized template retained %d entries", len(d.templates))
	}
}

func TestTemplateCacheBoundsAggregateFieldStorage(t *testing.T) {
	d := New()
	fields := make([]templateField, maxFieldsPerTemplate)
	for i := range fields {
		fields[i] = templateField{typ: 900, length: 1}
	}
	for i := 0; i < maxCachedTemplateFields/maxFieldsPerTemplate+10; i++ {
		d.store(templateKey{exporter: testExporter, sourceID: uint32(i), id: 256},
			&template{fields: append([]templateField(nil), fields...), recLen: len(fields)})
	}
	if d.templateFields > maxCachedTemplateFields {
		t.Fatalf("retained fields = %d, limit %d", d.templateFields, maxCachedTemplateFields)
	}
	if d.templateFields != sumTemplateFields(d.templates) {
		t.Fatalf("accounting = %d, actual %d", d.templateFields, sumTemplateFields(d.templates))
	}
}

func sumTemplateFields(templates map[templateKey]*template) int {
	total := 0
	for _, tmpl := range templates {
		total += len(tmpl.fields)
	}
	return total
}
