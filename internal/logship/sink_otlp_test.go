package logship

import (
	"context"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// fakeExporter captures the records that would go on the wire, resource and all.
type fakeExporter struct {
	mu       sync.Mutex
	records  []sdklog.Record
	shutdown int
}

func (f *fakeExporter) Export(_ context.Context, records []sdklog.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, records...)
	return nil
}

func (f *fakeExporter) Shutdown(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shutdown++
	return nil
}

func (f *fakeExporter) ForceFlush(context.Context) error { return nil }

func (f *fakeExporter) exported() []sdklog.Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sdklog.Record(nil), f.records...)
}

// newTestSink builds a sink over a fake exporter, bypassing the endpoint plumbing.
func newTestSink(exp sdklog.Exporter) *otlpSink {
	return &otlpSink{
		exporter:  exp,
		base:      baseLogAttributes("opnsense-exporter", "v1.2.3", "opnsense"),
		providers: make(map[resourceKey]*resourceLogger),
	}
}

// resourceAttrs reads a record's resource back as a map.
func resourceAttrs(r sdklog.Record) map[string]string {
	out := map[string]string{}
	res := r.Resource()
	if res == nil {
		return out
	}
	for _, kv := range res.Attributes() {
		out[string(kv.Key)] = kv.Value.String()
	}
	return out
}

// recordAttrs reads a record's log attributes back as a map.
func recordAttrs(r sdklog.Record) map[string]string {
	out := map[string]string{}
	r.WalkAttributes(func(kv otellog.KeyValue) bool {
		out[kv.Key] = kv.Value.String()
		return true
	})
	return out
}

// shipAndDrain emits a batch and flushes it through to the exporter.
func shipAndDrain(t *testing.T, s *otlpSink, batch []Entry) {
	t.Helper()
	if err := s.Emit(context.Background(), batch); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// THE POINT OF #263: Loki can only promote a RESOURCE attribute to an index label.
// `source` and `subsystem` must therefore leave the record and land on the resource
// — otherwise no tenant config on earth can index them.
func TestOTLPSink_SourceAndSubsystemAreResourceAttributes(t *testing.T) {
	exp := &fakeExporter{}
	s := newTestSink(exp)

	shipAndDrain(t, s, []Entry{{
		Source: "syslog",
		Record: Record{
			Body: "a block",
			Attributes: map[string]string{
				"opnsense.subsystem": "firewall",
				"program":            "filterlog",
				"src_ip":             "10.0.0.6",
			},
		},
	}})

	got := exp.exported()
	if len(got) != 1 {
		t.Fatalf("exported %d records, want 1", len(got))
	}
	res := resourceAttrs(got[0])
	for k, want := range map[string]string{
		"opnsense.source":     "syslog",
		"opnsense.subsystem":  "firewall",
		"service.name":        "opnsense-exporter",
		"service.instance.id": "opnsense",
		"service.version":     "v1.2.3",
	} {
		if res[k] != want {
			t.Errorf("resource attribute %q = %q, want %q", k, res[k], want)
		}
	}

	// They must NOT also remain on the record: that would duplicate them into
	// structured metadata alongside the label.
	rec := recordAttrs(got[0])
	for _, k := range []string{"opnsense.source", "opnsense.subsystem"} {
		if v, dup := rec[k]; dup {
			t.Errorf("%q was duplicated onto the record as %q; it belongs only on the resource", k, v)
		}
	}

	// High-cardinality data must stay on the record, where it can never be promoted.
	if rec["src_ip"] != "10.0.0.6" {
		t.Errorf("src_ip = %q, want it on the record as structured metadata", rec["src_ip"])
	}
	if _, leaked := res["src_ip"]; leaked {
		t.Error("src_ip reached the RESOURCE — a tenant promoting resource attributes would index it")
	}
	// `program` comes off the syslog wire (any process can pick its own tag via
	// logger(1)), so it is deliberately NOT promotable.
	if _, leaked := res["program"]; leaked {
		t.Error("program reached the resource; it is wire-derived and must stay unpromotable")
	}
}

// One resource per distinct (source, subsystem) — and exactly one, reused.
func TestOTLPSink_PartitionsResourcesBySourceAndSubsystem(t *testing.T) {
	exp := &fakeExporter{}
	s := newTestSink(exp)

	batch := []Entry{
		{Source: "syslog", Record: Record{Body: "1", Attributes: map[string]string{"opnsense.subsystem": "firewall"}}},
		{Source: "syslog", Record: Record{Body: "2", Attributes: map[string]string{"opnsense.subsystem": "firewall"}}},
		{Source: "syslog", Record: Record{Body: "3", Attributes: map[string]string{"opnsense.subsystem": "dns"}}},
		{Source: "unbound", Record: Record{Body: "4"}}, // a source with no subsystem
	}
	if err := s.Emit(context.Background(), batch); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if n := len(s.providers); n != 3 {
		t.Fatalf("built %d providers, want 3 (syslog/firewall, syslog/dns, unbound/-)", n)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// The subsystem-less source must carry no empty subsystem attribute at all.
	for _, r := range exp.exported() {
		res := resourceAttrs(r)
		if res["opnsense.source"] == "unbound" {
			if v, present := res["opnsense.subsystem"]; present {
				t.Errorf("unbound carried subsystem=%q; an absent subsystem must be absent, not empty", v)
			}
		}
	}
}

// The cap is unreachable with today's closed key sets, but it must hold anyway: a
// future Source putting something wire-derived behind `subsystem` must degrade, not
// leak providers (nor, once promoted, explode Loki's label cardinality).
func TestOTLPSink_ResourceCountIsCapped(t *testing.T) {
	exp := &fakeExporter{}
	s := newTestSink(exp)

	batch := make([]Entry, 0, maxLogResources*4)
	for i := 0; i < maxLogResources*4; i++ {
		batch = append(batch, Entry{
			Source: "syslog",
			Record: Record{
				Body:       "x",
				Attributes: map[string]string{"opnsense.subsystem": "sub-" + string(rune('a'+i%26)) + string(rune('a'+i/26))},
			},
		})
	}
	if err := s.Emit(context.Background(), batch); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if n := len(s.providers); n > maxLogResources {
		t.Fatalf("built %d providers, over the cap of %d", n, maxLogResources)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	// Nothing may be dropped just because the cap was hit.
	if n := len(exp.exported()); n != len(batch) {
		t.Errorf("exported %d records, want all %d — the cap must degrade, never drop", n, len(batch))
	}
}

// Providers share one exporter. A provider's own Shutdown must NOT close it, or the
// siblings still draining would lose whatever they had queued.
func TestOTLPSink_SharedExporterClosesExactlyOnce(t *testing.T) {
	exp := &fakeExporter{}
	s := newTestSink(exp)

	shipAndDrain(t, s, []Entry{
		{Source: "syslog", Record: Record{Body: "1", Attributes: map[string]string{"opnsense.subsystem": "firewall"}}},
		{Source: "syslog", Record: Record{Body: "2", Attributes: map[string]string{"opnsense.subsystem": "dns"}}},
		{Source: "syslog", Record: Record{Body: "3", Attributes: map[string]string{"opnsense.subsystem": "auth"}}},
	})

	if n := len(exp.exported()); n != 3 {
		t.Errorf("exported %d records, want 3 — a sibling provider lost its queue to an early exporter shutdown", n)
	}
	exp.mu.Lock()
	defer exp.mu.Unlock()
	if exp.shutdown != 1 {
		t.Errorf("exporter Shutdown called %d times, want exactly 1", exp.shutdown)
	}
}

// baseLogAttributes must carry only identity. Anything else risks colliding with
// Loki's default promotion list and silently becoming a label.
func TestBaseLogAttributesAreIdentityOnly(t *testing.T) {
	got := baseLogAttributes("svc", "v1", "inst")
	want := map[attribute.Key]string{
		"service.name":        "svc",
		"service.version":     "v1",
		"service.instance.id": "inst",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d attributes, want %d: %v", len(got), len(want), got)
	}
	for _, kv := range got {
		if w, ok := want[kv.Key]; !ok || kv.Value.String() != w {
			t.Errorf("unexpected identity attribute %s=%s", kv.Key, kv.Value.String())
		}
	}
}
