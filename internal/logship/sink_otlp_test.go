package logship

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/options"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	collogpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
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

// mustEmit asserts that Emit acknowledged the WHOLE batch, and returns the result.
// Most tests here are about record shape rather than delivery, and they should fail
// loudly if the delivery path quietly stopped acknowledging.
func mustEmit(t *testing.T, s *otlpSink, batch []Entry) SinkResult {
	t.Helper()
	res := s.Emit(context.Background(), batch)
	if len(res.Acked) != len(batch) {
		t.Fatalf("Emit acked %d of %d entries (rejected=%d retry=%d): %v",
			len(res.Acked), len(batch), len(res.Rejected), len(res.Retry), res.Err)
	}
	return res
}

// assertResultCoversBatch enforces the SinkResult contract: the three lists partition
// the batch, no entry lost and none counted twice. Every delivery counter downstream
// depends on this, so it is worth asserting on every outcome a test constructs.
func assertResultCoversBatch(t *testing.T, res SinkResult, batch []Entry) {
	t.Helper()
	got := len(res.Acked) + len(res.Rejected) + len(res.Retry)
	if got != len(batch) {
		t.Fatalf("SinkResult accounts for %d entries (acked=%d rejected=%d retry=%d), want all %d",
			got, len(res.Acked), len(res.Rejected), len(res.Retry), len(batch))
	}
	seen := make(map[string]int, len(batch))
	for _, list := range [][]Entry{res.Acked, res.Rejected, res.Retry} {
		for _, e := range list {
			seen[e.Record.Body]++
		}
	}
	for _, e := range batch {
		if n := seen[e.Record.Body]; n != 1 {
			t.Fatalf("entry %q appears %d times across the result lists, want exactly 1", e.Record.Body, n)
		}
	}
}

// entryBodies renders a list of entries as their record bodies, for readable diffs.
func entryBodies(entries []Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Record.Body)
	}
	return out
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
	mustEmit(t, s, batch)
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
	mustEmit(t, s, batch)
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
	mustEmit(t, s, batch)
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

// #475: the instrumentation scope name is a PER-LINE COST, not free metadata. Loki's
// OTLP handler appends it as structured metadata verbatim on every record, gated only
// on it being non-empty (pkg/loghttp/push/otlplabels/labels.go: `if scopeName :=
// scope.Name(); scopeName != ""`). The old value —
// "github.com/rknightion/opnsense-exporter/logship" — measured 57 B/line on the wire
// at exactly one distinct value across every family, which on the Zenarmor stream
// alone is ~140 MB/day of the same 46 bytes.
//
// It bought nothing: this binary ships logs from ONE scope, and service.name already
// identifies the producer. Empty is the only value Loki treats as "omit".
func TestOTLPSink_EmitsNoInstrumentationScopeName(t *testing.T) {
	exp := &fakeExporter{}
	s := newTestSink(exp)

	shipAndDrain(t, s, []Entry{{
		Source: "zenarmor",
		Record: Record{Body: "{}", Attributes: map[string]string{"opnsense.subsystem": "flow"}},
	}})

	got := exp.exported()
	if len(got) != 1 {
		t.Fatalf("exported %d records, want 1", len(got))
	}
	if name := got[0].InstrumentationScope().Name; name != "" {
		t.Errorf("instrumentation scope name = %q, want empty: Loki ships it as "+
			"structured metadata on every single line (#475)", name)
	}
}

// AttrAction must be hoisted onto the RESOURCE (so Loki can index it) and must not
// also be duplicated into the record's structured metadata.
func TestOTLPSink_HoistsActionOntoResource(t *testing.T) {
	exp := &fakeExporter{}
	s := newTestSink(exp)

	shipAndDrain(t, s, []Entry{{Source: "zenarmor", Record: Record{
		Body: "1",
		Attributes: map[string]string{
			AttrSubsystem: "flow",
			AttrAction:    ActionBlock,
			"src.ip":      "10.0.0.1",
		},
	}}})

	recs := exp.exported()
	if len(recs) != 1 {
		t.Fatalf("exported %d records, want 1", len(recs))
	}
	if got := resourceAttrs(recs[0])[AttrAction]; got != ActionBlock {
		t.Errorf("resource %s = %q, want %q", AttrAction, got, ActionBlock)
	}
	if _, present := recordAttrs(recs[0])[AttrAction]; present {
		t.Errorf("%s leaked into structured metadata; it lives only on the resource", AttrAction)
	}
	// Everything else still belongs on the record.
	if got := recordAttrs(recs[0])["src.ip"]; got != "10.0.0.1" {
		t.Errorf("src.ip = %q, want 10.0.0.1", got)
	}
}

// An unknown disposition must leave the attribute ABSENT, not present-and-empty.
// MapFilterlogAction returns "" for a verb it does not recognise (a NAT/rdr line),
// and opnsense_action="" would be a lie: it reads as a real value in LogQL.
func TestOTLPSink_UnsetActionIsAbsentNotEmpty(t *testing.T) {
	exp := &fakeExporter{}
	s := newTestSink(exp)

	shipAndDrain(t, s, []Entry{{Source: "syslog", Record: Record{
		Body:       "1",
		Attributes: map[string]string{AttrSubsystem: "firewall"},
	}}})

	recs := exp.exported()
	if len(recs) != 1 {
		t.Fatalf("exported %d records, want 1", len(recs))
	}
	if v, present := resourceAttrs(recs[0])[AttrAction]; present {
		t.Errorf("carried %s=%q; an unset action must be absent, not empty", AttrAction, v)
	}
}

// Action partitions the resource alongside source and subsystem.
func TestOTLPSink_PartitionsResourcesByAction(t *testing.T) {
	exp := &fakeExporter{}
	s := newTestSink(exp)

	batch := []Entry{
		{Source: "zenarmor", Record: Record{Body: "1", Attributes: map[string]string{AttrSubsystem: "flow", AttrAction: ActionPass}}},
		{Source: "zenarmor", Record: Record{Body: "2", Attributes: map[string]string{AttrSubsystem: "flow", AttrAction: ActionPass}}},
		{Source: "zenarmor", Record: Record{Body: "3", Attributes: map[string]string{AttrSubsystem: "flow", AttrAction: ActionBlock}}},
	}
	mustEmit(t, s, batch)
	if n := len(s.providers); n != 2 {
		t.Fatalf("built %d providers, want 2 (flow/pass, flow/block)", n)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// --- #473: device category and interface on the resource --------------------

// Both new keys must be hoisted onto the RESOURCE (the only place Loki can promote
// from) and must not also be duplicated into structured metadata under the same key.
// The lane's own verbatim `device.category` / `interface.name` are a DIFFERENT key
// space and must survive untouched, so queries written against them keep working
// before — and after — the tenant opts into promotion.
func TestOTLPSink_HoistsDeviceCategoryAndInterfaceOntoResource(t *testing.T) {
	exp := &fakeExporter{}
	s := newTestSink(exp)

	shipAndDrain(t, s, []Entry{{Source: "zenarmor", Record: Record{
		Body: "1",
		Attributes: map[string]string{
			AttrSubsystem:      "flow",
			AttrAction:         ActionPass,
			AttrDeviceCategory: "laptop",
			AttrInterface:      "IOT",
			"device.category":  "laptop",
			"interface.name":   "IOT",
			"device.name":      "some-host",
		},
	}}})

	recs := exp.exported()
	if len(recs) != 1 {
		t.Fatalf("exported %d records, want 1", len(recs))
	}
	res, rec := resourceAttrs(recs[0]), recordAttrs(recs[0])

	for key, want := range map[string]string{AttrDeviceCategory: "laptop", AttrInterface: "IOT"} {
		if got := res[key]; got != want {
			t.Errorf("resource %s = %q, want %q", key, got, want)
		}
		if _, present := rec[key]; present {
			t.Errorf("%s leaked into structured metadata; it lives only on the resource", key)
		}
	}
	// The lane's verbatim keys are untouched — this change is query-neutral.
	for key, want := range map[string]string{
		"device.category": "laptop",
		"interface.name":  "IOT",
		"device.name":     "some-host",
	} {
		if got := rec[key]; got != want {
			t.Errorf("structured metadata %s = %q, want %q — existing queries must keep working", key, got, want)
		}
	}
}

// Absent, not present-and-empty. Syslog records carry neither field, and
// opnsense_device_category="" reads as a real value in LogQL.
func TestOTLPSink_UnsetDeviceCategoryAndInterfaceAreAbsent(t *testing.T) {
	exp := &fakeExporter{}
	s := newTestSink(exp)

	shipAndDrain(t, s, []Entry{{Source: "syslog", Record: Record{
		Body:       "1",
		Attributes: map[string]string{AttrSubsystem: "firewall"},
	}}})

	recs := exp.exported()
	if len(recs) != 1 {
		t.Fatalf("exported %d records, want 1", len(recs))
	}
	for _, key := range []string{AttrDeviceCategory, AttrInterface} {
		if v, present := resourceAttrs(recs[0])[key]; present {
			t.Errorf("carried %s=%q; an unset field must be absent, not empty", key, v)
		}
	}
}

// Each new key partitions the resource independently of the others.
func TestOTLPSink_PartitionsResourcesByDeviceCategoryAndInterface(t *testing.T) {
	exp := &fakeExporter{}
	s := newTestSink(exp)

	attrs := func(cat, iface string) map[string]string {
		return map[string]string{
			AttrSubsystem: "flow", AttrAction: ActionPass,
			AttrDeviceCategory: cat, AttrInterface: iface,
		}
	}
	batch := []Entry{
		{Source: "zenarmor", Record: Record{Body: "1", Attributes: attrs("laptop", "LAN")}},
		{Source: "zenarmor", Record: Record{Body: "2", Attributes: attrs("laptop", "LAN")}},
		{Source: "zenarmor", Record: Record{Body: "3", Attributes: attrs("laptop", "IOT")}},
		{Source: "zenarmor", Record: Record{Body: "4", Attributes: attrs("camera", "IOT")}},
	}
	mustEmit(t, s, batch)
	if n := len(s.providers); n != 3 {
		t.Fatalf("built %d providers, want 3 (laptop/LAN, laptop/IOT, camera/IOT)", n)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// observedResourceCombos is the number of DISTINCT resource keys measured on the
// live box over one hour with both #473 fields on the key. The progression that
// forced the cap change is on #473: 16 today, 37 with interface alone, 44 with
// device category alone, 79 with both.
//
// It is pinned here rather than left implicit because the failure mode it guards is
// silent: past maxLogResources the sink degrades to the base resource and the record
// ships with NO opnsense.* labels at all, so overshooting the cap destroys the three
// labels that already work instead of merely failing to add two. A future key with a
// wider vocabulary must trip THIS test, in CI, rather than the live cap.
const observedResourceCombos = 79

func TestOTLPSink_ResourceKeyBudgetHasHeadroomOverObserved(t *testing.T) {
	// 3x the measured steady state. Anything less and normal churn — a new VLAN, a
	// device category Zenarmor has not classified before — walks into the cap.
	if want := 3 * observedResourceCombos; maxLogResources < want {
		t.Fatalf("maxLogResources = %d, want at least %d (3x the %d combinations measured live)",
			maxLogResources, want, observedResourceCombos)
	}

	// And the measured shape must actually fit, undegraded: every key gets its own
	// provider and nothing collapses onto the base resource.
	exp := &fakeExporter{}
	s := newTestSink(exp)
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

	batch := make([]Entry, 0, observedResourceCombos)
	for i := range observedResourceCombos {
		batch = append(batch, Entry{Source: "zenarmor", Record: Record{
			Body: strconv.Itoa(i),
			Attributes: map[string]string{
				AttrSubsystem:      "flow",
				AttrAction:         ActionPass,
				AttrDeviceCategory: "cat-" + strconv.Itoa(i%9),
				AttrInterface:      "if-" + strconv.Itoa(i/9),
			},
		}})
	}
	mustEmit(t, s, batch)
	if n := len(s.providers); n != observedResourceCombos {
		t.Fatalf("built %d providers for %d distinct keys — the measured live shape must fit undegraded",
			n, observedResourceCombos)
	}
	if _, degraded := s.providers[resourceKey{}]; degraded {
		t.Fatal("collapsed onto the base resource; every record would ship with no opnsense.* labels")
	}
}

// --- #392: resource- and protocol-aware delivery outcomes -------------------

// scriptedOutcome is what a scripted exporter should report for one partition.
type scriptedOutcome struct {
	outcome  deliveryOutcome
	rejected int64
	err      error
}

// scriptedCall records one Export the sink made: which resource partition it carried
// (identified by opnsense.subsystem, which is unique per partition in these tests) and
// the record bodies in it.
type scriptedCall struct {
	subsystem string
	bodies    []string
}

// scriptedExporter stands in for the transport hook: it writes a chosen outcome into
// the deliveryObservation on the export context, exactly as observingTransport and
// observingUnaryInterceptor do against a real endpoint. Partitions with no script
// entry succeed silently, which is the "no observation, no error" case.
type scriptedExporter struct {
	mu       sync.Mutex
	script   map[string]scriptedOutcome
	calls    []scriptedCall
	shutdown int
}

func (e *scriptedExporter) Export(ctx context.Context, recs []sdklog.Record) error {
	if len(recs) == 0 {
		return nil
	}
	sub := resourceAttrs(recs[0])["opnsense.subsystem"]
	call := scriptedCall{subsystem: sub}
	for _, r := range recs {
		call.bodies = append(call.bodies, r.Body().AsString())
	}

	e.mu.Lock()
	e.calls = append(e.calls, call)
	o, scripted := e.script[sub]
	e.mu.Unlock()

	if !scripted {
		return nil
	}
	deliveryObservationFrom(ctx).record(o.outcome, o.rejected)
	return o.err
}

func (e *scriptedExporter) Shutdown(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.shutdown++
	return nil
}

func (e *scriptedExporter) ForceFlush(context.Context) error { return nil }

func (e *scriptedExporter) seen() []scriptedCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]scriptedCall(nil), e.calls...)
}

// countFor returns how many records the exporter was handed for a subsystem, across
// every Export it saw. Two attempts carrying the same record show up as 2 — which is
// exactly the duplication this issue is about.
func (e *scriptedExporter) countFor(subsystem string) int {
	n := 0
	for _, c := range e.seen() {
		if c.subsystem == subsystem {
			n += len(c.bodies)
		}
	}
	return n
}

func entry(source, subsystem, body string) Entry {
	return Entry{Source: source, Record: Record{
		Body:       body,
		Attributes: map[string]string{AttrSubsystem: subsystem},
	}}
}

// THE HEADLINE ACCEPTANCE CRITERION OF #392. One logical batch spans two resource
// partitions. The first is acknowledged, the second fails transiently. The retry must
// carry the SECOND ONLY: resending the acknowledged partition duplicates firewall/IDS
// events downstream, where a duplicate is indistinguishable from a real repeat.
//
// Against the pre-#392 sink this fails immediately — Emit returned one error for the
// whole batch, so the pipeline resent every entry and "firewall" reached the wire twice.
func TestOTLPSink_AcknowledgedPartitionIsNotResentWhenSiblingFails(t *testing.T) {
	exp := &scriptedExporter{script: map[string]scriptedOutcome{
		"dns": {outcome: outcomeRetryable, err: errors.New("503 service unavailable")},
	}}
	s := newTestSink(exp)
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

	batch := []Entry{
		entry("syslog", "firewall", "fw-1"),
		entry("syslog", "dns", "dns-1"),
		entry("syslog", "firewall", "fw-2"),
	}

	res := s.Emit(context.Background(), batch)
	assertResultCoversBatch(t, res, batch)

	if got := entryBodies(res.Acked); !slices.Equal(got, []string{"fw-1", "fw-2"}) {
		t.Fatalf("acked = %v, want the firewall partition [fw-1 fw-2]", got)
	}
	if got := entryBodies(res.Retry); !slices.Equal(got, []string{"dns-1"}) {
		t.Fatalf("retry = %v, want the failed sibling only [dns-1]", got)
	}
	if len(res.Rejected) != 0 {
		t.Fatalf("rejected = %v, want none (a 503 is transient, not a refusal)", entryBodies(res.Rejected))
	}

	// The pipeline re-Emits exactly res.Retry. Nothing may put the firewall partition
	// back on the wire.
	exp.mu.Lock()
	exp.script = nil // the endpoint recovered
	exp.mu.Unlock()
	res2 := s.Emit(context.Background(), res.Retry)
	assertResultCoversBatch(t, res2, res.Retry)
	if got := entryBodies(res2.Acked); !slices.Equal(got, []string{"dns-1"}) {
		t.Fatalf("retry attempt acked %v, want [dns-1]", got)
	}

	if n := exp.countFor("firewall"); n != 2 {
		t.Fatalf("the firewall partition reached the wire with %d records over both attempts, want 2 "+
			"(each record exactly once) — an acknowledged partition was resent", n)
	}
	if n := exp.countFor("dns"); n != 2 {
		t.Fatalf("the dns partition reached the wire %d times, want 2 (one failed attempt + one retry)", n)
	}
}

// Partition flush order must be deterministic, or which partitions had already reached
// the wire when a sibling failed varies run to run — untestable, and unreproducible in
// an incident. Go map iteration is randomised per range, so an unsorted implementation
// fails this quickly across repetitions.
func TestOTLPSink_FlushesPartitionsInDeterministicKeyOrder(t *testing.T) {
	want := []string{"auth", "dns", "firewall", "flow"}
	for i := 0; i < 25; i++ {
		exp := &scriptedExporter{}
		s := newTestSink(exp)
		batch := []Entry{
			entry("syslog", "flow", "d"),
			entry("syslog", "firewall", "c"),
			entry("syslog", "auth", "a"),
			entry("syslog", "dns", "b"),
		}
		mustEmit(t, s, batch)
		if err := s.Shutdown(context.Background()); err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
		got := make([]string, 0, len(want))
		for _, c := range exp.seen() {
			got = append(got, c.subsystem)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("run %d flushed partitions in order %v, want sorted %v", i, got, want)
		}
	}
}

// sortResourceKeys is the ordering itself: source first, then subsystem, then action.
func TestSortResourceKeys(t *testing.T) {
	keys := []resourceKey{
		{source: "syslog", subsystem: "flow", action: "pass"},
		{source: "syslog", subsystem: "flow", action: "block"},
		{source: "netflow", subsystem: "flow"},
		{source: "syslog", subsystem: "auth"},
	}
	sortResourceKeys(keys)
	want := []resourceKey{
		{source: "netflow", subsystem: "flow"},
		{source: "syslog", subsystem: "auth"},
		{source: "syslog", subsystem: "flow", action: "block"},
		{source: "syslog", subsystem: "flow", action: "pass"},
	}
	if !slices.Equal(keys, want) {
		t.Fatalf("sorted = %v, want %v", keys, want)
	}
}

// A populated partial success is TERMINAL for that exact request: the OTLP spec forbids
// resending it, because the server already accepted the records it did not reject. The
// accepted share counts shipped, the rejected COUNT counts dropped, and none of it goes
// back on the wire.
func TestOTLPSink_PartialSuccessIsTerminalAndCountSplit(t *testing.T) {
	exp := &scriptedExporter{script: map[string]scriptedOutcome{
		"firewall": {outcome: outcomePartial, rejected: 2, err: errors.New("partial success")},
	}}
	s := newTestSink(exp)
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

	batch := []Entry{
		entry("syslog", "firewall", "a"),
		entry("syslog", "firewall", "b"),
		entry("syslog", "firewall", "c"),
		entry("syslog", "firewall", "d"),
		entry("syslog", "firewall", "e"),
	}
	res := s.Emit(context.Background(), batch)
	assertResultCoversBatch(t, res, batch)

	if len(res.Retry) != 0 {
		t.Fatalf("retry = %v; a populated partial_success must NEVER be resent", entryBodies(res.Retry))
	}
	if len(res.Acked) != 3 {
		t.Fatalf("acked %d records, want 3 (5 sent, 2 rejected)", len(res.Acked))
	}
	if len(res.Rejected) != 2 {
		t.Fatalf("rejected %d records, want the 2 the server reported", len(res.Rejected))
	}
}

// A server reporting more rejections than the request contained is out of contract.
// Clamp it: the alternative under-runs the split and counts a negative delivery.
func TestOTLPSink_PartialSuccessRejectedCountIsClamped(t *testing.T) {
	for _, tc := range []struct {
		name         string
		rejected     int64
		wantAcked    int
		wantRejected int
	}{
		{"more than sent", 99, 0, 2},
		{"negative", -5, 2, 0},
		{"exactly all", 2, 0, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exp := &scriptedExporter{script: map[string]scriptedOutcome{
				"firewall": {outcome: outcomePartial, rejected: tc.rejected, err: errors.New("partial")},
			}}
			s := newTestSink(exp)
			t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

			batch := []Entry{entry("syslog", "firewall", "a"), entry("syslog", "firewall", "b")}
			res := s.Emit(context.Background(), batch)
			assertResultCoversBatch(t, res, batch)
			if len(res.Acked) != tc.wantAcked || len(res.Rejected) != tc.wantRejected {
				t.Fatalf("acked=%d rejected=%d, want acked=%d rejected=%d",
					len(res.Acked), len(res.Rejected), tc.wantAcked, tc.wantRejected)
			}
			if len(res.Retry) != 0 {
				t.Fatalf("retry = %v, want none", entryBodies(res.Retry))
			}
		})
	}
}

// A permanent protocol response is ONE attempt, then counted and dropped. Retrying it
// up to --logs.ship-max-attempts (10 by default) is ten identical refusals for nothing.
func TestOTLPSink_PermanentResponseIsRejectedNotRetried(t *testing.T) {
	exp := &scriptedExporter{script: map[string]scriptedOutcome{
		"firewall": {outcome: outcomePermanent, err: errors.New("400 bad request")},
	}}
	s := newTestSink(exp)
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

	batch := []Entry{entry("syslog", "firewall", "a"), entry("syslog", "firewall", "b")}
	res := s.Emit(context.Background(), batch)
	assertResultCoversBatch(t, res, batch)

	if len(res.Rejected) != 2 {
		t.Fatalf("rejected %d, want both records", len(res.Rejected))
	}
	if len(res.Retry) != 0 || len(res.Acked) != 0 {
		t.Fatalf("retry=%v acked=%v, want neither", entryBodies(res.Retry), entryBodies(res.Acked))
	}
}

// A failure with no observed wire outcome (marshalling, an oversize request, a bare
// exporter) stays retryable: the safer of the two mistakes is one bounded extra attempt,
// not discarding records we cannot prove were refused.
func TestOTLPSink_UnclassifiedFailureIsRetryable(t *testing.T) {
	s := newTestSink(erroringExporter{})
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

	batch := []Entry{entry("syslog", "firewall", "a")}
	res := s.Emit(context.Background(), batch)
	assertResultCoversBatch(t, res, batch)
	if len(res.Retry) != 1 {
		t.Fatalf("retry=%v, want the batch back for another attempt", entryBodies(res.Retry))
	}
	if res.Err == nil {
		t.Fatal("Err is nil; the underlying failure must still be reported for logging")
	}
}

// An empty batch must not invent an export or a partition.
func TestOTLPSink_EmptyBatchIsANoOp(t *testing.T) {
	exp := &scriptedExporter{}
	s := newTestSink(exp)
	res := s.Emit(context.Background(), nil)
	if len(res.Acked)+len(res.Rejected)+len(res.Retry) != 0 || res.Err != nil {
		t.Fatalf("empty batch produced %+v, want a zero result", res)
	}
	if n := len(exp.seen()); n != 0 {
		t.Fatalf("exporter saw %d exports for an empty batch, want 0", n)
	}
}

// --- #392: the classification seam against REAL transports ------------------
//
// The tests above script the outcome directly. These ones drive the pinned exporters
// against real servers, which is the only way to prove the seam itself works: that
// otlploghttp.WithHTTPClient and otlploggrpc.WithDialOption are actually honoured, and
// that a status code / partial-success payload really does reach classifyPartition
// without anyone parsing vendor error text.

// newSinkOverEndpoint builds a real OTLP exporter pointed at endpoint and wraps it in
// the sink, exactly as production does.
func newSinkOverEndpoint(t *testing.T, protocol, endpoint string) *otlpSink {
	t.Helper()
	exp, err := newLogExporter(context.Background(), &options.OTLPConfig{
		Protocol: protocol,
		Endpoint: endpoint,
		Insecure: true,
	})
	if err != nil {
		t.Fatalf("newLogExporter(%s): %v", protocol, err)
	}
	s := &otlpSink{
		exporter:  exp,
		base:      baseLogAttributes("opnsense-exporter", "v1.2.3", "opnsense"),
		providers: make(map[resourceKey]*resourceLogger),
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	return s
}

// partialSuccessBody is a protobuf ExportLogsServiceResponse carrying a populated
// partial_success, i.e. what an endpoint sends when it accepted the request but threw
// away some records.
func partialSuccessBody(t *testing.T, rejected int64, msg string) []byte {
	t.Helper()
	body, err := proto.Marshal(&collogpb.ExportLogsServiceResponse{
		PartialSuccess: &collogpb.ExportLogsPartialSuccess{
			RejectedLogRecords: rejected,
			ErrorMessage:       msg,
		},
	})
	if err != nil {
		t.Fatalf("marshal partial success: %v", err)
	}
	return body
}

// One HTTP status per delivery class, end to end through the pinned exporter.
func TestOTLPSink_HTTPStatusClassification(t *testing.T) {
	for _, tc := range []struct {
		name         string
		status       int
		body         func(*testing.T) []byte
		contentType  string
		wantAcked    int
		wantRejected int
		wantRetry    int
		// wantRequests is how many times the endpoint should be hit for ONE Emit. The
		// SDK applies its own retry to the transient classes, so only the terminal ones
		// are pinned to exactly 1.
		wantOneRequest bool
	}{
		{
			name: "200 empty body is a clean accept", status: 200,
			wantAcked: 3, wantOneRequest: true,
		},
		{
			name: "200 with populated partial_success is terminal", status: 200,
			contentType: "application/x-protobuf",
			body:        func(t *testing.T) []byte { return partialSuccessBody(t, 1, "1 record rejected") },
			wantAcked:   2, wantRejected: 1, wantOneRequest: true,
		},
		{
			name: "200 with an error message but zero rejections is still terminal", status: 200,
			contentType: "application/x-protobuf",
			body:        func(t *testing.T) []byte { return partialSuccessBody(t, 0, "some records were mangled") },
			wantAcked:   3, wantOneRequest: true,
		},
		{
			name: "200 with an EMPTY partial_success is a clean accept", status: 200,
			contentType: "application/x-protobuf",
			body:        func(t *testing.T) []byte { return partialSuccessBody(t, 0, "") },
			wantAcked:   3, wantOneRequest: true,
		},
		{
			name: "400 is permanent", status: 400,
			wantRejected: 3, wantOneRequest: true,
		},
		{
			name: "401 is permanent", status: 401,
			wantRejected: 3, wantOneRequest: true,
		},
		{name: "429 is transient", status: 429, wantRetry: 3},
		{name: "502 is transient", status: 502, wantRetry: 3},
		{name: "503 is transient", status: 503, wantRetry: 3},
		{name: "504 is transient", status: 504, wantRetry: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				if tc.contentType != "" {
					w.Header().Set("Content-Type", tc.contentType)
				}
				w.WriteHeader(tc.status)
				if tc.body != nil {
					_, _ = w.Write(tc.body(t))
				}
			}))
			defer srv.Close()

			s := newSinkOverEndpoint(t, "http/protobuf", srv.URL)
			batch := []Entry{
				entry("syslog", "firewall", "a"),
				entry("syslog", "firewall", "b"),
				entry("syslog", "firewall", "c"),
			}
			emitCtx := context.Background()
			if tc.wantRetry > 0 {
				var cancel context.CancelFunc
				emitCtx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
				defer cancel()
			}
			res := s.Emit(emitCtx, batch)
			assertResultCoversBatch(t, res, batch)

			if len(res.Acked) != tc.wantAcked || len(res.Rejected) != tc.wantRejected || len(res.Retry) != tc.wantRetry {
				t.Fatalf("HTTP %d: acked=%d rejected=%d retry=%d, want acked=%d rejected=%d retry=%d (err=%v)",
					tc.status, len(res.Acked), len(res.Rejected), len(res.Retry),
					tc.wantAcked, tc.wantRejected, tc.wantRetry, res.Err)
			}
			if tc.wantOneRequest && requests.Load() != 1 {
				t.Fatalf("HTTP %d: endpoint hit %d times for one Emit, want exactly 1 — "+
					"a terminal response must never be repeated on the wire", tc.status, requests.Load())
			}
		})
	}
}

// The observing RoundTripper reads the response body to look for a partial success. It
// must put the bytes back, or the SDK parses an empty body and the classification would
// only work by accident.
func TestObservingTransport_LeavesTheBodyReadableForTheSDK(t *testing.T) {
	want := partialSuccessBody(t, 7, "seven rejected")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(want)
	}))
	defer srv.Close()

	obs := &deliveryObservation{}
	client := &http.Client{Transport: &observingTransport{}}
	req, err := http.NewRequestWithContext(withDeliveryObservation(context.Background(), obs),
		http.MethodPost, srv.URL, http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body after the hook consumed it: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("body seen by the SDK is %d bytes, want the original %d — the hook ate it", len(got), len(want))
	}
	if outcome, rejected := obs.result(); outcome != outcomePartial || rejected != 7 {
		t.Fatalf("observation = (%v, %d), want (outcomePartial, 7)", outcome, rejected)
	}
}

// A transport that never reaches a server is transient, not a refusal: the endpoint may
// be restarting.
func TestObservingTransport_ConnectionFailureIsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening now

	obs := &deliveryObservation{}
	client := &http.Client{Transport: &observingTransport{}}
	req, err := http.NewRequestWithContext(withDeliveryObservation(context.Background(), obs),
		http.MethodPost, url, http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if resp, derr := client.Do(req); derr == nil {
		resp.Body.Close()
		t.Skip("something answered on the closed port; cannot exercise the failure path")
	}
	if outcome, _ := obs.result(); outcome != outcomeRetryable {
		t.Fatalf("observation = %v, want outcomeRetryable for a dead endpoint", outcome)
	}
}

// scriptedLogsServer is a real OTLP/gRPC logs endpoint whose reply is chosen per test.
type scriptedLogsServer struct {
	collogpb.UnimplementedLogsServiceServer
	requests atomic.Int64
	resp     *collogpb.ExportLogsServiceResponse
	err      error
}

func (s *scriptedLogsServer) Export(
	context.Context, *collogpb.ExportLogsServiceRequest,
) (*collogpb.ExportLogsServiceResponse, error) {
	s.requests.Add(1)
	if s.err != nil {
		return nil, s.err
	}
	if s.resp != nil {
		return s.resp, nil
	}
	return &collogpb.ExportLogsServiceResponse{}, nil
}

// startLogsGRPCServer runs srv on a loopback port and returns its endpoint URL.
func startLogsGRPCServer(t *testing.T, srv collogpb.LogsServiceServer) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	g := grpc.NewServer()
	collogpb.RegisterLogsServiceServer(g, srv)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = g.Serve(lis)
	}()
	t.Cleanup(func() {
		g.Stop()
		<-done
	})
	return "http://" + lis.Addr().String()
}

// The gRPC arm of the seam, end to end through the pinned exporter: one code per class,
// plus partial success.
func TestOTLPSink_GRPCStatusClassification(t *testing.T) {
	for _, tc := range []struct {
		name         string
		resp         *collogpb.ExportLogsServiceResponse
		err          error
		wantAcked    int
		wantRejected int
		wantRetry    int
		wantOneCall  bool
	}{
		{name: "OK is a clean accept", wantAcked: 3, wantOneCall: true},
		{
			name: "populated partial_success is terminal",
			resp: &collogpb.ExportLogsServiceResponse{PartialSuccess: &collogpb.ExportLogsPartialSuccess{
				RejectedLogRecords: 2, ErrorMessage: "2 rejected",
			}},
			wantAcked: 1, wantRejected: 2, wantOneCall: true,
		},
		{
			name:      "empty partial_success is a clean accept",
			resp:      &collogpb.ExportLogsServiceResponse{PartialSuccess: &collogpb.ExportLogsPartialSuccess{}},
			wantAcked: 3, wantOneCall: true,
		},
		{
			name:         "InvalidArgument is permanent",
			err:          status.Error(codes.InvalidArgument, "malformed request"),
			wantRejected: 3, wantOneCall: true,
		},
		{
			name:         "Unauthenticated is permanent",
			err:          status.Error(codes.Unauthenticated, "bad credentials"),
			wantRejected: 3, wantOneCall: true,
		},
		{
			name:         "PermissionDenied is permanent",
			err:          status.Error(codes.PermissionDenied, "no"),
			wantRejected: 3, wantOneCall: true,
		},
		{
			name:      "Unavailable is transient",
			err:       status.Error(codes.Unavailable, "try later"),
			wantRetry: 3,
		},
		{
			name:      "DataLoss is transient",
			err:       status.Error(codes.DataLoss, "stream broken"),
			wantRetry: 3,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := &scriptedLogsServer{resp: tc.resp, err: tc.err}
			s := newSinkOverEndpoint(t, "grpc", startLogsGRPCServer(t, srv))

			batch := []Entry{
				entry("syslog", "firewall", "a"),
				entry("syslog", "firewall", "b"),
				entry("syslog", "firewall", "c"),
			}
			emitCtx := context.Background()
			if tc.wantRetry > 0 {
				var cancel context.CancelFunc
				emitCtx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
				defer cancel()
			}
			res := s.Emit(emitCtx, batch)
			assertResultCoversBatch(t, res, batch)

			if len(res.Acked) != tc.wantAcked || len(res.Rejected) != tc.wantRejected || len(res.Retry) != tc.wantRetry {
				t.Fatalf("acked=%d rejected=%d retry=%d, want acked=%d rejected=%d retry=%d (err=%v)",
					len(res.Acked), len(res.Rejected), len(res.Retry),
					tc.wantAcked, tc.wantRejected, tc.wantRetry, res.Err)
			}
			if tc.wantOneCall && srv.requests.Load() != 1 {
				t.Fatalf("endpoint called %d times for one Emit, want exactly 1 — "+
					"a terminal response must never be repeated on the wire", srv.requests.Load())
			}
		})
	}
}

// A retryable HTTP reply must remain inside the real exporter: once the endpoint
// recovers, Emit reports one acknowledgement rather than handing the batch back to
// the pipeline for a second logical delivery attempt. This catches a disabled or
// lost exporter retry/recovery path.
func TestOTLPSink_HTTPTransientThenRecoveryAcknowledgesOnce(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := newSinkOverEndpoint(t, "http/protobuf", srv.URL)
	batch := []Entry{entry("syslog", "firewall", "recovery")}
	res := s.Emit(context.Background(), batch)
	assertResultCoversBatch(t, res, batch)

	if len(res.Acked) != 1 || len(res.Rejected) != 0 || len(res.Retry) != 0 || res.Err != nil {
		t.Fatalf("recovered HTTP export = acked=%d rejected=%d retry=%d err=%v, want one acknowledgement only",
			len(res.Acked), len(res.Rejected), len(res.Retry), res.Err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("HTTP wire attempts = %d, want exactly 2 (503 then recovery)", got)
	}
}

// recoveringLogsServer is a real OTLP/gRPC endpoint that returns Unavailable for
// its first request and accepts its second. It keeps the recovery sequence at the
// protocol boundary instead of scripting an exporter outcome.
type recoveringLogsServer struct {
	collogpb.UnimplementedLogsServiceServer
	requests atomic.Int64
}

func (s *recoveringLogsServer) Export(
	context.Context, *collogpb.ExportLogsServiceRequest,
) (*collogpb.ExportLogsServiceResponse, error) {
	if s.requests.Add(1) == 1 {
		return nil, status.Error(codes.Unavailable, "try later")
	}
	return &collogpb.ExportLogsServiceResponse{}, nil
}

// A retryable gRPC status must recover within the pinned exporter exactly as HTTP
// does, with one logical acknowledgement and the two bounded wire attempts visible.
// This catches a disabled or lost exporter retry/recovery path.
func TestOTLPSink_GRPCTransientThenRecoveryAcknowledgesOnce(t *testing.T) {
	srv := &recoveringLogsServer{}
	s := newSinkOverEndpoint(t, "grpc", startLogsGRPCServer(t, srv))
	batch := []Entry{entry("syslog", "firewall", "recovery")}
	res := s.Emit(context.Background(), batch)
	assertResultCoversBatch(t, res, batch)

	if len(res.Acked) != 1 || len(res.Rejected) != 0 || len(res.Retry) != 0 || res.Err != nil {
		t.Fatalf("recovered gRPC export = acked=%d rejected=%d retry=%d err=%v, want one acknowledgement only",
			len(res.Acked), len(res.Rejected), len(res.Retry), res.Err)
	}
	if got := srv.requests.Load(); got != 2 {
		t.Fatalf("gRPC wire attempts = %d, want exactly 2 (Unavailable then recovery)", got)
	}
}

// retryTimestampExporter captures the OTLP observed timestamp on each wire attempt.
// Its first attempt is reported as retryable; the next succeeds, so the test can feed
// the sink's returned Entry back through the real Emit path.
type retryTimestampExporter struct {
	mu       sync.Mutex
	observed [][]byte
	attempts int
}

func (e *retryTimestampExporter) Export(ctx context.Context, records []sdklog.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.attempts++
	for i := range records {
		b, err := records[i].ObservedTimestamp().MarshalBinary()
		if err != nil {
			return err
		}
		e.observed = append(e.observed, b)
	}
	if e.attempts == 1 {
		deliveryObservationFrom(ctx).record(outcomeRetryable, 0)
		return errors.New("first attempt failed")
	}
	return nil
}

func (*retryTimestampExporter) Shutdown(context.Context) error { return nil }
func (*retryTimestampExporter) ForceFlush(context.Context) error {
	return nil
}

func (e *retryTimestampExporter) timestamps() [][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([][]byte, len(e.observed))
	for i := range e.observed {
		out[i] = append([]byte(nil), e.observed[i]...)
	}
	return out
}

// The same admitted Entry may make several delivery attempts, but it is still one
// observed event. Its OTLP ObservedTimestamp must therefore remain byte-for-byte
// identical to the queue-admission stamp across retries (#394).
func TestOTLPSink_RetryPreservesObservedTimestamp(t *testing.T) {
	exp := &retryTimestampExporter{}
	s := newTestSink(exp)
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

	received := time.Date(2026, time.July, 26, 9, 10, 11, 123456789, time.UTC)
	admitted := Entry{
		Source:   "syslog",
		Received: received,
		Record: Record{
			Body:       "one admitted event",
			Attributes: map[string]string{AttrSubsystem: "firewall"},
		},
	}

	first := s.Emit(context.Background(), []Entry{admitted})
	if len(first.Retry) != 1 || len(first.Acked) != 0 || len(first.Rejected) != 0 {
		t.Fatalf("first attempt: acked=%d rejected=%d retry=%d, want the one entry retryable",
			len(first.Acked), len(first.Rejected), len(first.Retry))
	}
	second := s.Emit(context.Background(), first.Retry)
	if len(second.Acked) != 1 || len(second.Retry) != 0 || len(second.Rejected) != 0 {
		t.Fatalf("second attempt: acked=%d rejected=%d retry=%d, want the retry acknowledged",
			len(second.Acked), len(second.Rejected), len(second.Retry))
	}

	got := exp.timestamps()
	if len(got) != 2 {
		t.Fatalf("captured %d observed timestamps, want two wire attempts", len(got))
	}
	want, err := received.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal admission time: %v", err)
	}
	for i := range got {
		if !bytes.Equal(got[i], want) {
			t.Errorf("attempt %d observed timestamp bytes = %x, want admission bytes %x", i+1, got[i], want)
		}
	}
	if !bytes.Equal(got[0], got[1]) {
		t.Errorf("observed timestamp changed across retries: first=%x second=%x", got[0], got[1])
	}
}

// The seam must survive a real multi-partition batch over a real transport: two resource
// partitions, one acknowledged and one refused in the same Emit.
func TestOTLPSink_HTTPMixedPartitionOutcomes(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req collogpb.ExportLogsServiceRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			w.WriteHeader(500)
			return
		}
		// One partition per request, so the first resource identifies it.
		sub := ""
		for _, rl := range req.GetResourceLogs() {
			for _, kv := range rl.GetResource().GetAttributes() {
				if kv.GetKey() == AttrSubsystem {
					sub = kv.GetValue().GetStringValue()
				}
			}
		}
		mu.Lock()
		seen[sub]++
		mu.Unlock()

		if sub == "dns" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := newSinkOverEndpoint(t, "http/protobuf", srv.URL)
	batch := []Entry{
		entry("syslog", "firewall", "fw-1"),
		entry("syslog", "dns", "dns-1"),
		entry("syslog", "firewall", "fw-2"),
	}
	res := s.Emit(context.Background(), batch)
	assertResultCoversBatch(t, res, batch)

	if got := entryBodies(res.Acked); !slices.Equal(got, []string{"fw-1", "fw-2"}) {
		t.Fatalf("acked = %v, want the firewall partition", got)
	}
	if got := entryBodies(res.Rejected); !slices.Equal(got, []string{"dns-1"}) {
		t.Fatalf("rejected = %v, want the 400'd dns partition", got)
	}
	if len(res.Retry) != 0 {
		t.Fatalf("retry = %v, want none — an HTTP 400 is permanent", entryBodies(res.Retry))
	}

	mu.Lock()
	defer mu.Unlock()
	if seen["firewall"] != 1 || seen["dns"] != 1 {
		t.Fatalf("wire requests per partition = %v, want each exactly once", seen)
	}
}

// Shutdown must still drain and close exactly once now that flushing is per partition,
// and it must not be affected by an endpoint that refuses everything.
func TestOTLPSink_ShutdownAfterPartitionedFailureClosesExporterOnce(t *testing.T) {
	exp := &scriptedExporter{script: map[string]scriptedOutcome{
		"dns": {outcome: outcomePermanent, err: errors.New("400")},
	}}
	s := newTestSink(exp)

	res := s.Emit(context.Background(), []Entry{
		entry("syslog", "firewall", "a"),
		entry("syslog", "dns", "b"),
	})
	if len(res.Acked) != 1 || len(res.Rejected) != 1 {
		t.Fatalf("unexpected outcome %+v", res)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	exp.mu.Lock()
	defer exp.mu.Unlock()
	if exp.shutdown != 1 {
		t.Fatalf("exporter Shutdown called %d times, want exactly 1", exp.shutdown)
	}
}

// logExportTimeout must keep honouring the SDK's env vars, because supplying our own
// *http.Client is what stops the SDK from reading them.
func TestLogExportTimeout(t *testing.T) {
	if got := logExportTimeout(); got != 10*time.Second {
		t.Fatalf("default = %v, want the SDK's 10s", got)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "2500")
	if got := logExportTimeout(); got != 2500*time.Millisecond {
		t.Fatalf("OTEL_EXPORTER_OTLP_TIMEOUT=2500 gave %v, want 2.5s (the value is milliseconds)", got)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_TIMEOUT", "500")
	if got := logExportTimeout(); got != 500*time.Millisecond {
		t.Fatalf("the logs-specific var must win, got %v", got)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_TIMEOUT", "not-a-number")
	if got := logExportTimeout(); got != 2500*time.Millisecond {
		t.Fatalf("a malformed value gave %v; it must fall through, never disable the timeout", got)
	}
}

// A plaintext endpoint configured with TLS files is a misconfiguration the SDK used to
// reject. Supplying our own client bypasses that check, so the fail-fast has to live
// here or the setting would be silently ignored.
func TestNewObservingHTTPClient_RejectsInsecureWithTLS(t *testing.T) {
	_, err := newObservingHTTPClient(&options.OTLPConfig{Insecure: true}, &tls.Config{MinVersion: tls.VersionTLS12})
	if err == nil {
		t.Fatal("an insecure endpoint with TLS client configuration was accepted silently")
	}
	if !strings.Contains(err.Error(), "--otlp.insecure") {
		t.Fatalf("error should name the conflicting flag, got: %v", err)
	}
}
