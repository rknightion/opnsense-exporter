package metricsnap

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestRecorder_CapturesOnGather(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGauge(prometheus.GaugeOpts{Name: "x_total", Help: "h"}))
	r := New()
	if _, at := r.Snapshot(); !at.IsZero() {
		t.Fatal("want zero time before capture")
	}
	teed := r.Tee(reg)
	if _, err := teed.Gather(); err != nil {
		t.Fatal(err)
	}
	mfs, at := r.Snapshot()
	if at.IsZero() || len(mfs) != 1 || mfs[0].GetName() != "x_total" {
		t.Fatalf("snapshot %v/%v", len(mfs), at)
	}
}

// fakeGatherer lets a test control exactly what Gather() returns, to probe
// the Recorder's handling of erroring / empty inner gathers without needing
// a real registry in a failure state.
type fakeGatherer struct {
	mfs []*dto.MetricFamily
	err error
}

func (f fakeGatherer) Gather() ([]*dto.MetricFamily, error) { return f.mfs, f.err }

// family builds a minimal named MetricFamily for the lane-merge tests.
func family(name string) *dto.MetricFamily {
	n := name
	return &dto.MetricFamily{Name: &n}
}

// gathererOf returns a clean gatherer over the given families.
func gathererOf(mfs ...*dto.MetricFamily) prometheus.Gatherer {
	return fakeGatherer{mfs: mfs}
}

// errGathererOf returns a gatherer that yields families AND an error, the
// continue-on-error shape the real scrape and OTLP paths produce.
func errGathererOf(mfs ...*dto.MetricFamily) prometheus.Gatherer {
	return fakeGatherer{mfs: mfs, err: errors.New("boom")}
}

// TestRecorder_PartialErrorReplacesSnapshot covers the core bug fix: a
// gather that returns non-empty families ALONGSIDE an error (the real
// promhttp.ContinueOnError / OTLP continue-on-error shape) must still
// replace the recorded snapshot, advance At, and mark the capture Partial.
func TestRecorder_PartialErrorReplacesSnapshot(t *testing.T) {
	r := New()
	good := []*dto.MetricFamily{{Name: strPtr("good_metric")}}

	teed := r.Tee(fakeGatherer{mfs: good, err: nil})
	if _, err := teed.Gather(); err != nil {
		t.Fatal(err)
	}
	firstCap := r.Capture()
	if firstCap.Partial {
		t.Fatalf("want non-partial after full capture, got %+v", firstCap)
	}

	time.Sleep(time.Millisecond)

	partialFamilies := []*dto.MetricFamily{{Name: strPtr("partial_metric")}}
	partial := r.Tee(fakeGatherer{mfs: partialFamilies, err: errors.New("boom")})
	mfs, err := partial.Gather()
	if err == nil {
		t.Fatal("expected error from inner gatherer to propagate")
	}
	if len(mfs) != 1 || mfs[0].GetName() != "partial_metric" {
		t.Fatalf("Gather() must return the inner gatherer's result unchanged, got %v", mfs)
	}

	cap := r.Capture()
	if len(cap.Families) != 1 || cap.Families[0].GetName() != "partial_metric" {
		t.Fatalf("want partial families recorded, got %v", cap.Families)
	}
	if !cap.At.After(firstCap.At) {
		t.Fatalf("want At to advance past %v, got %v", firstCap.At, cap.At)
	}
	if !cap.Partial {
		t.Fatal("want Partial == true after a non-empty error gather")
	}
	if cap.ErrorCount != 1 {
		t.Fatalf("want ErrorCount == 1, got %d", cap.ErrorCount)
	}
	if cap.LastErrorAt.IsZero() {
		t.Fatal("want LastErrorAt set after an error gather")
	}

	// Snapshot() must mirror the same replaced families/time.
	mfsSnap, atSnap := r.Snapshot()
	if len(mfsSnap) != 1 || mfsSnap[0].GetName() != "partial_metric" || !atSnap.Equal(cap.At) {
		t.Fatalf("want Snapshot() to reflect the partial capture, got %v/%v", mfsSnap, atSnap)
	}
}

// TestRecorder_EmptyErrorRetainsSnapshot covers a gather that returns an
// error with NO families at all (nothing usable was produced) — the
// previous good snapshot and its capture time must be retained untouched,
// while the cumulative error counters still advance.
func TestRecorder_EmptyErrorRetainsSnapshot(t *testing.T) {
	r := New()
	good := []*dto.MetricFamily{{Name: strPtr("good_metric")}}

	teed := r.Tee(fakeGatherer{mfs: good, err: nil})
	if _, err := teed.Gather(); err != nil {
		t.Fatal(err)
	}
	firstCap := r.Capture()

	empty := r.Tee(fakeGatherer{mfs: nil, err: errors.New("boom")})
	if _, err := empty.Gather(); err == nil {
		t.Fatal("expected error from inner gatherer to propagate")
	}

	cap := r.Capture()
	if len(cap.Families) != 1 || cap.Families[0].GetName() != "good_metric" {
		t.Fatalf("want previous good families retained, got %v", cap.Families)
	}
	if !cap.At.Equal(firstCap.At) {
		t.Fatalf("want At unchanged at %v, got %v", firstCap.At, cap.At)
	}
	if cap.Partial {
		t.Fatal("want Partial unchanged (false) when an empty-error gather retains the old capture")
	}
	if cap.ErrorCount != 1 {
		t.Fatalf("want ErrorCount == 1, got %d", cap.ErrorCount)
	}
	if cap.LastErrorAt.IsZero() {
		t.Fatal("want LastErrorAt set even though the families were retained")
	}

	// An empty, non-erroring gather must also retain the snapshot and must
	// NOT bump the error counters.
	emptyNoErr := r.Tee(fakeGatherer{mfs: nil, err: nil})
	if _, err := emptyNoErr.Gather(); err != nil {
		t.Fatal(err)
	}
	cap2 := r.Capture()
	if len(cap2.Families) != 1 || cap2.Families[0].GetName() != "good_metric" || !cap2.At.Equal(firstCap.At) {
		t.Fatalf("want snapshot retained across empty/no-error gather, got %+v", cap2)
	}
	if cap2.ErrorCount != 1 {
		t.Fatalf("want ErrorCount to stay at 1 (no error on this gather), got %d", cap2.ErrorCount)
	}
	if !cap2.LastErrorAt.Equal(cap.LastErrorAt) {
		t.Fatalf("want LastErrorAt unchanged by a non-erroring gather, got %v vs %v", cap2.LastErrorAt, cap.LastErrorAt)
	}
}

// TestRecorder_PartialThenFullClearsPartial ensures recovery is visible: a
// subsequent full (non-partial) capture must clear Partial back to false.
func TestRecorder_PartialThenFullClearsPartial(t *testing.T) {
	r := New()
	partialFamilies := []*dto.MetricFamily{{Name: strPtr("partial_metric")}}
	partial := r.Tee(fakeGatherer{mfs: partialFamilies, err: errors.New("boom")})
	if _, err := partial.Gather(); err == nil {
		t.Fatal("expected error to propagate")
	}
	if cap := r.Capture(); !cap.Partial {
		t.Fatalf("want Partial == true after the partial gather, got %+v", cap)
	}

	fullFamilies := []*dto.MetricFamily{{Name: strPtr("full_metric")}}
	full := r.Tee(fakeGatherer{mfs: fullFamilies, err: nil})
	if _, err := full.Gather(); err != nil {
		t.Fatal(err)
	}
	cap := r.Capture()
	if cap.Partial {
		t.Fatal("want Partial == false after a subsequent full success")
	}
	if len(cap.Families) != 1 || cap.Families[0].GetName() != "full_metric" {
		t.Fatalf("want full families recorded, got %v", cap.Families)
	}
	// ErrorCount/LastErrorAt are cumulative and must NOT reset on success.
	if cap.ErrorCount != 1 {
		t.Fatalf("want ErrorCount to remain 1 after a later success, got %d", cap.ErrorCount)
	}
	if cap.LastErrorAt.IsZero() {
		t.Fatal("want LastErrorAt to remain set after a later success")
	}
}

// TestRecorder_NeverCaptured checks the zero-value contract for both
// Capture() and Snapshot() before any Gather has happened.
func TestRecorder_NeverCaptured(t *testing.T) {
	r := New()
	cap := r.Capture()
	if !cap.At.IsZero() {
		t.Fatalf("want zero At before any capture, got %v", cap.At)
	}
	if len(cap.Families) != 0 {
		t.Fatalf("want no families before any capture, got %v", cap.Families)
	}
	if cap.Partial {
		t.Fatal("want Partial == false before any capture")
	}
	if !cap.LastErrorAt.IsZero() {
		t.Fatalf("want zero LastErrorAt before any capture, got %v", cap.LastErrorAt)
	}
	if cap.ErrorCount != 0 {
		t.Fatalf("want ErrorCount == 0 before any capture, got %d", cap.ErrorCount)
	}

	mfs, at := r.Snapshot()
	if mfs != nil {
		t.Fatalf("want nil families from Snapshot() before any capture, got %v", mfs)
	}
	if !at.IsZero() {
		t.Fatalf("want zero time from Snapshot() before any capture, got %v", at)
	}
}

// TestRecorder_ConcurrentGatherAndCapture exercises the mutex guarding
// under -race: concurrent Gather() calls (some erroring, some not) racing
// against concurrent Capture() reads must never trip the race detector.
func TestRecorder_ConcurrentGatherAndCapture(t *testing.T) {
	r := New()
	families := []*dto.MetricFamily{{Name: strPtr("race_metric")}}
	okGatherer := r.Tee(fakeGatherer{mfs: families, err: nil})
	errGatherer := r.Tee(fakeGatherer{mfs: families, err: errors.New("boom")})
	emptyGatherer := r.Tee(fakeGatherer{mfs: nil, err: errors.New("empty boom")})

	var wg sync.WaitGroup
	const n = 50
	wg.Add(n * 4)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, _ = okGatherer.Gather()
		}()
		go func() {
			defer wg.Done()
			_, _ = errGatherer.Gather()
		}()
		go func() {
			defer wg.Done()
			_, _ = emptyGatherer.Gather()
		}()
		go func() {
			defer wg.Done()
			_ = r.Capture()
			_, _ = r.Snapshot()
		}()
	}
	wg.Wait()
}

func strPtr(s string) *string { return &s }

// TestRecorder_MergesDisjointLanes pins the console-facing half of the optional
// two-lane OTLP split (#390): with the metric set produced by two disjoint readers,
// neither lane alone is the whole picture, so Capture must return the UNION. Without
// this the console would silently under-report families, series and cardinality by
// whatever the fast tier happens to hold.
func TestRecorder_MergesDisjointLanes(t *testing.T) {
	r := New()
	base := r.TeeLane("base", gathererOf(family("opnsense_base_one"), family("opnsense_base_two")))
	fast := r.TeeLane("fast", gathererOf(family("opnsense_fast_one")))

	if _, err := base.Gather(); err != nil {
		t.Fatalf("base gather: %v", err)
	}
	c := r.Capture()
	if len(c.Families) != 2 {
		t.Fatalf("with only the base lane captured, want 2 families, got %d", len(c.Families))
	}

	if _, err := fast.Gather(); err != nil {
		t.Fatalf("fast gather: %v", err)
	}
	c = r.Capture()
	names := map[string]bool{}
	for _, mf := range c.Families {
		names[mf.GetName()] = true
	}
	if len(c.Families) != 3 {
		t.Errorf("both lanes captured: want the 3-family union, got %d (%v)", len(c.Families), names)
	}
	for _, want := range []string{"opnsense_base_one", "opnsense_base_two", "opnsense_fast_one"} {
		if !names[want] {
			t.Errorf("merged capture is missing %q", want)
		}
	}
	// Families come back name-sorted, matching what a single Gather would produce.
	for i := 1; i < len(c.Families); i++ {
		if c.Families[i-1].GetName() > c.Families[i].GetName() {
			t.Errorf("merged families must be name-sorted, got %v", names)
			break
		}
	}
}

// TestRecorder_MergedAgeIsTheStalestLane pins that a merged capture reports the age
// of its OLDEST contributing lane. The merged set is only as fresh as its stalest
// part, and claiming otherwise is the same class of quiet lie #382 removes.
func TestRecorder_MergedAgeIsTheStalestLane(t *testing.T) {
	r := New()
	old := r.TeeLane("base", gathererOf(family("opnsense_old")))
	if _, err := old.Gather(); err != nil {
		t.Fatalf("gather: %v", err)
	}
	oldAt := r.Capture().At

	time.Sleep(10 * time.Millisecond)
	fresh := r.TeeLane("fast", gathererOf(family("opnsense_fresh")))
	if _, err := fresh.Gather(); err != nil {
		t.Fatalf("gather: %v", err)
	}

	c := r.Capture()
	if !c.At.Equal(oldAt) {
		t.Errorf("merged capture time = %v, want the stalest lane's %v", c.At, oldAt)
	}
}

// TestRecorder_PartialLanePoisonsTheMerge: if ANY contributing lane was partial, the
// merged capture must be marked partial — the console must not present a union that
// contains a degraded half as if it were clean.
func TestRecorder_PartialLanePoisonsTheMerge(t *testing.T) {
	r := New()
	clean := r.TeeLane("base", gathererOf(family("opnsense_clean")))
	broken := r.TeeLane("fast", errGathererOf(family("opnsense_partial")))
	if _, err := clean.Gather(); err != nil {
		t.Fatalf("gather: %v", err)
	}
	if _, err := broken.Gather(); err == nil {
		t.Fatal("the partial lane must still surface its error to its caller")
	}
	if c := r.Capture(); !c.Partial {
		t.Error("a merge containing a partial lane must be marked partial")
	}
}

// TestRecorder_SingleLaneUnchanged pins backward compatibility: plain Tee (the
// /metrics handler and single-lane OTLP) behaves exactly as before.
func TestRecorder_SingleLaneUnchanged(t *testing.T) {
	r := New()
	g := r.Tee(gathererOf(family("opnsense_a"), family("opnsense_b")))
	if _, err := g.Gather(); err != nil {
		t.Fatalf("gather: %v", err)
	}
	mfs, at := r.Snapshot()
	if len(mfs) != 2 || at.IsZero() {
		t.Errorf("single-lane Tee must record both families with a capture time, got %d at %v", len(mfs), at)
	}
}
