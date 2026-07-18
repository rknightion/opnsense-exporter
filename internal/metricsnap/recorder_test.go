package metricsnap

import (
	"errors"
	"testing"

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

func TestRecorder_DoesNotOverwriteOnErrorOrEmpty(t *testing.T) {
	r := New()
	good := []*dto.MetricFamily{{Name: strPtr("good_metric")}}

	teed := r.Tee(fakeGatherer{mfs: good, err: nil})
	if _, err := teed.Gather(); err != nil {
		t.Fatal(err)
	}
	mfs, at := r.Snapshot()
	if len(mfs) != 1 || mfs[0].GetName() != "good_metric" || at.IsZero() {
		t.Fatalf("want good snapshot captured, got %v/%v", mfs, at)
	}
	firstAt := at

	// An erroring inner Gather must not clobber the prior good snapshot.
	erroring := r.Tee(fakeGatherer{mfs: nil, err: errors.New("boom")})
	if _, err := erroring.Gather(); err == nil {
		t.Fatal("expected error from inner gatherer to propagate")
	}
	mfs, at = r.Snapshot()
	if len(mfs) != 1 || mfs[0].GetName() != "good_metric" || !at.Equal(firstAt) {
		t.Fatalf("error gather must not overwrite snapshot, got %v/%v", mfs, at)
	}

	// An empty (but non-erroring) inner Gather must also not clobber it.
	empty := r.Tee(fakeGatherer{mfs: nil, err: nil})
	if _, err := empty.Gather(); err != nil {
		t.Fatal(err)
	}
	mfs, at = r.Snapshot()
	if len(mfs) != 1 || mfs[0].GetName() != "good_metric" || !at.Equal(firstAt) {
		t.Fatalf("empty gather must not overwrite snapshot, got %v/%v", mfs, at)
	}
}

func strPtr(s string) *string { return &s }
