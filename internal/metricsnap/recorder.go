// Package metricsnap passively captures the metric families produced by real
// Prometheus scrapes so other consumers (e.g. the web UI operator console)
// can read a last-scrape snapshot without ever triggering a scrape of their
// own.
package metricsnap

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Capture is one recorded gather, plus the metadata that distinguishes a full
// capture from a partial (error-accompanied) one.
type Capture struct {
	Families    []*dto.MetricFamily
	At          time.Time // capture time; zero if never captured
	Partial     bool      // these families arrived together with a gather error
	LastErrorAt time.Time // last time a gather returned an error; zero if never
	ErrorCount  uint64    // total gathers that returned an error
}

// Recorder holds the most recent set of metric families captured from a
// wrapped Gatherer, plus the time they were captured and metadata about
// gather errors observed along the way.
type Recorder struct {
	mu          sync.RWMutex
	last        []*dto.MetricFamily
	at          time.Time
	partial     bool
	lastErrorAt time.Time
	errorCount  uint64
}

// New returns an empty Recorder. Snapshot returns (nil, zero-time) until the
// first non-empty Gather passes through a Tee'd gatherer.
func New() *Recorder { return &Recorder{} }

// teed wraps an inner Gatherer, delegating Gather to it and recording the
// result into the owning Recorder.
type teed struct {
	r     *Recorder
	inner prometheus.Gatherer
}

// Tee returns a Gatherer that delegates to inner and records the result as
// the latest capture whenever inner returns non-empty families — regardless
// of whether inner also returned an error, mirroring the continue-on-error
// contract used by the real scrape and OTLP paths (promhttp.ContinueOnError
// and the OTLP continue-on-error gatherer both serve partial families rather
// than discard them). Used to wrap the real scrape gatherers so the console
// reads captured families without gathering itself.
func (r *Recorder) Tee(inner prometheus.Gatherer) prometheus.Gatherer { return teed{r, inner} }

func (t teed) Gather() ([]*dto.MetricFamily, error) {
	mfs, err := t.inner.Gather()

	t.r.mu.Lock()
	if err != nil {
		t.r.errorCount++
		t.r.lastErrorAt = time.Now()
	}
	if len(mfs) > 0 {
		t.r.last = mfs
		t.r.at = time.Now()
		t.r.partial = err != nil
	}
	t.r.mu.Unlock()

	return mfs, err
}

// Snapshot returns a copy of the last captured families and the time they
// were captured. Returns (nil, zero-time) if no capture has happened yet.
func (r *Recorder) Snapshot() ([]*dto.MetricFamily, time.Time) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]*dto.MetricFamily(nil), r.last...), r.at
}

// Capture returns a copy of the most recent recorded capture.
func (r *Recorder) Capture() Capture {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return Capture{
		Families:    append([]*dto.MetricFamily(nil), r.last...),
		At:          r.at,
		Partial:     r.partial,
		LastErrorAt: r.lastErrorAt,
		ErrorCount:  r.errorCount,
	}
}
