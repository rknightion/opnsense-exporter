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

// Recorder holds the most recent set of metric families captured from a
// wrapped Gatherer, plus the time they were captured.
type Recorder struct {
	mu   sync.RWMutex
	last []*dto.MetricFamily
	at   time.Time
}

// New returns an empty Recorder. Snapshot returns (nil, zero-time) until the
// first successful, non-empty Gather passes through a Tee'd gatherer.
func New() *Recorder { return &Recorder{} }

// teed wraps an inner Gatherer, delegating Gather to it and recording the
// result into the owning Recorder on success.
type teed struct {
	r     *Recorder
	inner prometheus.Gatherer
}

// Tee returns a Gatherer that delegates to inner and, on a successful
// non-empty Gather, stores the families as the latest snapshot. Used to wrap
// the real scrape gatherers so the console reads captured families without
// gathering itself.
func (r *Recorder) Tee(inner prometheus.Gatherer) prometheus.Gatherer { return teed{r, inner} }

func (t teed) Gather() ([]*dto.MetricFamily, error) {
	mfs, err := t.inner.Gather()
	if err == nil && len(mfs) > 0 {
		t.r.mu.Lock()
		t.r.last = mfs
		t.r.at = time.Now()
		t.r.mu.Unlock()
	}
	return mfs, err
}

// Snapshot returns a copy of the last captured families and the time they
// were captured. Returns (nil, zero-time) if no successful capture has
// happened yet.
func (r *Recorder) Snapshot() ([]*dto.MetricFamily, time.Time) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]*dto.MetricFamily(nil), r.last...), r.at
}
