// Package metricsnap passively captures the metric families produced by real
// Prometheus scrapes so other consumers (e.g. the web UI operator console)
// can read a last-scrape snapshot without ever triggering a scrape of their
// own.
package metricsnap

import (
	"sort"
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

// laneCapture is one lane's most recent families and when they arrived.
type laneCapture struct {
	families []*dto.MetricFamily
	at       time.Time
	partial  bool
}

// defaultLane is the lane key used by Tee, i.e. every caller that gathers the
// complete metric set in one go (the /metrics handler, and OTLP when the
// optional fast lane is disabled).
const defaultLane = ""

// Recorder holds the most recent set of metric families captured from wrapped
// Gatherers, plus the time they were captured and metadata about gather errors
// observed along the way.
//
// Captures are keyed by LANE because the metric set is not always produced by a
// single gather: with the optional fast OTLP lane enabled (#390) the exporter's
// series are split across two disjoint readers, and neither one alone is the
// whole picture. Capture merges the lanes so the console keeps reporting the
// union rather than silently under-counting families, series and cardinality by
// whatever the fast tier happens to hold.
type Recorder struct {
	mu          sync.RWMutex
	lanes       map[string]laneCapture
	lastErrorAt time.Time
	errorCount  uint64
}

// New returns an empty Recorder. Snapshot returns (nil, zero-time) until the
// first non-empty Gather passes through a Tee'd gatherer.
func New() *Recorder { return &Recorder{lanes: make(map[string]laneCapture)} }

// teed wraps an inner Gatherer, delegating Gather to it and recording the
// result into the owning Recorder under lane.
type teed struct {
	r     *Recorder
	lane  string
	inner prometheus.Gatherer
}

// Tee returns a Gatherer that delegates to inner and records the result as
// the latest capture whenever inner returns non-empty families — regardless
// of whether inner also returned an error, mirroring the continue-on-error
// contract used by the real scrape and OTLP paths (promhttp.ContinueOnError
// and the OTLP continue-on-error gatherer both serve partial families rather
// than discard them). Used to wrap the real scrape gatherers so the console
// reads captured families without gathering itself.
func (r *Recorder) Tee(inner prometheus.Gatherer) prometheus.Gatherer {
	return teed{r: r, lane: defaultLane, inner: inner}
}

// TeeLane is Tee for a gatherer that produces only PART of the metric set, such
// as one of the two disjoint OTLP export lanes (#390). Each lane's families are
// held separately and merged by Capture, so a split export pipeline still gives
// the console the complete picture. Lane names must be stable; a lane is only
// ever replaced by a later gather of the same lane.
func (r *Recorder) TeeLane(lane string, inner prometheus.Gatherer) prometheus.Gatherer {
	return teed{r: r, lane: lane, inner: inner}
}

func (t teed) Gather() ([]*dto.MetricFamily, error) {
	mfs, err := t.inner.Gather()

	t.r.mu.Lock()
	if err != nil {
		t.r.errorCount++
		t.r.lastErrorAt = time.Now()
	}
	if len(mfs) > 0 {
		t.r.lanes[t.lane] = laneCapture{families: mfs, at: time.Now(), partial: err != nil}
	}
	t.r.mu.Unlock()

	return mfs, err
}

// merged folds every lane into one family set. Callers hold the read lock.
//
// Lanes are disjoint by construction, so in practice this is a concatenation;
// the family-name dedupe exists only to keep the result well-formed if a
// complete-set lane (Tee) and partial lanes (TeeLane) are ever both active — the
// most recently captured copy of a family wins, since all lanes read the same
// underlying snapshot and the newest is the least stale.
//
// The reported time is the OLDEST contributing lane, not the newest: the merged
// set is only as fresh as its stalest part, and overstating that is exactly the
// kind of quiet lie #382 exists to remove.
func (r *Recorder) merged() ([]*dto.MetricFamily, time.Time, bool) {
	if len(r.lanes) == 1 {
		for _, lc := range r.lanes {
			return lc.families, lc.at, lc.partial
		}
	}
	type owned struct {
		mf *dto.MetricFamily
		at time.Time
	}
	byName := make(map[string]owned)
	var oldest time.Time
	partial := false
	for _, lc := range r.lanes {
		if lc.partial {
			partial = true
		}
		if oldest.IsZero() || lc.at.Before(oldest) {
			oldest = lc.at
		}
		for _, mf := range lc.families {
			if prev, ok := byName[mf.GetName()]; ok && prev.at.After(lc.at) {
				continue
			}
			byName[mf.GetName()] = owned{mf: mf, at: lc.at}
		}
	}
	out := make([]*dto.MetricFamily, 0, len(byName))
	for _, o := range byName {
		out = append(out, o.mf)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetName() < out[j].GetName() })
	return out, oldest, partial
}

// Snapshot returns a copy of the last captured families and the time they
// were captured. Returns (nil, zero-time) if no capture has happened yet.
func (r *Recorder) Snapshot() ([]*dto.MetricFamily, time.Time) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	mfs, at, _ := r.merged()
	return append([]*dto.MetricFamily(nil), mfs...), at
}

// Capture returns a copy of the most recent recorded capture.
func (r *Recorder) Capture() Capture {
	r.mu.RLock()
	defer r.mu.RUnlock()
	mfs, at, partial := r.merged()
	return Capture{
		Families:    append([]*dto.MetricFamily(nil), mfs...),
		At:          at,
		Partial:     partial,
		LastErrorAt: r.lastErrorAt,
		ErrorCount:  r.errorCount,
	}
}
