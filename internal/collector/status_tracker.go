package collector

import (
	"sort"
	"sync"
	"time"
)

// StatusRingSize bounds the per-collector duration/outcome history rings that
// back the web console's sparkline and outcome strip.
const StatusRingSize = 40

// CollectorStat is a point-in-time copy of one collector's run history,
// returned by StatusTracker.Snapshot. It carries no locks and is safe for the
// caller to read and render freely.
type CollectorStat struct {
	Name, Display             string
	Runs, Failures            uint64
	ConsecutiveFails          uint64
	LastStarted, LastFinished time.Time
	LastDurationMs            float64
	LastOK                    bool
	LastError                 string
	Interval                  time.Duration // configured poll interval; 0 if unknown
	DurationMs                []float64     // ring, oldest→newest, ≤ StatusRingSize
	Outcomes                  []bool        // ring, oldest→newest, ≤ StatusRingSize

	// SnapshotAt / LastSuccessAt / NextDeadline mirror the scheduler's real clocks
	// (#382, #385) so the console can show DATA age and a true next-run countdown
	// without gathering the registry. They are carried here rather than read back
	// out of the metric families on purpose: on a console-only deployment with OTLP
	// disabled and nothing scraping /metrics, a metricsnap capture may never exist.
	//
	// LastFinished is the last ATTEMPT and is NOT data freshness — a collector that
	// has failed every poll for six hours keeps refreshing it while replaying
	// six-hour-old values. Anything user-facing that says "fresh" must read
	// SnapshotAt. Zero means never.
	SnapshotAt    time.Time
	LastSuccessAt time.Time
	NextDeadline  time.Time
}

// statEntry is the mutable per-collector accumulator held under the tracker mutex.
type statEntry struct {
	name             string
	runs, failures   uint64
	consecutiveFails uint64
	lastStarted      time.Time
	lastFinished     time.Time
	lastDurationMs   float64
	lastOK           bool
	lastError        string
	interval         time.Duration
	durationMs       []float64
	outcomes         []bool
	snapshotAt       time.Time
	lastSuccessAt    time.Time
	nextDeadline     time.Time
}

// StatusTracker passively retains per-collector run history for the operator
// console. It is updated from execute() on every sub-collector run and from
// RunCollector, and read via Snapshot. All methods are safe for concurrent use.
type StatusTracker struct {
	mu    sync.RWMutex
	stats map[string]*statEntry
}

// NewStatusTracker returns an empty tracker ready to Record runs.
func NewStatusTracker() *StatusTracker {
	return &StatusTracker{stats: make(map[string]*statEntry)}
}

// Record appends one collector run outcome, updating counters and the bounded
// history rings. durationMs is the run duration in milliseconds; ok is the
// success flag; errStr is the last error string (empty when ok).
func (t *StatusTracker) Record(name string, start time.Time, durationMs float64, ok bool, errStr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entry(name)
	e.runs++
	if ok {
		e.consecutiveFails = 0
	} else {
		e.failures++
		e.consecutiveFails++
	}
	e.lastStarted = start
	e.lastFinished = start.Add(time.Duration(durationMs * float64(time.Millisecond)))
	e.lastDurationMs = durationMs
	e.lastOK = ok
	e.lastError = errStr
	e.durationMs = appendRing(e.durationMs, durationMs)
	e.outcomes = appendRingBool(e.outcomes, ok)
}

// RecordClocks publishes a collector's data clocks — when its stored metric buffer
// was last replaced, and when it last fully succeeded (#382). Called by the poll
// scheduler straight after the snapshot store is written, so the console and the
// exported timestamps cannot drift apart. Zero times are stored as-is and mean
// "never".
func (t *StatusTracker) RecordClocks(name string, snapshotAt, lastSuccessAt time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entry(name)
	e.snapshotAt = snapshotAt
	e.lastSuccessAt = lastSuccessAt
}

// SetNextDeadline publishes the scheduler's ACTUAL next poll time for a collector
// (#385). The console reads this instead of computing LastFinished + Interval, which
// runs late by exactly the poll duration and is wrong by a whole cadence after a poll
// that overran its interval. The zero time means no poll is scheduled — the poller
// has stopped — and must render as such rather than as a countdown.
func (t *StatusTracker) SetNextDeadline(name string, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entry(name).nextDeadline = at
}

// entry returns the accumulator for name, creating it if absent. Callers hold the
// write lock.
func (t *StatusTracker) entry(name string) *statEntry {
	e := t.stats[name]
	if e == nil {
		e = &statEntry{name: name}
		t.stats[name] = e
	}
	return e
}

// SetInterval records a collector's configured poll interval so Snapshot can expose
// it (the console derives the next-run countdown from LastFinished + Interval). It is
// called once per collector at StartPolling, before any run is recorded.
func (t *StatusTracker) SetInterval(name string, d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entry(name).interval = d
}

// Snapshot returns a deep copy of every tracked collector's stats, sorted by
// Display name. The returned slices are independent of the tracker's internal
// rings, so the caller may hold and mutate them freely.
func (t *StatusTracker) Snapshot() []CollectorStat {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]CollectorStat, 0, len(t.stats))
	for _, e := range t.stats {
		display := SubsystemDisplayNames[e.name]
		if display == "" {
			display = e.name
		}
		out = append(out, CollectorStat{
			Name:             e.name,
			Display:          display,
			Runs:             e.runs,
			Failures:         e.failures,
			ConsecutiveFails: e.consecutiveFails,
			LastStarted:      e.lastStarted,
			LastFinished:     e.lastFinished,
			LastDurationMs:   e.lastDurationMs,
			LastOK:           e.lastOK,
			LastError:        e.lastError,
			Interval:         e.interval,
			DurationMs:       append([]float64(nil), e.durationMs...),
			Outcomes:         append([]bool(nil), e.outcomes...),
			SnapshotAt:       e.snapshotAt,
			LastSuccessAt:    e.lastSuccessAt,
			NextDeadline:     e.nextDeadline,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Display < out[j].Display })
	return out
}

// appendRing appends v to a float ring bounded at StatusRingSize, shifting the
// oldest element out once full. Order is oldest→newest.
func appendRing(ring []float64, v float64) []float64 {
	if len(ring) < StatusRingSize {
		return append(ring, v)
	}
	copy(ring, ring[1:])
	ring[StatusRingSize-1] = v
	return ring
}

// appendRingBool is appendRing for the boolean outcome ring.
func appendRingBool(ring []bool, v bool) []bool {
	if len(ring) < StatusRingSize {
		return append(ring, v)
	}
	copy(ring, ring[1:])
	ring[StatusRingSize-1] = v
	return ring
}
