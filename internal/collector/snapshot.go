package collector

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// collectorSnapshot is the stored result of a collector's most recent poll: the
// metrics it emitted plus the poll metadata the serving path re-emits as the
// per-collector scrape_collector_{duration,success} series. It is written only by
// the poll scheduler and read (copied) by the serving path.
// The three time fields are deliberately distinct clocks (#382). Conflating them
// is what let a collector that has failed every poll for six hours keep replaying
// its 10:00 values while the console and dashboard called them seconds old:
//
//	lastPoll     the last poll ATTEMPT completed — advances on every attempt,
//	             success or failure. Scheduler liveness, never data freshness.
//	snapshotAt   the stored metric buffer was last REPLACED — the age of the data
//	             a scrape actually replays. Does not advance when an errored poll
//	             emitted nothing and the last-good buffer was retained.
//	lastSuccess  the last FULLY CLEAN poll. Does not advance on a partial-error
//	             poll, even though that poll did replace the buffer with genuinely
//	             new (partial) data.
//
// A partial-error poll therefore advances lastPoll and snapshotAt but not
// lastSuccess, which is precisely why one clock cannot express this.
type collectorSnapshot struct {
	metrics     []prometheus.Metric
	lastPoll    time.Time
	snapshotAt  time.Time
	lastSuccess time.Time
	lastOK      bool
	durationMs  float64
	polled      bool
	// nextDeadline is the scheduler's ACTUAL next tick for this collector (#385),
	// written by runCollectorPoller before each poll. It is deliberately not
	// derived from lastPoll + interval: the scheduler runs on a fixed ticker, so
	// any non-trivial poll duration makes the derived value late by exactly that
	// duration, and an overrunning poll makes it wrong by a whole cadence. Zero
	// means no poller is running for this collector.
	nextDeadline time.Time
}

// snapshotEntry is a read copy handed to the serving path. metrics aliases the
// stored slice; the const-metrics inside are immutable, so replaying them to many
// gather channels concurrently is safe.
type snapshotEntry struct {
	metrics      []prometheus.Metric
	lastPoll     time.Time
	snapshotAt   time.Time
	lastSuccess  time.Time
	lastOK       bool
	durationMs   float64
	polled       bool
	nextDeadline time.Time
}

// snapshotStore holds the latest poll result per collector. All access is guarded
// so the poll goroutines and concurrent gather (/metrics + OTLP) never race.
type snapshotStore struct {
	mu   sync.RWMutex
	data map[string]*collectorSnapshot
}

func newSnapshotStore() *snapshotStore {
	return &snapshotStore{data: make(map[string]*collectorSnapshot)}
}

// put records one poll outcome (D8). The buffer is replaced whenever the poll
// produced any metrics OR succeeded; the last-good buffer is retained only when an
// errored poll produced nothing:
//   - ok + non-empty:  replace (normal success).
//   - ok + empty:      replace with empty — drops series whose data is genuinely
//     gone (clean absence).
//   - !ok + non-empty: replace with the partial emit — a collector that emitted real
//     data before erroring on a secondary endpoint still exports what it fetched.
//   - !ok + empty:     retain last-good — a transient full failure must never blank
//     the dashboard (error retention).
//
// lastOK always tracks the poll result, so scrape_collector_success reflects the
// error even when the partial buffer is kept.
//
// The three clocks move on exactly the conditions that define them (#382), and
// this is the ONLY place they are written:
//
//	lastPoll     always — an attempt completed.
//	snapshotAt   iff the buffer was actually replaced, i.e. the same condition
//	             that guards the assignment. Retaining the last-good buffer and
//	             advancing its timestamp is the bug: it relabels hours-old data
//	             as seconds old for as long as the failures keep arriving on time.
//	lastSuccess  iff ok — a partial-error poll deliberately does not count, even
//	             though it refreshed the buffer.
func (s *snapshotStore) put(name string, metrics []prometheus.Metric, dur time.Duration, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.ensure(name)
	now := time.Now()
	if ok || len(metrics) > 0 {
		e.metrics = metrics
		e.snapshotAt = now
	}
	if ok {
		e.lastSuccess = now
	}
	e.lastPoll = now
	e.lastOK = ok
	e.durationMs = float64(dur) / float64(time.Millisecond)
	e.polled = true
}

// view returns read copies of the stored snapshots. include==nil returns every
// stored collector; a non-nil map restricts the result to the named collectors.
func (s *snapshotStore) view(include map[string]bool) map[string]snapshotEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]snapshotEntry, len(s.data))
	for name, e := range s.data {
		if include != nil && !include[name] {
			continue
		}
		out[name] = e.view()
	}
	return out
}

// view returns a read copy of one stored snapshot. Callers hold the store lock.
func (e *collectorSnapshot) view() snapshotEntry {
	return snapshotEntry{
		metrics:      e.metrics,
		lastPoll:     e.lastPoll,
		snapshotAt:   e.snapshotAt,
		lastSuccess:  e.lastSuccess,
		lastOK:       e.lastOK,
		durationMs:   e.durationMs,
		polled:       e.polled,
		nextDeadline: e.nextDeadline,
	}
}

// ensure returns the entry for name, creating it if absent. Callers hold the write
// lock. The scheduler seeds an entry via setDeadline before the first poll, so a
// collector's next-run state is known from the moment its poller starts.
func (s *snapshotStore) ensure(name string) *collectorSnapshot {
	e := s.data[name]
	if e == nil {
		e = &collectorSnapshot{}
		s.data[name] = e
	}
	return e
}

// setDeadline records the scheduler's actual next tick for one collector (#385).
// Passing the zero time clears it, which is how a stopped poller reports that no
// further poll is scheduled rather than leaving a deadline that silently ages into
// a permanent "due".
func (s *snapshotStore) setDeadline(name string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure(name).nextDeadline = at
}

// allPolled reports whether every named collector has completed at least one poll
// (successful or not). It is the store half of the warm-up signal (#341): until it
// is true, a scrape replays a snapshot that is missing whole collectors.
func (s *snapshotStore) allPolled(names []string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, name := range names {
		if e := s.data[name]; e == nil || !e.polled {
			return false
		}
	}
	return true
}

// entry returns the stored snapshot for one collector, or a zero entry with
// polled=false if it has never been polled.
func (s *snapshotStore) entry(name string) snapshotEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := s.data[name]
	if e == nil {
		return snapshotEntry{}
	}
	return e.view()
}
