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
type collectorSnapshot struct {
	metrics    []prometheus.Metric
	lastPoll   time.Time
	lastOK     bool
	durationMs float64
	polled     bool
}

// snapshotEntry is a read copy handed to the serving path. metrics aliases the
// stored slice; the const-metrics inside are immutable, so replaying them to many
// gather channels concurrently is safe.
type snapshotEntry struct {
	metrics    []prometheus.Metric
	lastPoll   time.Time
	lastOK     bool
	durationMs float64
	polled     bool
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
func (s *snapshotStore) put(name string, metrics []prometheus.Metric, dur time.Duration, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.data[name]
	if e == nil {
		e = &collectorSnapshot{}
		s.data[name] = e
	}
	if ok || len(metrics) > 0 {
		e.metrics = metrics
	}
	e.lastPoll = time.Now()
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
		out[name] = snapshotEntry{
			metrics:    e.metrics,
			lastPoll:   e.lastPoll,
			lastOK:     e.lastOK,
			durationMs: e.durationMs,
			polled:     e.polled,
		}
	}
	return out
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
	return snapshotEntry{
		metrics:    e.metrics,
		lastPoll:   e.lastPoll,
		lastOK:     e.lastOK,
		durationMs: e.durationMs,
		polled:     e.polled,
	}
}
