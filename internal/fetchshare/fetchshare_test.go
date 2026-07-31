package fetchshare

import (
	"sync"
	"testing"
	"time"
)

// fakeClock is a hand-advanced clock, so freshness boundaries are asserted exactly
// rather than raced against wall time.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestStore() (*Store, *fakeClock) {
	clk := &fakeClock{t: time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)}
	s := New()
	s.now = clk.now
	return s, clk
}

type leaseTable struct{ Rows int }

func TestFreshReturnsAPublishedValueWithinMaxAge(t *testing.T) {
	s, clk := newTestStore()
	s.Publish(KeyArpTable, leaseTable{Rows: 3})

	clk.advance(59 * time.Second)
	got, ok := Fresh[leaseTable](s, KeyArpTable, time.Minute)
	if !ok {
		t.Fatal("Fresh missed a value published 59s ago under a 60s maxAge")
	}
	if got.Rows != 3 {
		t.Errorf("Fresh returned %+v, want Rows=3", got)
	}
}

// TestFreshMissesAtAndBeyondMaxAge pins the boundary as exclusive. It matters
// because the enrichment refresher reads with maxAge equal to its own refresh TTL
// and the collectors publish on the same nominal cadence: an inclusive boundary
// would make a hit-or-miss decision on two timers that are nominally equal, which
// is exactly the kind of thing that behaves differently in production than in a
// test.
func TestFreshMissesAtAndBeyondMaxAge(t *testing.T) {
	for _, age := range []time.Duration{time.Minute, 61 * time.Second} {
		s, clk := newTestStore()
		s.Publish(KeyArpTable, leaseTable{Rows: 3})
		clk.advance(age)
		if _, ok := Fresh[leaseTable](s, KeyArpTable, time.Minute); ok {
			t.Errorf("Fresh hit on a value published %v ago under a 60s maxAge; want a miss", age)
		}
	}
}

func TestFreshMissesUnpublishedKey(t *testing.T) {
	s, _ := newTestStore()
	if _, ok := Fresh[leaseTable](s, KeyArpTable, time.Hour); ok {
		t.Error("Fresh hit on a key that was never published")
	}
}

// TestFreshMissesOnTypeMismatch proves the read degrades to a miss rather than
// panicking, so a mis-keyed producer costs an API call rather than the process.
func TestFreshMissesOnTypeMismatch(t *testing.T) {
	s, _ := newTestStore()
	s.Publish(KeyArpTable, "not a lease table")
	if _, ok := Fresh[leaseTable](s, KeyArpTable, time.Hour); ok {
		t.Error("Fresh hit with the wrong type; want a miss")
	}
}

// TestPublishZeroValueIsAHit is the plugin-absent case. FetchKeaLeases4 folds a 404
// into empty-data-and-nil-error, and the collector publishes that empty result. If
// the seam treated an empty value as "nothing published", every reader would fetch
// forever on exactly the boxes with the least to fetch.
func TestPublishZeroValueIsAHit(t *testing.T) {
	s, _ := newTestStore()
	s.Publish(KeyKeaLeases4, leaseTable{})
	got, ok := Fresh[leaseTable](s, KeyKeaLeases4, time.Minute)
	if !ok {
		t.Fatal("Fresh missed a published zero value; an empty result is a real answer")
	}
	if got.Rows != 0 {
		t.Errorf("got %+v, want the zero value", got)
	}
}

func TestPublishReplacesAndRestartsTheClock(t *testing.T) {
	s, clk := newTestStore()
	s.Publish(KeyArpTable, leaseTable{Rows: 1})
	clk.advance(90 * time.Second)
	if _, ok := Fresh[leaseTable](s, KeyArpTable, time.Minute); ok {
		t.Fatal("precondition: the first value should have aged out")
	}

	s.Publish(KeyArpTable, leaseTable{Rows: 2})
	got, ok := Fresh[leaseTable](s, KeyArpTable, time.Minute)
	if !ok {
		t.Fatal("Fresh missed immediately after a republish")
	}
	if got.Rows != 2 {
		t.Errorf("got %+v, want the republished value (Rows=2)", got)
	}
}

// TestNonPositiveMaxAgeAlwaysMisses lets a caller disable seam reads without a
// branch at the call site.
func TestNonPositiveMaxAgeAlwaysMisses(t *testing.T) {
	s, _ := newTestStore()
	s.Publish(KeyArpTable, leaseTable{Rows: 1})
	for _, maxAge := range []time.Duration{0, -time.Second} {
		if _, ok := Fresh[leaseTable](s, KeyArpTable, maxAge); ok {
			t.Errorf("Fresh hit with maxAge=%v; want a miss", maxAge)
		}
	}
}

// TestNilStoreIsAPermanentlyEmptyStore keeps "built without a seam" from needing a
// nil check at any call site, mirroring the API client's nil-safe response cache.
func TestNilStoreIsAPermanentlyEmptyStore(t *testing.T) {
	var s *Store
	s.Publish(KeyArpTable, leaseTable{Rows: 1}) // must not panic
	if _, ok := Fresh[leaseTable](s, KeyArpTable, time.Hour); ok {
		t.Error("Fresh hit on a nil store")
	}
	if snap := s.Snapshot(); snap != nil {
		t.Errorf("Snapshot on a nil store = %v, want nil", snap)
	}
}

func TestSnapshotReportsAges(t *testing.T) {
	s, clk := newTestStore()
	s.Publish(KeyArpTable, leaseTable{})
	clk.advance(10 * time.Second)
	s.Publish(KeyNDPTable, leaseTable{})
	clk.advance(5 * time.Second)

	snap := s.Snapshot()
	if got, want := snap[KeyArpTable], 15*time.Second; got != want {
		t.Errorf("arp age = %v, want %v", got, want)
	}
	if got, want := snap[KeyNDPTable], 5*time.Second; got != want {
		t.Errorf("ndp age = %v, want %v", got, want)
	}
	if len(snap) != 2 {
		t.Errorf("snapshot has %d entries, want 2", len(snap))
	}
}

// TestConcurrentPublishAndRead is the race-detector's job; the assertion is only
// that nothing panics and the final read succeeds. Publishers here are the poll
// goroutines (one per collector, all concurrent under the scheduler) and the reader
// is the refresher's Run loop.
func TestConcurrentPublishAndRead(t *testing.T) {
	s := New()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(2)
		go func() { defer wg.Done(); s.Publish(KeyArpTable, leaseTable{Rows: i}) }()
		go func() { defer wg.Done(); Fresh[leaseTable](s, KeyArpTable, time.Hour) }()
	}
	wg.Wait()
	if _, ok := Fresh[leaseTable](s, KeyArpTable, time.Hour); !ok {
		t.Error("Fresh missed after concurrent publishes")
	}
}
