package collector

import (
	"sync"
	"testing"
	"time"
)

// subCadenceClock is hand-advanced so the interval boundary is asserted exactly
// rather than raced against wall time.
type subCadenceClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *subCadenceClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *subCadenceClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestSubCadence(interval time.Duration) (*subCadence, *subCadenceClock) {
	clk := &subCadenceClock{t: time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)}
	s := newSubCadence(interval)
	s.now = clk.now
	return s, clk
}

// TestSubCadenceFirstRunIsAlwaysDue pins the startup behaviour. If the gate started
// "not due", the slow half of the collector's data would be absent from the first
// poll until a full interval elapsed — for crowdsec's 15m that is fifteen minutes of
// missing hub gauges after every restart, which reads as a broken collector rather
// than as data that changes slowly.
func TestSubCadenceFirstRunIsAlwaysDue(t *testing.T) {
	s, _ := newTestSubCadence(15 * time.Minute)
	if !s.due() {
		t.Error("a freshly constructed gate is not due; the first poll must fetch everything")
	}
}

func TestSubCadenceGatesUntilTheIntervalElapses(t *testing.T) {
	s, clk := newTestSubCadence(15 * time.Minute)
	s.mark()

	// Step to each checkpoint absolutely rather than accumulating, so the assertion
	// cannot drift away from the boundary it claims to test.
	elapsed := time.Duration(0)
	for _, checkpoint := range []time.Duration{0, time.Minute, 14 * time.Minute, 15*time.Minute - time.Nanosecond} {
		clk.advance(checkpoint - elapsed)
		elapsed = checkpoint
		if s.due() {
			t.Errorf("gate is due %v after a successful run, want it held until 15m", elapsed)
		}
	}

	clk.advance(15*time.Minute - elapsed)
	if !s.due() {
		t.Error("gate is not due at exactly the interval; the boundary must be inclusive or a " +
			"15m gate on a 60s poll drifts to 16m forever")
	}
}

// TestSubCadenceFailureRetriesImmediately is the reason due() and mark() are
// separate calls. A caller that marked on every attempt — successful or not — would
// turn one failed sub-fetch into a full interval of stale data, and the operator
// would see a value that is simply wrong with nothing anywhere saying why.
func TestSubCadenceFailureRetriesImmediately(t *testing.T) {
	s, clk := newTestSubCadence(15 * time.Minute)

	// Poll 1: due, fetch fails, so the caller does NOT mark.
	if !s.due() {
		t.Fatal("precondition: first run should be due")
	}
	clk.advance(time.Minute)

	// Poll 2, one minute later: still due, because nothing succeeded yet.
	if !s.due() {
		t.Fatal("gate closed after a FAILED sub-fetch; a failure must retry on the next poll, " +
			"not park stale data for the whole interval")
	}
	s.mark() // this one succeeded
	clk.advance(time.Minute)
	if s.due() {
		t.Error("gate is still due one minute after a successful run")
	}
}

// TestSubCadenceNonPositiveIntervalIsAlwaysDue gives a caller a branch-free way to
// disable the gate (an operator override, or a test that wants every poll to fetch).
func TestSubCadenceNonPositiveIntervalIsAlwaysDue(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Minute} {
		s, clk := newTestSubCadence(interval)
		s.mark()
		clk.advance(time.Nanosecond)
		if !s.due() {
			t.Errorf("gate with interval %v is not due; a non-positive interval must disable it", interval)
		}
	}
}

// TestSubCadenceNilIsAlwaysDue keeps an un-wired gate from silently suppressing a
// sub-fetch — the failure mode would be a collector that quietly stops fetching half
// its data, which no test elsewhere would notice.
func TestSubCadenceNilIsAlwaysDue(t *testing.T) {
	var s *subCadence
	if !s.due() {
		t.Error("a nil gate is not due; an unwired gate must never suppress a fetch")
	}
	s.mark() // must not panic
}

func TestSubCadenceIsConcurrencySafe(t *testing.T) {
	s := newSubCadence(time.Millisecond)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(2)
		go func() { defer wg.Done(); s.due() }()
		go func() { defer wg.Done(); s.mark() }()
	}
	wg.Wait()
}
