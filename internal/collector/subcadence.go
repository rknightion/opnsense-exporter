package collector

import (
	"sync"
	"time"
)

// subCadence gates one sub-fetch inside a collector's Update to a slower cadence
// than the collector's own poll tier (#575).
//
// # Why this exists at all
//
// A poll tier is assigned per COLLECTOR, but a collector that issues several
// requests per poll does not necessarily need all of them at the same rate.
// crowdsec is the motivating case: eleven requests per 60s poll, of which six are
// pure hub inventory — counts of installed hub items that change only on a
// `cscli hub upgrade` or an admin install — while the other five carry live
// alert/decision/bouncer state that genuinely needs 60s. At the #535 tax of two
// configd RPCs per request whatever it returns, asking for the static half sixty
// times an hour costs 8,640 requests a day to learn nothing.
//
// The obvious alternatives do not work here. Demoting the collector's tier would
// blunt the live half. A body cache is structurally unavailable: all six are POST
// bootgrid searches, and a POST body is never replayed (#194's ruling — one POST's
// response is not a valid answer to a different POST). So the only lever left is
// cadence inside Update, which is what this is.
//
// # Contract for a caller
//
// The exported metrics MUST NOT change shape. A skipped sub-fetch means the
// collector re-emits its LAST GOOD values, so the series stay continuous and simply
// update less often; a skip must never mean an absent series, because a gauge that
// disappears every other poll reads as a fault rather than as unchanged data.
// Holding the last-good value is the caller's job — see crowdsecCollector.
//
// due() and mark() are deliberately separate. mark() is called only after a
// SUCCESSFUL sub-fetch, so a failure retries on the very next poll instead of
// parking the stale value for another full interval. Coupling them ("check and
// consume in one call") would silently turn one failed fetch into a 15-minute
// outage of that data.
type subCadence struct {
	// interval is the minimum time between successful sub-fetches. A non-positive
	// interval disables the gate entirely: due() is always true, which is what an
	// operator overriding the behaviour off should get.
	interval time.Duration

	// now is injectable so tests assert the boundary exactly rather than sleeping.
	now func() time.Time

	// mu guards last. Update runs on the collector's own poll goroutine, but the
	// scheduler makes no promise that it is the same goroutine every time, and
	// nothing stops a future caller sharing one gate across concurrent sub-fetches.
	mu   sync.Mutex
	last time.Time
}

// newSubCadence returns a gate that admits a sub-fetch at most once per interval.
// The zero last-run time makes the FIRST call due, so a collector's first poll
// after start always fetches everything — anything else would leave the slow half
// absent until the interval elapsed, which looks exactly like a broken collector.
func newSubCadence(interval time.Duration) *subCadence {
	return &subCadence{interval: interval, now: time.Now}
}

// due reports whether the sub-fetch should run on this poll.
func (s *subCadence) due() bool {
	if s == nil {
		return true
	}
	if s.interval <= 0 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last.IsZero() {
		return true
	}
	return s.now().Sub(s.last) >= s.interval
}

// mark records a successful sub-fetch, starting the interval. Call it ONLY on
// success: an errored fetch that marks would park the previous values for another
// full interval, turning a transient API failure into stale data nobody can explain.
func (s *subCadence) mark() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = s.now()
}
