package cpustream

import (
	"encoding/json"
	"time"
)

// Mode label values for cpu_seconds_total. A closed, code-defined set — these are
// exactly the five states FreeBSD's iostat reports and OPNsense's cpu.py forwards.
const (
	ModeUser      = "user"
	ModeNice      = "nice"
	ModeSystem    = "system"
	ModeInterrupt = "interrupt"
	ModeIdle      = "idle"
)

// Modes is the fixed emission order, so the exported series are stable.
var Modes = []string{ModeUser, ModeNice, ModeSystem, ModeInterrupt, ModeIdle}

// frame is one SSE payload. The wire keys are OPNsense's, not ours: cpu.py builds
// `{'total':…, 'user':…, 'nice':…, 'sys':…, 'intr':…, 'idle':…}`. Pointers so a
// missing key is distinguishable from a legitimate zero — a frame that carried no
// CPU data at all would otherwise read as a fully idle box.
//
// `total` is deliberately not decoded: it is `sum(all) - idle`, i.e. derivable, and
// exporting a sixth mode that overlaps the other five would double-count under any
// sum-by-mode aggregation.
type frame struct {
	User *float64 `json:"user"`
	Nice *float64 `json:"nice"`
	Sys  *float64 `json:"sys"`
	Intr *float64 `json:"intr"`
	Idle *float64 `json:"idle"`
}

// parseFrame decodes one `data:` payload into per-mode percentages.
//
// Values are integer percentages: cpu.py does `formatted = [int(x) for x in
// formatted]` before serialising, so each sample carries up to ±0.5% quantisation
// noise. That noise is unbiased, so it does not accumulate systematically over the
// counter's life, but it is why the metric HELP text says the counter is a
// reconstruction rather than a kernel tick counter.
//
// A frame whose values cannot be percentages is rejected outright rather than
// clamped. The accumulator multiplies these by elapsed wall time, so accepting a
// nonsense 900% would silently invent CPU-seconds that never ran — and a fabricated
// counter is worse than an absent one.
func parseFrame(b []byte) (map[string]float64, bool) {
	var f frame
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, false
	}
	fields := map[string]*float64{
		ModeUser: f.User, ModeNice: f.Nice, ModeSystem: f.Sys,
		ModeInterrupt: f.Intr, ModeIdle: f.Idle,
	}
	out := make(map[string]float64, len(Modes))
	for mode, v := range fields {
		if v == nil {
			return nil, false
		}
		// A little headroom over 100 for rounding; anything beyond is not a
		// percentage and the whole frame is untrustworthy.
		if *v < 0 || *v > 101 {
			return nil, false
		}
		out[mode] = *v
	}
	return out, true
}

// accumulator reconstructs cumulative per-mode CPU seconds from a stream of
// instantaneous percentage samples: `seconds[mode] += (pct/100) * elapsed`, where
// elapsed is the MEASURED time since the previous frame.
//
// Not safe for concurrent use; Stream owns the locking.
type accumulator struct {
	// total is the cumulative counter. It survives reconnects: the exporter process
	// never restarted, so resetting it would publish a spurious counter reset.
	total map[string]float64
	// last is when the previous accepted frame arrived, or the zero time when the
	// timebase is not established (before the first frame of a connection).
	last time.Time
	// maxGap bounds how much wall time one frame may be credited with. A frame
	// describes only its own ~1s sample interval, so a longer gap is time nothing
	// measured — see observe.
	maxGap time.Duration
}

func newAccumulator(maxGap time.Duration) *accumulator {
	return &accumulator{total: make(map[string]float64, len(Modes)), maxGap: maxGap}
}

// beginConnection resets the timebase without touching the totals, and is called on
// every (re)connect.
//
// It exists for a reason that is invisible unless you read OPNsense's source:
// `iostat -w <interval>` prints its FIRST report as an average since boot, not as an
// interval delta, and cpu.py forwards every non-header line unfiltered. Attributing
// a since-boot average to a one-second interval would skew the counter on every
// reconnect. Dropping the first frame of each connection fixes that, and happens to
// be required anyway — that frame has no predecessor to measure elapsed against.
func (a *accumulator) beginConnection() {
	a.last = time.Time{}
}

// observe folds one frame into the counter. The first frame after beginConnection
// only establishes the timebase.
func (a *accumulator) observe(pct map[string]float64, at time.Time) {
	prev := a.last
	a.last = at
	if prev.IsZero() {
		return
	}
	elapsed := at.Sub(prev)
	// A non-positive or oversized elapsed is not accumulated. Time we did not
	// observe stays unobserved: crediting a whole stalled minute to one 1-second
	// sample would fabricate the shape of that minute. The timebase is still
	// advanced (above), so the next frame accumulates normally.
	if elapsed <= 0 || elapsed > a.maxGap {
		return
	}
	secs := elapsed.Seconds()
	for _, mode := range Modes {
		a.total[mode] += pct[mode] / 100 * secs
	}
}

// seconds returns a copy of the cumulative per-mode counter.
func (a *accumulator) seconds() map[string]float64 {
	out := make(map[string]float64, len(Modes))
	for _, mode := range Modes {
		out[mode] = a.total[mode]
	}
	return out
}
