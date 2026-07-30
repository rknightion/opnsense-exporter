package cpustream

import (
	"math"
	"testing"
	"time"
)

func approx(t *testing.T, got, want float64, what string) {
	t.Helper()
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

func TestParseFrame(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		wantOK  bool
		wantPct map[string]float64
	}{
		{
			name:   "a real frame from the box",
			in:     `{"total":6,"user":3,"nice":0,"sys":3,"intr":0,"idle":94}`,
			wantOK: true,
			wantPct: map[string]float64{
				ModeUser: 3, ModeNice: 0, ModeSystem: 3, ModeInterrupt: 0, ModeIdle: 94,
			},
		},
		{
			name:   "a fully idle box",
			in:     `{"total":0,"user":0,"nice":0,"sys":0,"intr":0,"idle":100}`,
			wantOK: true,
			wantPct: map[string]float64{
				ModeUser: 0, ModeNice: 0, ModeSystem: 0, ModeInterrupt: 0, ModeIdle: 100,
			},
		},
		{name: "not json", in: `oops`},
		{name: "empty", in: ``},
		{name: "missing every field", in: `{"total":6}`},
		// A percentage set that cannot be a percentage set is rejected rather than
		// accumulated: the reconstruction below multiplies these by elapsed wall
		// time, so a bogus 900% would silently invent CPU-seconds that never ran.
		{name: "percentages far over 100", in: `{"user":900,"nice":0,"sys":0,"intr":0,"idle":0}`},
		{name: "negative percentage", in: `{"user":-5,"nice":0,"sys":0,"intr":0,"idle":105}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseFrame([]byte(tc.in))
			if ok != tc.wantOK {
				t.Fatalf("parseFrame ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			for mode, want := range tc.wantPct {
				approx(t, got[mode], want, "pct["+mode+"]")
			}
		})
	}
}

// TestAccumulatorDiscardsTheFirstFrameOfEachConnection pins the trap found in
// OPNsense's own source: `iostat -w 1` emits its FIRST report as an average since
// boot, not as a one-second delta (cpu.py runs `iostat -w <interval> cpu` and passes
// every non-header line straight through). Attributing a since-boot average to one
// interval would skew the counter on every single reconnect. Discarding it also
// solves the independent problem that the first frame has no predecessor to measure
// elapsed time against.
func TestAccumulatorDiscardsTheFirstFrameOfEachConnection(t *testing.T) {
	a := newAccumulator(5 * time.Second)
	base := time.Unix(1_800_000_000, 0)

	a.beginConnection()
	a.observe(map[string]float64{ModeUser: 100, ModeIdle: 0}, base)
	for _, m := range Modes {
		approx(t, a.seconds()[m], 0, "seconds["+m+"] after only the since-boot frame")
	}

	a.observe(map[string]float64{ModeUser: 50, ModeIdle: 50}, base.Add(time.Second))
	approx(t, a.seconds()[ModeUser], 0.5, "seconds[user]")
	approx(t, a.seconds()[ModeIdle], 0.5, "seconds[idle]")

	// A reconnect must discard the next since-boot frame too, while KEEPING the
	// accumulated total — the process never restarted, so the counter must not reset.
	a.beginConnection()
	a.observe(map[string]float64{ModeUser: 100, ModeIdle: 0}, base.Add(2*time.Second))
	approx(t, a.seconds()[ModeUser], 0.5, "seconds[user] must survive a reconnect unchanged")
}

func TestAccumulatorUsesMeasuredElapsedNotAFixedInterval(t *testing.T) {
	a := newAccumulator(5 * time.Second)
	base := time.Unix(1_800_000_000, 0)
	a.beginConnection()
	a.observe(map[string]float64{ModeIdle: 100}, base)

	// Frame delivery jitters; a hardcoded 1s would drift against real time.
	a.observe(map[string]float64{ModeSystem: 100}, base.Add(1400*time.Millisecond))
	approx(t, a.seconds()[ModeSystem], 1.4, "seconds[system]")
}

// TestAccumulatorRefusesToInventTimeAcrossAGap pins that an unobserved gap stays
// unobserved. A frame arriving long after its predecessor describes only its own
// sample interval, not the whole gap — multiplying it out would fabricate CPU
// seconds for a window nothing was measured in.
func TestAccumulatorRefusesToInventTimeAcrossAGap(t *testing.T) {
	a := newAccumulator(5 * time.Second)
	base := time.Unix(1_800_000_000, 0)
	a.beginConnection()
	a.observe(map[string]float64{ModeIdle: 100}, base)
	a.observe(map[string]float64{ModeIdle: 100}, base.Add(time.Second))
	approx(t, a.seconds()[ModeIdle], 1, "seconds[idle] before the gap")

	a.observe(map[string]float64{ModeUser: 100}, base.Add(time.Minute))
	approx(t, a.seconds()[ModeIdle], 1, "the gap must not be accumulated")
	approx(t, a.seconds()[ModeUser], 0, "the gap must not be accumulated")

	// The timebase is re-established by the gap frame, so the NEXT frame accumulates
	// normally rather than the stream staying stuck.
	a.observe(map[string]float64{ModeUser: 100}, base.Add(time.Minute+time.Second))
	approx(t, a.seconds()[ModeUser], 1, "accumulation must resume after the gap")
}

func TestAccumulatorSecondsIsACopy(t *testing.T) {
	a := newAccumulator(5 * time.Second)
	base := time.Unix(1_800_000_000, 0)
	a.beginConnection()
	a.observe(map[string]float64{ModeIdle: 100}, base)
	a.observe(map[string]float64{ModeIdle: 100}, base.Add(time.Second))

	got := a.seconds()
	got[ModeIdle] = 999
	approx(t, a.seconds()[ModeIdle], 1, "mutating the returned map must not corrupt the accumulator")
}
