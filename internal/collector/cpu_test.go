package collector

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"

	"github.com/rknightion/opnsense2otel/v5/internal/cpustream"
)

// collectCPU registers a cpu collector against a fixed stream snapshot and returns
// the emitted metrics keyed by "<family name>|<mode label>" (mode empty when the
// metric has none).
func collectCPU(t *testing.T, snap cpustream.Snapshot) map[string]float64 {
	t.Helper()
	prev := CPUStream.src.Load()
	t.Cleanup(func() { CPUStream.src.Store(prev) })
	CPUStream.Configure(func() cpustream.Snapshot { return snap })

	c := &cpuCollector{subsystem: CPUSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	ch := make(chan prometheus.Metric, 64)
	if err := c.Update(t.Context(), nil, ch); err != nil {
		t.Fatalf("Update: %v", err)
	}
	close(ch)

	out := map[string]float64{}
	for m := range ch {
		desc := m.Desc().String()
		name := ""
		for _, n := range []string{
			"opnsense_cpu_seconds_total",
			"opnsense_cpu_stream_up",
			"opnsense_cpu_stream_last_frame_age_seconds",
			"opnsense_cpu_stream_reconnects_total",
			"opnsense_cpu_stream_frames_total",
			"opnsense_cpu_stream_counters_published",
		} {
			// seconds_total is a prefix of nothing else, but stream_up is a prefix of
			// nothing either; match the longest that fits to stay unambiguous.
			if strings.Contains(desc, `fqName: "`+n+`"`) {
				name = n
				break
			}
		}
		if name == "" {
			t.Fatalf("unexpected metric: %s", desc)
		}
		out[name+"|"+getMetricLabels(m)["mode"]] = getMetricValue(m)
	}
	return out
}

func freshSnapshot() cpustream.Snapshot {
	return cpustream.Snapshot{
		Connected:    true,
		HaveFrame:    true,
		LastFrameAge: 900 * time.Millisecond,
		Reconnects:   2,
		Frames:       417,
		Fresh:        true,
		Seconds: map[string]float64{
			cpustream.ModeUser: 12, cpustream.ModeNice: 0, cpustream.ModeSystem: 3,
			cpustream.ModeInterrupt: 1, cpustream.ModeIdle: 400,
		},
	}
}

func TestCPUCollectorPublishesCountersWhileFresh(t *testing.T) {
	got := collectCPU(t, freshSnapshot())

	for _, mode := range cpustream.Modes {
		if _, ok := got["opnsense_cpu_seconds_total|"+mode]; !ok {
			t.Errorf("missing cpu_seconds_total for mode %q", mode)
		}
	}
	for name, want := range map[string]float64{
		"opnsense_cpu_seconds_total|user":             12,
		"opnsense_cpu_seconds_total|idle":             400,
		"opnsense_cpu_stream_up|":                     1,
		"opnsense_cpu_stream_counters_published|":     1,
		"opnsense_cpu_stream_reconnects_total|":       2,
		"opnsense_cpu_stream_frames_total|":           417,
		"opnsense_cpu_stream_last_frame_age_seconds|": 0.9,
	} {
		if got[name] != want {
			t.Errorf("%s = %v, want %v", name, got[name], want)
		}
	}
}

// TestCPUCollectorWithdrawsCountersWhenStale pins #559 decision 2. A counter frozen
// by a dead stream is not merely unhelpful, it is actively misleading: rate() over a
// window entirely inside the freeze reads exactly zero, which is indistinguishable
// from a genuinely idle CPU. The stream-health series must survive so the cause is
// visible rather than inferred.
func TestCPUCollectorWithdrawsCountersWhenStale(t *testing.T) {
	snap := freshSnapshot()
	snap.Fresh = false
	snap.Connected = false
	snap.LastFrameAge = 5 * time.Minute
	got := collectCPU(t, snap)

	for _, mode := range cpustream.Modes {
		if _, ok := got["opnsense_cpu_seconds_total|"+mode]; ok {
			t.Errorf("cpu_seconds_total for mode %q must be ABSENT once stale, not frozen", mode)
		}
	}
	for name, want := range map[string]float64{
		"opnsense_cpu_stream_up|":                     0,
		"opnsense_cpu_stream_counters_published|":     0,
		"opnsense_cpu_stream_last_frame_age_seconds|": 300,
		"opnsense_cpu_stream_frames_total|":           417,
	} {
		if got[name] != want {
			t.Errorf("%s = %v, want %v (health must stay exported while the counters are withdrawn)", name, got[name], want)
		}
	}
}

// TestCPUCollectorBeforeAnyFrame: age is absent rather than zero, because a zero
// would read as a perfectly fresh stream on every freshness panel.
func TestCPUCollectorBeforeAnyFrame(t *testing.T) {
	got := collectCPU(t, cpustream.Snapshot{Seconds: map[string]float64{}})

	if _, ok := got["opnsense_cpu_stream_last_frame_age_seconds|"]; ok {
		t.Error("last-frame-age must be absent before the first frame, not zero")
	}
	if got["opnsense_cpu_stream_up|"] != 0 {
		t.Error("stream_up must be exported as 0 before the first connection")
	}
}

// TestCPUCollectorIsSilentWithoutAStream: an unwired holder must not panic, and must
// report the stream down rather than emitting nothing at all.
func TestCPUCollectorIsSilentWithoutAStream(t *testing.T) {
	prev := CPUStream.src.Load()
	t.Cleanup(func() { CPUStream.src.Store(prev) })
	CPUStream.src.Store(nil)

	c := &cpuCollector{subsystem: CPUSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	ch := make(chan prometheus.Metric, 32)
	if err := c.Update(t.Context(), nil, ch); err != nil {
		t.Fatalf("Update: %v", err)
	}
	close(ch)
	if len(ch) == 0 {
		t.Error("an unwired stream must still report its state")
	}
}

// TestCPUCollectorIsFastAndFree pins why the cpu collector may sit on the fast tier
// without costing the firewall anything: it reads a stream-fed accumulator and makes
// no API call, which is also why every Update above is called with a nil client and
// does not panic. Fast tier buys 15s CPU resolution for an operator running
// --otlp.fast-export-interval, and 15s stall detection, for free.
func TestCPUCollectorIsFastAndFree(t *testing.T) {
	if collectorTiers[CPUSubsystem] != IntervalFast {
		t.Errorf("cpu tier = %v, want fast: it makes no API call, so freshness is free",
			collectorTiers[CPUSubsystem])
	}
}
