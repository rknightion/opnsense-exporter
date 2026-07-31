package webui

import (
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/rknightion/opnsense2otel/v4/internal/metricsnap"

	"github.com/rknightion/opnsense2otel/v4/internal/collector"
)

func TestPerSecond_NormalDelta(t *testing.T) {
	if got := perSecond(100, 160, 30*time.Second); got < 1.99 || got > 2.01 {
		t.Fatalf("perSecond(100,160,30s) = %v, want ~2", got)
	}
}

func TestPerSecond_CounterDidNotMove(t *testing.T) {
	if got := perSecond(100, 100, 30*time.Second); got != 0 {
		t.Fatalf("unmoved counter must rate to 0, got %v", got)
	}
}

func TestPerSecond_NoElapsedOrWentBackwards(t *testing.T) {
	if got := perSecond(100, 160, 0); got != 0 {
		t.Fatalf("zero elapsed must rate to 0 (never +Inf), got %v", got)
	}
	if got := perSecond(100, 160, -time.Second); got != 0 {
		t.Fatalf("negative elapsed must rate to 0, got %v", got)
	}
	// A counter can only go backwards on a reset; a negative rate would be a lie.
	if got := perSecond(160, 100, 30*time.Second); got != 0 {
		t.Fatalf("counter reset must rate to 0, got %v", got)
	}
}

// The first sample has no prior total to difference against, so the sampler must
// publish NO rate for it — the rate series is one shorter than the value series,
// exactly like RuntimeStats.GCRateSeries.
func TestTrendSampler_FirstSampleYieldsNoRate(t *testing.T) {
	tr := newTrendSampler(8)
	tr.logShipping = true
	tr.sample(trendSample{at: time.Now(), shipped: 10})

	st := tr.stats()
	if len(st.SeriesCountSeries) != 1 {
		t.Fatalf("SeriesCountSeries len = %d, want 1", len(st.SeriesCountSeries))
	}
	if len(st.ShippedRateSeries) != 0 {
		t.Fatalf("one sample must yield no rate, got %v", st.ShippedRateSeries)
	}
	if st.ShippedRate != 0 {
		t.Fatalf("ShippedRate = %v, want 0 with no prior total", st.ShippedRate)
	}
}

func TestTrendSampler_RatesFromAdjacentSamples(t *testing.T) {
	now := time.Now()
	tr := newTrendSampler(8)
	tr.logShipping = true
	tr.sample(trendSample{at: now.Add(-60 * time.Second), shipped: 0, dropped: 0})
	tr.sample(trendSample{at: now.Add(-30 * time.Second), shipped: 60, dropped: 3})
	tr.sample(trendSample{at: now, shipped: 60, dropped: 3}) // idle tick

	st := tr.stats()
	if len(st.ShippedRateSeries) != 2 || len(st.DroppedRateSeries) != 2 {
		t.Fatalf("rate series len = %d/%d, want 2/2 (N-1 deltas)",
			len(st.ShippedRateSeries), len(st.DroppedRateSeries))
	}
	if got := st.ShippedRateSeries[0]; got < 1.99 || got > 2.01 {
		t.Errorf("ShippedRateSeries[0] = %v, want ~2/s", got)
	}
	if got := st.ShippedRateSeries[1]; got != 0 {
		t.Errorf("idle tick must rate to 0, got %v", got)
	}
	if st.ShippedRate != st.ShippedRateSeries[1] {
		t.Errorf("ShippedRate = %v, want the newest rate %v", st.ShippedRate, st.ShippedRateSeries[1])
	}
	if got := st.DroppedRateSeries[0]; got < 0.09 || got > 0.11 {
		t.Errorf("DroppedRateSeries[0] = %v, want ~0.1/s", got)
	}
}

// With no log-shipping pipeline running there is no emit boundary to measure, so
// the console must publish no rate series at all rather than a flat zero that
// would read as "shipping nothing".
func TestTrendSampler_NoLogShippingPublishesNoRates(t *testing.T) {
	now := time.Now()
	tr := newTrendSampler(8)
	tr.sample(trendSample{at: now.Add(-30 * time.Second)})
	tr.sample(trendSample{at: now})

	st := tr.stats()
	if st.LogShipping {
		t.Fatal("LogShipping true with no throughput source")
	}
	if st.ShippedRateSeries != nil || st.DroppedRateSeries != nil {
		t.Fatalf("want nil rate series, got %v/%v", st.ShippedRateSeries, st.DroppedRateSeries)
	}
}

func TestTrendSampler_RingBounded(t *testing.T) {
	tr := newTrendSampler(3)
	for i := 0; i < 10; i++ {
		tr.sample(trendSample{at: time.Now(), series: i})
	}
	if got := len(tr.stats().SeriesCountSeries); got != 3 {
		t.Fatalf("SeriesCountSeries len = %d, want 3 (ring bounded)", got)
	}
}

func TestTrendSampler_FleetAndSeriesSeries(t *testing.T) {
	now := time.Now()
	tr := newTrendSampler(8)
	tr.sample(trendSample{at: now.Add(-30 * time.Second), series: 100, active: 4, failing: 0, meanMs: 10})
	tr.sample(trendSample{at: now, series: 120, active: 5, failing: 2, meanMs: 12.5})

	st := tr.stats()
	if st.SeriesCount != 120 {
		t.Errorf("SeriesCount = %d, want 120", st.SeriesCount)
	}
	if st.ActiveCollectors != 5 || st.FailingCollectors != 2 {
		t.Errorf("active/failing = %d/%d, want 5/2", st.ActiveCollectors, st.FailingCollectors)
	}
	if st.MeanDurationMs != 12.5 {
		t.Errorf("MeanDurationMs = %v, want 12.5", st.MeanDurationMs)
	}
	if len(st.FailingSeries) != 2 || st.FailingSeries[1] != 2 {
		t.Errorf("FailingSeries = %v, want [0 2]", st.FailingSeries)
	}
	if len(st.MeanDurationMsSeries) != 2 || st.MeanDurationMsSeries[0] != 10 {
		t.Errorf("MeanDurationMsSeries = %v, want [10 12.5]", st.MeanDurationMsSeries)
	}
}

func TestTrendSampler_StatsEmptyBeforeFirstSample(t *testing.T) {
	st := newTrendSampler(8).stats()
	if st.SeriesCountSeries != nil || st.FailingSeries != nil || st.MeanDurationMsSeries != nil {
		t.Fatalf("want a zero TrendStats before the first sample, got %+v", st)
	}
}

func TestAggregateFleet(t *testing.T) {
	stats := []collector.CollectorStat{
		{Name: "a", Runs: 5, LastOK: true, LastDurationMs: 10},
		{Name: "b", Runs: 5, LastOK: false, LastDurationMs: 30},
		{Name: "c", Runs: 0, LastOK: false, LastDurationMs: 0}, // never run: not failing
	}
	active, failing, meanMs := aggregateFleet(stats)
	if active != 3 {
		t.Errorf("active = %d, want 3 (every tracked collector)", active)
	}
	if failing != 1 {
		t.Errorf("failing = %d, want 1 (never-run is not failing)", failing)
	}
	// mean over collectors that HAVE run: (10+30)/2.
	if meanMs != 20 {
		t.Errorf("meanMs = %v, want 20", meanMs)
	}
}

func TestAggregateFleet_NoRunsYet(t *testing.T) {
	active, failing, meanMs := aggregateFleet([]collector.CollectorStat{{Name: "a"}})
	if active != 1 || failing != 0 || meanMs != 0 {
		t.Fatalf("got %d/%d/%v, want 1/0/0", active, failing, meanMs)
	}
}

func TestAggregateFleet_Empty(t *testing.T) {
	active, failing, meanMs := aggregateFleet(nil)
	if active != 0 || failing != 0 || meanMs != 0 {
		t.Fatalf("got %d/%d/%v, want 0/0/0", active, failing, meanMs)
	}
}

func TestCountSeries(t *testing.T) {
	if got := countSeries([]*dto.MetricFamily{famWith("a", 3), famWith("b", 4)}); got != 7 {
		t.Fatalf("countSeries = %d, want 7", got)
	}
	if got := countSeries(nil); got != 0 {
		t.Fatalf("countSeries(nil) = %d, want 0", got)
	}
}

// trendSample must read the SAME passive sources the rest of the console does —
// the metricsnap snapshot and the status tracker — plus the log-shipping
// counters, and never gather.
func TestServer_TrendSample_ReadsPassiveDeps(t *testing.T) {
	tracker := collector.NewStatusTracker()
	tracker.Record("a", time.Now(), 10, true, "")
	tracker.Record("b", time.Now(), 30, false, "boom")

	d := testDeps()
	d.Tracker = tracker
	d.Capture = func() metricsnap.Capture {
		return metricsnap.Capture{Families: []*dto.MetricFamily{famWith("m", 12)}, At: time.Now()}
	}
	d.LogThroughput = func() (uint64, uint64) { return 700, 7 }

	srv := NewServer(d)
	s := srv.trendSample()
	if s.series != 12 {
		t.Errorf("series = %d, want 12", s.series)
	}
	if s.active != 2 || s.failing != 1 {
		t.Errorf("active/failing = %d/%d, want 2/1", s.active, s.failing)
	}
	if s.meanMs != 20 {
		t.Errorf("meanMs = %v, want 20", s.meanMs)
	}
	if s.shipped != 700 || s.dropped != 7 {
		t.Errorf("shipped/dropped = %d/%d, want 700/7", s.shipped, s.dropped)
	}
	if s.at.IsZero() {
		t.Error("sample timestamp not set")
	}
}

func TestNewServer_LogShippingFlagFollowsDeps(t *testing.T) {
	if NewServer(testDeps()).trend.stats().LogShipping {
		t.Error("LogShipping true with a nil LogThroughput")
	}
	d := testDeps()
	d.LogThroughput = func() (uint64, uint64) { return 0, 0 }
	if !NewServer(d).trend.stats().LogShipping {
		t.Error("LogShipping false with a wired LogThroughput")
	}
}

func TestSnapshotCarriesTrend(t *testing.T) {
	tracker := collector.NewStatusTracker()
	tracker.Record("a", time.Now(), 12, true, "")

	d := testDeps()
	d.Tracker = tracker
	d.Capture = func() metricsnap.Capture {
		return metricsnap.Capture{Families: []*dto.MetricFamily{famWith("m", 9)}, At: time.Now()}
	}
	srv := NewServer(d)
	srv.trend.sample(srv.trendSample())

	st := srv.snapshot()
	if st.Trend.SeriesCount != 9 {
		t.Errorf("Trend.SeriesCount = %d, want 9", st.Trend.SeriesCount)
	}
	if st.Trend.ActiveCollectors != 1 {
		t.Errorf("Trend.ActiveCollectors = %d, want 1", st.Trend.ActiveCollectors)
	}
	if len(st.Trend.SeriesCountSeries) != 1 {
		t.Errorf("Trend.SeriesCountSeries = %v, want one point", st.Trend.SeriesCountSeries)
	}
}
