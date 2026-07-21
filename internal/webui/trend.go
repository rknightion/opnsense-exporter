package webui

import (
	"sync"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/rknightion/opnsense-exporter/internal/collector"
)

// TrendStats holds the bounded ~10-minute trend series behind three Overview
// charts: active series, emitted throughput, and the collector-fleet aggregate.
// It is filled by trendSampler.stats().
//
// Every *Series field is oldest→newest and bounded by the sampler's ring. The
// rate series are one shorter than the value series (a rate needs two samples),
// mirroring RuntimeStats.GCRateSeries.
type TrendStats struct {
	// SeriesCount is the number of active time series currently exposed at
	// /metrics, counted from the passive metric snapshot the console already
	// holds — no extra gather.
	SeriesCount       int
	SeriesCountSeries []int

	// LogShipping reports whether a log-shipping pipeline is running. When it is
	// false the rate series are nil rather than zero: this is a Prometheus PULL
	// exporter, so with --logs.enabled off there is no emit boundary at all, and a
	// flat 0/s would claim we are shipping nothing when in truth nothing is
	// configured to ship.
	LogShipping       bool
	ShippedRate       float64 // newest records/sec confirmed exported
	DroppedRate       float64 // newest records/sec lost before delivery
	ShippedRateSeries []float64
	DroppedRateSeries []float64

	// Collector-fleet aggregate, rolled up across every tracked collector on each
	// sampler tick.
	ActiveCollectors     int
	FailingCollectors    int
	MeanDurationMs       float64
	FailingSeries        []int
	MeanDurationMsSeries []float64
}

// trendSample is one observation: the exposed series count, the fleet roll-up,
// and the raw process-lifetime log-shipping totals (differenced into rates by
// stats(), never stored as rates).
type trendSample struct {
	at      time.Time
	series  int
	active  int
	failing int
	meanMs  float64
	shipped uint64
	dropped uint64
}

// trendSampler keeps a bounded ring of trend observations sampled on the same
// background ticker as the runtime sampler, so the Overview tab can show the
// trend without any live API call — or any Gather. It mirrors growthSampler's
// shape (immediate first sample, ticker, stop channel).
type trendSampler struct {
	mu   sync.Mutex
	ring []trendSample
	max  int
	stop chan struct{}
	// logShipping is fixed at construction: whether a log-shipping pipeline exists
	// to measure at all. See TrendStats.LogShipping.
	logShipping bool
}

// newTrendSampler returns a sampler bounded at max observations (min 2).
func newTrendSampler(max int) *trendSampler {
	if max < 2 {
		max = 2
	}
	return &trendSampler{max: max}
}

// sample records one observation, evicting the oldest once the ring is full.
func (t *trendSampler) sample(s trendSample) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ring = append(t.ring, s)
	if len(t.ring) > t.max {
		t.ring = t.ring[len(t.ring)-t.max:]
	}
}

// stats returns the latest observation plus the trend series. Returns a zero
// value (with LogShipping still set) when no sample exists yet.
func (t *trendSampler) stats() TrendStats {
	t.mu.Lock()
	defer t.mu.Unlock()

	st := TrendStats{LogShipping: t.logShipping}
	n := len(t.ring)
	if n == 0 {
		return st
	}

	last := t.ring[n-1]
	st.SeriesCount = last.series
	st.ActiveCollectors = last.active
	st.FailingCollectors = last.failing
	st.MeanDurationMs = last.meanMs

	st.SeriesCountSeries = make([]int, n)
	st.FailingSeries = make([]int, n)
	st.MeanDurationMsSeries = make([]float64, n)
	for i, s := range t.ring {
		st.SeriesCountSeries[i] = s.series
		st.FailingSeries[i] = s.failing
		st.MeanDurationMsSeries[i] = s.meanMs
	}

	if !t.logShipping || n < 2 {
		return st
	}
	st.ShippedRateSeries = make([]float64, 0, n-1)
	st.DroppedRateSeries = make([]float64, 0, n-1)
	for i := 1; i < n; i++ {
		elapsed := t.ring[i].at.Sub(t.ring[i-1].at)
		st.ShippedRateSeries = append(st.ShippedRateSeries,
			perSecond(t.ring[i-1].shipped, t.ring[i].shipped, elapsed))
		st.DroppedRateSeries = append(st.DroppedRateSeries,
			perSecond(t.ring[i-1].dropped, t.ring[i].dropped, elapsed))
	}
	st.ShippedRate = st.ShippedRateSeries[len(st.ShippedRateSeries)-1]
	st.DroppedRate = st.DroppedRateSeries[len(st.DroppedRateSeries)-1]
	return st
}

// start begins background sampling every interval until close is called. It takes
// one sample immediately so a freshly-loaded page isn't blank. Safe to call once;
// a nil collect func or non-positive interval is a no-op.
func (t *trendSampler) start(collect func() trendSample, interval time.Duration) {
	if collect == nil || interval <= 0 || t.stop != nil {
		return
	}
	t.stop = make(chan struct{})
	go func() {
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			t.sample(collect())
			select {
			case <-t.stop:
				return
			case <-tick.C:
			}
		}
	}()
}

// close stops background sampling.
func (t *trendSampler) close() {
	if t.stop != nil {
		close(t.stop)
		t.stop = nil
	}
}

// perSecond returns the per-second rate of a monotonic counter between two
// samples. It yields 0 — never a negative, infinite or NaN rate — when no time
// elapsed, when the counter did not move, or when it went backwards (only
// possible on a process restart, which restarts the sampler anyway).
func perSecond(prev, cur uint64, elapsed time.Duration) float64 {
	secs := elapsed.Seconds()
	if secs <= 0 || cur <= prev {
		return 0
	}
	return float64(cur-prev) / secs
}

// aggregateFleet rolls the per-collector status snapshot up into the three fleet
// numbers the console charts. active counts every tracked collector (matching
// ExporterStats.ActiveCollectors); failing counts those whose LAST run failed —
// a collector that has never run is starting, not failing; meanMs is the mean
// last-run duration over collectors that have actually run, so never-run zeroes
// cannot drag the mean down.
func aggregateFleet(stats []collector.CollectorStat) (active, failing int, meanMs float64) {
	active = len(stats)
	var sum float64
	var ran int
	for _, s := range stats {
		if s.Runs == 0 {
			continue
		}
		ran++
		sum += s.LastDurationMs
		if !s.LastOK {
			failing++
		}
	}
	if ran > 0 {
		meanMs = sum / float64(ran)
	}
	return active, failing, meanMs
}

// countSeries totals the time series across a metric-family set.
func countSeries(families []*dto.MetricFamily) int {
	series := 0
	for _, mf := range families {
		series += len(mf.GetMetric())
	}
	return series
}
