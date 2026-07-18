package webui

import (
	"math"
	"sort"
	"sync"
	"time"

	dto "github.com/prometheus/client_model/go"
)

// growthSampler keeps a bounded ring of per-family series counts sampled on a
// background ticker, so the cardinality page can show a per-minute series
// growth rate. It samples the passive metricsnap snapshot (Deps.Metrics), so it
// never triggers a scrape of its own.
type growthSampler struct {
	mu   sync.Mutex
	ring []growthSample
	max  int
	stop chan struct{}
}

type growthSample struct {
	at     time.Time
	counts map[string]int // family name -> series count
}

func newGrowthSampler(max int) *growthSampler {
	if max < 2 {
		max = 2
	}
	return &growthSampler{max: max}
}

// sample records one observation of the current family series counts.
func (g *growthSampler) sample(families []*dto.MetricFamily) {
	if len(families) == 0 {
		return
	}
	counts := make(map[string]int, len(families))
	for _, mf := range families {
		counts[mf.GetName()] = len(mf.GetMetric())
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ring = append(g.ring, growthSample{at: time.Now(), counts: counts})
	if len(g.ring) > g.max {
		g.ring = g.ring[len(g.ring)-g.max:]
	}
}

// rows computes signed per-minute growth per family from the oldest and newest
// samples in the ring. Returns nil until at least two samples span a positive
// interval. Families with zero net change are omitted; the rest are sorted by
// absolute rate, fastest first.
func (g *growthSampler) rows() []GrowthRow {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.ring) < 2 {
		return nil
	}
	oldest, newest := g.ring[0], g.ring[len(g.ring)-1]
	mins := newest.at.Sub(oldest.at).Minutes()
	if mins <= 0 {
		return nil
	}
	rows := make([]GrowthRow, 0, len(newest.counts))
	for name, now := range newest.counts {
		delta := now - oldest.counts[name]
		if delta == 0 {
			continue
		}
		rows = append(rows, GrowthRow{Name: name, Series: now, PerMin: float64(delta) / mins})
	}
	sort.Slice(rows, func(i, j int) bool {
		if math.Abs(rows[i].PerMin) != math.Abs(rows[j].PerMin) {
			return math.Abs(rows[i].PerMin) > math.Abs(rows[j].PerMin)
		}
		return rows[i].Name < rows[j].Name
	})
	return rows
}

// start begins background sampling every interval until stop is called. It
// takes one sample immediately so a freshly-loaded page isn't blank. Safe to
// call once; a nil getter or non-positive interval is a no-op.
func (g *growthSampler) start(getter func() ([]*dto.MetricFamily, time.Time), interval time.Duration) {
	if getter == nil || interval <= 0 || g.stop != nil {
		return
	}
	g.stop = make(chan struct{})
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			fams, _ := getter()
			g.sample(fams)
			select {
			case <-g.stop:
				return
			case <-t.C:
			}
		}
	}()
}

func (g *growthSampler) close() {
	if g.stop != nil {
		close(g.stop)
		g.stop = nil
	}
}
