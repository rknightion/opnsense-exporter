package webui

import (
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
)

func famWith(name string, series int) *dto.MetricFamily {
	mf := &dto.MetricFamily{Name: &name}
	for i := 0; i < series; i++ {
		mf.Metric = append(mf.Metric, &dto.Metric{})
	}
	return mf
}

func TestGrowthSampler_NilUntilTwoSamples(t *testing.T) {
	g := newGrowthSampler(30)
	if g.rows() != nil {
		t.Fatal("no samples -> nil")
	}
	g.sample([]*dto.MetricFamily{famWith("m", 10)})
	if g.rows() != nil {
		t.Fatal("one sample -> nil")
	}
}

func TestGrowthSampler_ComputesPerMinute(t *testing.T) {
	g := newGrowthSampler(30)
	// Seed two samples five minutes apart with +50 series of growth.
	g.mu.Lock()
	g.ring = []growthSample{
		{at: time.Now().Add(-5 * time.Minute), counts: map[string]int{"m": 100}},
		{at: time.Now(), counts: map[string]int{"m": 150}},
	}
	g.mu.Unlock()
	rows := g.rows()
	if len(rows) != 1 || rows[0].Name != "m" || rows[0].Series != 150 {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].PerMin < 9.9 || rows[0].PerMin > 10.1 { // 50 series / 5 min = 10/min
		t.Fatalf("PerMin = %v, want ~10", rows[0].PerMin)
	}
}

func TestGrowthSampler_RingBounded(t *testing.T) {
	g := newGrowthSampler(3)
	for i := 0; i < 10; i++ {
		g.sample([]*dto.MetricFamily{famWith("m", i)})
	}
	g.mu.Lock()
	n := len(g.ring)
	g.mu.Unlock()
	if n != 3 {
		t.Fatalf("ring not bounded: %d", n)
	}
}
