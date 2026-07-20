package webui

import (
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/rknightion/opnsense-exporter/internal/collector"
)

func TestCollectorRow_NextRunAndFreshness(t *testing.T) {
	now := time.Now()
	s := collector.CollectorStat{
		Name: "gateways", Display: "Gateways", Runs: 10, Failures: 1, LastOK: true,
		Interval: 60 * time.Second, LastFinished: now.Add(-15 * time.Second),
	}
	r := collectorRow(s)
	if r.IntervalSec != 60 {
		t.Errorf("IntervalSec=%d want 60", r.IntervalSec)
	}
	if !r.HasRun || !r.LastSuccess {
		t.Errorf("HasRun/LastSuccess wrong: HasRun=%v LastSuccess=%v", r.HasRun, r.LastSuccess)
	}
	// next run ≈ 45s away (60 - 15); allow slack for test timing
	if r.NextRunInSec < 43 || r.NextRunInSec > 46 {
		t.Errorf("NextRunInSec=%d want ~45", r.NextRunInSec)
	}
	if r.FreshnessState != "fresh" {
		t.Errorf("FreshnessState=%q want fresh", r.FreshnessState)
	}
	if r.Freshness == "" {
		t.Errorf("Freshness empty; want a rendered age")
	}
}

func TestCollectorRow_StaleAndNeverRun(t *testing.T) {
	now := time.Now()
	// stale: age > 2× interval
	stale := collectorRow(collector.CollectorStat{
		Name: "pf", Display: "PF", Runs: 3, LastOK: true,
		Interval: 15 * time.Second, LastFinished: now.Add(-40 * time.Second),
	})
	if stale.FreshnessState != "stale" {
		t.Errorf("FreshnessState=%q want stale", stale.FreshnessState)
	}
	if stale.NextRunIn != "due" {
		t.Errorf("NextRunIn=%q want due (overdue collector)", stale.NextRunIn)
	}
	// never run
	never := collectorRow(collector.CollectorStat{Name: "x", Display: "X", Interval: 60 * time.Second})
	if never.HasRun {
		t.Errorf("HasRun true for never-run collector")
	}
	if never.FreshnessState != "none" {
		t.Errorf("FreshnessState=%q want none", never.FreshnessState)
	}
}

func TestSnapshotCarriesCardinality(t *testing.T) {
	srv := NewServer(cardinalityDeps(populatedMetrics()))
	st := srv.snapshot()
	if st.Cardinality.TotalSeries != 702 {
		t.Errorf("Cardinality.TotalSeries=%d want 702 (2+700)", st.Cardinality.TotalSeries)
	}
	if len(st.Cardinality.TopMetrics) == 0 {
		t.Errorf("Cardinality.TopMetrics empty; snapshot did not fold in cardinality")
	}
	if st.Cardinality.Generated.IsZero() {
		t.Errorf("Cardinality.Generated not set")
	}
}

func TestSuccessRate(t *testing.T) {
	if got := successRate(0, 0); got != -1 {
		t.Fatalf("never-run want -1, got %v", got)
	}
	if got := successRate(4, 1); got != 75 {
		t.Fatalf("want 75, got %v", got)
	}
	if got := successRate(10, 0); got != 100 {
		t.Fatalf("want 100, got %v", got)
	}
}

func TestDeriveHealth_Healthy(t *testing.T) {
	stats := []collector.CollectorStat{
		{Name: "gateways", Display: "Gateways", Runs: 3, LastOK: true},
		{Name: "unbound", Display: "Unbound", Runs: 5, LastOK: true},
	}
	h, reasons := deriveHealth(stats)
	if h != "healthy" {
		t.Fatalf("want healthy, got %q (%v)", h, reasons)
	}
	if len(reasons) != 0 {
		t.Fatalf("want no reasons, got %v", reasons)
	}
}

func TestDeriveHealth_DegradedOnLastFail(t *testing.T) {
	stats := []collector.CollectorStat{
		{Name: "gateways", Display: "Gateways", Runs: 3, LastOK: true},
		{Name: "unbound", Display: "Unbound", Runs: 5, Failures: 1, LastOK: false, LastError: "boom"},
	}
	h, reasons := deriveHealth(stats)
	if h != "degraded" {
		t.Fatalf("want degraded, got %q", h)
	}
	if len(reasons) != 1 {
		t.Fatalf("want 1 reason, got %v", reasons)
	}
}

func TestDeriveHealth_StartingWhenAnyUnrun(t *testing.T) {
	stats := []collector.CollectorStat{
		{Name: "gateways", Display: "Gateways", Runs: 3, LastOK: true},
		{Name: "unbound", Display: "Unbound", Runs: 0},
	}
	h, _ := deriveHealth(stats)
	if h != "starting" {
		t.Fatalf("want starting, got %q", h)
	}
}

func TestDeriveHealth_EmptyIsStarting(t *testing.T) {
	h, reasons := deriveHealth(nil)
	if h != "starting" || len(reasons) == 0 {
		t.Fatalf("empty want starting+reason, got %q/%v", h, reasons)
	}
}

// --- dto builders for buildStatus test ---

func fp(v float64) *float64 { return &v }
func up(v uint64) *uint64   { return &v }
func sp(v string) *string   { return &v }

func counterMetric(value float64, labels ...string) *dto.Metric {
	m := &dto.Metric{Counter: &dto.Counter{Value: fp(value)}}
	for i := 0; i+1 < len(labels); i += 2 {
		m.Label = append(m.Label, &dto.LabelPair{Name: sp(labels[i]), Value: sp(labels[i+1])})
	}
	return m
}

func TestBuildStatus(t *testing.T) {
	families := []*dto.MetricFamily{
		{Name: sp("opnsense_up"), Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: fp(1)}}}},
		{Name: sp("opnsense_exporter_api_requests_total"), Metric: []*dto.Metric{
			counterMetric(3, "endpoint", "api/a", "code", "200"),
			counterMetric(7, "endpoint", "api/b", "code", "200"),
		}},
		{Name: sp("opnsense_exporter_api_request_duration_seconds"), Metric: []*dto.Metric{
			{Histogram: &dto.Histogram{SampleSum: fp(2.0), SampleCount: up(4)}},
		}},
		{Name: sp("opnsense_exporter_endpoint_errors_total"), Metric: []*dto.Metric{
			counterMetric(5, "endpoint", "api/foo"),
			counterMetric(1, "endpoint", "api/bar"),
		}},
	}
	stats := []collector.CollectorStat{
		{Name: "gateways", Display: "Gateways", Runs: 3, LastOK: true},
		{Name: "unbound", Display: "Unbound", Runs: 5, Failures: 2, LastOK: false, LastError: "x"},
	}
	svc := ServiceInfo{Name: "opnsense-exporter", Version: "test"}
	allNames := []string{"gateways", "unbound", "extra"}

	st := buildStatus(stats, families, nil, svc, allNames)

	if st.Stats.MetricFamilies != 4 {
		t.Fatalf("MetricFamilies want 4, got %d", st.Stats.MetricFamilies)
	}
	if st.Stats.Series != 6 { // 1 + 2 + 1 + 2
		t.Fatalf("Series want 6, got %d", st.Stats.Series)
	}
	if st.Stats.ActiveCollectors != 2 {
		t.Fatalf("ActiveCollectors want 2, got %d", st.Stats.ActiveCollectors)
	}
	if st.API.Requests != 10 {
		t.Fatalf("API.Requests want 10, got %v", st.API.Requests)
	}
	if st.API.AvgMs != 500 { // 2.0/4 * 1000
		t.Fatalf("API.AvgMs want 500, got %v", st.API.AvgMs)
	}
	if len(st.API.TopErrors) == 0 || st.API.TopErrors[0].Endpoint != "api/foo" {
		t.Fatalf("TopErrors top want api/foo, got %+v", st.API.TopErrors)
	}
	if len(st.Skipped) != 1 || st.Skipped[0].Name != "extra" {
		t.Fatalf("Skipped want [extra], got %+v", st.Skipped)
	}
	if st.Health != "degraded" {
		t.Fatalf("Health want degraded, got %q", st.Health)
	}
	// SuccessRate: unbound 5 runs 2 failures => 60.
	var found bool
	for _, r := range st.Collectors {
		if r.Name == "unbound" {
			found = true
			if r.SuccessRate != 60 {
				t.Fatalf("unbound successRate want 60, got %v", r.SuccessRate)
			}
			if r.State != "failing" {
				t.Fatalf("unbound state want failing, got %q", r.State)
			}
		}
	}
	if !found {
		t.Fatal("unbound row missing")
	}
}
