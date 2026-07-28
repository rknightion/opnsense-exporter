package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/rknightion/opnsense-exporter/internal/metricsnap"
)

// fakeFamilies builds a []*dto.MetricFamily where each named family carries the
// given number of (label-less) metrics, so series count == the map value.
func fakeFamilies(spec map[string]int) []*dto.MetricFamily {
	out := make([]*dto.MetricFamily, 0, len(spec))
	for name, n := range spec {
		mf := &dto.MetricFamily{Name: sp(name)}
		for i := 0; i < n; i++ {
			mf.Metric = append(mf.Metric, &dto.Metric{})
		}
		out = append(out, mf)
	}
	return out
}

func TestBuildCardinality_CountsAndOrdering(t *testing.T) {
	fams := fakeFamilies(map[string]int{"metric_a": 3, "metric_b": 1200})
	rep := buildCardinality(fams, 1000, 10000, 0)

	if rep.TotalFamilies != 2 {
		t.Fatalf("TotalFamilies want 2, got %d", rep.TotalFamilies)
	}
	if rep.TotalSeries != 1203 {
		t.Fatalf("TotalSeries want 1203, got %d", rep.TotalSeries)
	}
	if len(rep.TopMetrics) != 2 || rep.TopMetrics[0].Name != "metric_b" {
		t.Fatalf("TopMetrics[0] want metric_b, got %+v", rep.TopMetrics)
	}
	if rep.TopMetrics[0].Series != 1200 {
		t.Fatalf("metric_b series want 1200, got %d", rep.TopMetrics[0].Series)
	}
	if rep.Warn != 1 {
		t.Fatalf("Warn want 1, got %d", rep.Warn)
	}
	if rep.Crit != 0 {
		t.Fatalf("Crit want 0, got %d", rep.Crit)
	}
	if rep.WarnThreshold != 1000 || rep.CritThreshold != 10000 {
		t.Fatalf("thresholds want 1000/10000, got %d/%d", rep.WarnThreshold, rep.CritThreshold)
	}
}

func TestBuildCardinality_Bucketing(t *testing.T) {
	fams := fakeFamilies(map[string]int{"low": 10, "mid": 600, "high": 3000})
	rep := buildCardinality(fams, 500, 2000, 0)
	if rep.Warn != 1 {
		t.Fatalf("Warn want 1 (mid), got %d", rep.Warn)
	}
	if rep.Crit != 1 {
		t.Fatalf("Crit want 1 (high), got %d", rep.Crit)
	}
	byName := map[string]string{}
	for _, m := range rep.TopMetrics {
		byName[m.Name] = m.Level
	}
	if byName["low"] != "ok" || byName["mid"] != "warn" || byName["high"] != "crit" {
		t.Fatalf("levels wrong: %+v", byName)
	}
	if len(rep.Alerts) == 0 {
		t.Fatalf("want an alert for the crit metric, got none")
	}
}

func TestBuildCardinality_LabelDistinctValues(t *testing.T) {
	fams := []*dto.MetricFamily{
		{Name: sp("http_requests"), Metric: []*dto.Metric{
			counterMetric(1, "code", "200", "method", "get"),
			counterMetric(1, "code", "500", "method", "get"),
			counterMetric(1, "code", "200", "method", "post"),
		}},
		{Name: sp("other"), Metric: []*dto.Metric{
			counterMetric(1, "code", "200"),
		}},
	}
	rep := buildCardinality(fams, 500, 2000, 0)

	var code *LabelCard
	for i := range rep.TopLabels {
		if rep.TopLabels[i].Name == "code" {
			code = &rep.TopLabels[i]
		}
	}
	if code == nil {
		t.Fatalf("label 'code' missing from %+v", rep.TopLabels)
	}
	if code.DistinctValues != 2 {
		t.Fatalf("code distinct values want 2, got %d", code.DistinctValues)
	}
	if code.Families != 2 {
		t.Fatalf("code families-using want 2, got %d", code.Families)
	}
	// TopLabels sorted by distinct values desc — code(2) ahead of method(2)
	// ties break by name, so code before method.
	if rep.TopLabels[0].Name != "code" {
		t.Fatalf("TopLabels[0] want code, got %+v", rep.TopLabels)
	}
}

// --- total-series budget tests (#494) ---

// TestBuildCardinalityBudget_Under pins the under-budget shape: OverBudget
// false, BudgetPercent computed, SeriesBudget echoed back.
func TestBuildCardinalityBudget_Under(t *testing.T) {
	fams := fakeFamilies(map[string]int{"a": 30})
	rep := buildCardinality(fams, 500, 2000, 100)
	if rep.SeriesBudget != 100 {
		t.Fatalf("SeriesBudget want 100, got %d", rep.SeriesBudget)
	}
	if rep.OverBudget {
		t.Fatalf("30/100 want OverBudget false")
	}
	if rep.BudgetPercent != 30 {
		t.Fatalf("BudgetPercent want 30, got %v", rep.BudgetPercent)
	}
}

// TestBuildCardinalityBudget_OverAtExactly pins the boundary: total == budget
// counts as OVER (matching the existing >= convention cardLevel already uses
// for the per-metric warn/crit thresholds), not under.
func TestBuildCardinalityBudget_OverAtExactly(t *testing.T) {
	fams := fakeFamilies(map[string]int{"a": 100})
	rep := buildCardinality(fams, 500, 2000, 100)
	if !rep.OverBudget {
		t.Fatalf("100/100 want OverBudget true (>= convention)")
	}
	if rep.BudgetPercent != 100 {
		t.Fatalf("BudgetPercent want 100, got %v", rep.BudgetPercent)
	}
}

// TestBuildCardinalityBudget_Disabled pins budget <= 0 as "disabled": the
// report carries zero values, never a divide-by-zero, regardless of the real
// series count.
func TestBuildCardinalityBudget_Disabled(t *testing.T) {
	fams := fakeFamilies(map[string]int{"a": 999999})
	rep := buildCardinality(fams, 500, 2000, 0)
	if rep.SeriesBudget != 0 {
		t.Fatalf("SeriesBudget want 0 (disabled), got %d", rep.SeriesBudget)
	}
	if rep.OverBudget {
		t.Fatalf("disabled budget must never report OverBudget")
	}
	if rep.BudgetPercent != 0 {
		t.Fatalf("disabled budget BudgetPercent want 0, got %v", rep.BudgetPercent)
	}
}

// TestSeriesBudget_ReachesTheJSONEndpointFromDeps pins the wiring that matters:
// the budget configured in Deps is what the SERVER's own report carries, not
// just what a direct buildCardinality call returns. Both call sites — the JSON
// endpoints here and the console's live Cardinality tab in server.go — read
// s.deps.SeriesBudget, so a report can never depend on hidden package state.
func TestSeriesBudget_ReachesTheJSONEndpointFromDeps(t *testing.T) {
	fams := fakeFamilies(map[string]int{"a": 40})
	s := NewServer(Deps{
		SeriesBudget: 40,
		Capture:      func() metricsnap.Capture { return metricsnap.Capture{Families: fams} },
	})

	rep := s.cardinalitySnapshot()
	if rep.SeriesBudget != 40 {
		t.Fatalf("SeriesBudget want 40 (from Deps), got %d", rep.SeriesBudget)
	}
	if !rep.OverBudget {
		t.Fatalf("40 series against a budget of 40 want OverBudget true")
	}
}

// TestSeriesBudget_ZeroDepsDisablesIt pins that an unset budget disables the
// check rather than reporting 0% used, which would read as infinite headroom.
func TestSeriesBudget_ZeroDepsDisablesIt(t *testing.T) {
	fams := fakeFamilies(map[string]int{"a": 5})
	s := NewServer(Deps{Capture: func() metricsnap.Capture { return metricsnap.Capture{Families: fams} }})

	rep := s.cardinalitySnapshot()
	if rep.SeriesBudget != 0 || rep.OverBudget || rep.BudgetPercent != 0 {
		t.Fatalf("want a disabled budget with zero percent, got %+v", rep)
	}
}

// --- handler / render tests ---

func cardinalityDeps(capture func() metricsnap.Capture) Deps {
	d := testDeps()
	d.Capture = capture
	return d
}

func populatedMetrics() func() metricsnap.Capture {
	fams := []*dto.MetricFamily{
		{Name: sp("opnsense_up"), Metric: []*dto.Metric{
			counterMetric(1, "instance", "a"),
			counterMetric(1, "instance", "b"),
		}},
		{Name: sp("opnsense_big"), Metric: func() []*dto.Metric {
			ms := make([]*dto.Metric, 0, 700)
			for i := 0; i < 700; i++ {
				ms = append(ms, counterMetric(1, "id", string(rune('a'+i%26))))
			}
			return ms
		}()},
	}
	at := time.Now()
	return func() metricsnap.Capture { return metricsnap.Capture{Families: fams, At: at} }
}

// TestHandler_CardinalityFoldedIntoPage asserts the cardinality data is folded
// into the single page as a tab (the old dedicated HTML drill-down handlers are
// gone; those paths now fall through to the "/" catch-all page). The JSON/export
// endpoints remain (covered by TestHandler_CardinalityExportAndJSON).
func TestHandler_CardinalityFoldedIntoPage(t *testing.T) {
	srv := NewServer(cardinalityDeps(populatedMetrics()))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `data-tab="cardinality"`) {
		t.Errorf("single page missing cardinality tab")
	}
	if !strings.Contains(body, "opnsense_big") {
		t.Errorf("single page missing folded-in cardinality metric data")
	}
	// The dedicated cardinality HTML handlers were removed; the pure builder and
	// JSON endpoints remain.
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/cardinality.json", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("cardinality JSON want 200, got %d", rec.Code)
	}
}

func TestHandler_CardinalityExportAndJSON(t *testing.T) {
	srv := NewServer(cardinalityDeps(populatedMetrics()))

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/cardinality/export.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("export want 200, got %d", rec.Code)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Fatalf("export missing attachment disposition, got %q", cd)
	}
	var rep CardinalityReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("export decode: %v", err)
	}
	if rep.TotalFamilies != 2 {
		t.Fatalf("export TotalFamilies want 2, got %d", rep.TotalFamilies)
	}

	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/cardinality.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("json twin want 200, got %d", rec.Code)
	}
	var rep2 CardinalityReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep2); err != nil {
		t.Fatalf("json twin decode: %v", err)
	}
}
