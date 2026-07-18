package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
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
	rep := buildCardinality(fams, 1000, 10000)

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
	rep := buildCardinality(fams, 500, 2000)
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
	rep := buildCardinality(fams, 500, 2000)

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

func TestBuildMetricLabelValues(t *testing.T) {
	fams := []*dto.MetricFamily{
		{Name: sp("http_requests"), Metric: []*dto.Metric{
			counterMetric(1, "code", "200", "method", "get"),
			counterMetric(1, "code", "500", "method", "get"),
			counterMetric(1, "code", "200", "method", "post"),
		}},
	}
	mlv := buildMetricLabelValues(fams, "http_requests")
	if !mlv.Found {
		t.Fatalf("metric should be found")
	}
	if mlv.Series != 3 {
		t.Fatalf("series want 3, got %d", mlv.Series)
	}
	var code *LabelValueGroup
	for i := range mlv.Labels {
		if mlv.Labels[i].Name == "code" {
			code = &mlv.Labels[i]
		}
	}
	if code == nil {
		t.Fatalf("code label group missing: %+v", mlv.Labels)
	}
	// 200 appears twice, 500 once → 200 first (count desc).
	if len(code.Values) != 2 || code.Values[0].Value != "200" || code.Values[0].Count != 2 {
		t.Fatalf("code values want [200:2, 500:1], got %+v", code.Values)
	}

	if miss := buildMetricLabelValues(fams, "nope"); miss.Found {
		t.Fatalf("nonexistent metric should not be Found")
	}
}

// --- handler / render tests ---

func cardinalityDeps(metrics func() ([]*dto.MetricFamily, time.Time)) Deps {
	d := testDeps()
	d.Metrics = metrics
	return d
}

func populatedMetrics() func() ([]*dto.MetricFamily, time.Time) {
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
	return func() ([]*dto.MetricFamily, time.Time) { return fams, at }
}

func TestHandler_CardinalityHub(t *testing.T) {
	srv := NewServer(cardinalityDeps(populatedMetrics()))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/cardinality", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("hub want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Cardinality") {
		t.Fatalf("hub missing title")
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("hub content-type want html, got %q", got)
	}
}

func TestHandler_CardinalityEmptyState(t *testing.T) {
	srv := NewServer(cardinalityDeps(func() ([]*dto.MetricFamily, time.Time) { return nil, time.Time{} }))
	for _, path := range []string{"/cardinality", "/cardinality/all-metrics", "/cardinality/all-labels"} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s want 200, got %d", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "first scrape") {
			t.Fatalf("%s should show waiting-for-first-scrape empty state", path)
		}
	}
}

func TestHandler_CardinalityAllMetricsAndLabels(t *testing.T) {
	srv := NewServer(cardinalityDeps(populatedMetrics()))
	for _, tc := range []struct{ path, want string }{
		{"/cardinality/all-metrics", "opnsense_big"},
		{"/cardinality/all-labels", "id"},
	} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s want 200, got %d", tc.path, rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, tc.want) {
			t.Fatalf("%s missing %q", tc.path, tc.want)
		}
		if !strings.Contains(body, "data-filter-target") {
			t.Fatalf("%s missing client-side filter input", tc.path)
		}
	}
}

func TestHandler_CardinalityLabelValues(t *testing.T) {
	srv := NewServer(cardinalityDeps(populatedMetrics()))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/cardinality/label-values/opnsense_up", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("label-values want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "instance") {
		t.Fatalf("label-values missing 'instance' label")
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
