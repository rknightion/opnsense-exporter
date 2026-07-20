package webui

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/rknightion/opnsense-exporter/internal/collector"
	"github.com/rknightion/opnsense-exporter/internal/options"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

func TestSparkline_EmptyForFewPoints(t *testing.T) {
	if got := sparkline(nil); got != "" {
		t.Fatalf("nil want empty, got %q", got)
	}
	if got := sparkline([]float64{5}); got != "" {
		t.Fatalf("single point want empty, got %q", got)
	}
}

func TestSparkline_SVGForSeries(t *testing.T) {
	got := string(sparkline([]float64{1, 2, 3, 4}))
	if !strings.Contains(got, "<svg") || !strings.Contains(got, "polyline") {
		t.Fatalf("want svg polyline, got %q", got)
	}
}

func TestRenderPage_Status(t *testing.T) {
	var buf bytes.Buffer
	v := view{
		Title:     "Status",
		RefreshMs: 5000,
		Data: Status{
			Service: ServiceInfo{Name: "opnsense-exporter", Version: "v1.2.3", GoVersion: "go1.26"},
			Health:  "healthy",
			Stats:   ExporterStats{ActiveCollectors: 3, MetricFamilies: 10, Series: 42},
			Collectors: []CollectorRow{{
				Name: "gateways", Display: "Gateways", State: "ok",
				IntervalSec: 60, NextRunIn: "45s", Freshness: "15s ago", FreshnessState: "fresh",
				HasRun: true, LastSuccess: true,
			}},
		},
	}
	if err := renderPage(&buf, v); err != nil {
		t.Fatalf("renderPage: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"opnsense-exporter", "v1.2.3",
		`data-tab="overview"`, `data-tab="collectors"`, `data-tab="api"`, `data-tab="cardinality"`,
		"opnsense-theme", "Next run",
		`id="themeToggle"`, `id="pauseBtn"`, `id="staleBanner"`, `id="tabs"`, `id="collBody"`,
		`id="chGoroutines"`, "function showTab", "function toggleTheme", "Gateways",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}
	// html/template's JS-context escaper space-pads the numeric value, so match
	// it near the assignment rather than an exact "= 5000" spacing.
	if i := strings.Index(out, "__refreshMs"); i < 0 || !strings.Contains(out[i:i+40], "5000") {
		t.Errorf("refresh interval 5000 not rendered into page")
	}
	if strings.Contains(out, "/static/app.css") || strings.Contains(out, "/static/app.js") {
		t.Errorf("stale external-asset link present in inline single-page console")
	}
	if strings.Contains(out, "data-collector=") || strings.Contains(out, "Run now") {
		t.Errorf("Run-Now affordance still present after removal")
	}
}

func testDeps() Deps {
	return Deps{
		Version:           "test",
		GoVersion:         "go1.26",
		Host:              "fw.example",
		StartTime:         time.Now().Add(-time.Minute),
		Tracker:           collector.NewStatusTracker(),
		Metrics:           func() ([]*dto.MetricFamily, time.Time) { return nil, time.Time{} },
		Cache:             func() []opnsense.CacheEntryView { return nil },
		EffectiveConfig:   func() []options.ConfigSection { return nil },
		AllCollectorNames: []string{"gateways"},
		RefreshSeconds:    5,
	}
}

func TestHandler_StatusPage(t *testing.T) {
	srv := NewServer(testDeps())
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "opnsense-exporter") {
		t.Fatalf("status page missing app name")
	}
}

func TestHandler_StatusJSON(t *testing.T) {
	srv := NewServer(testDeps())
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/status.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("json want 200, got %d", rec.Code)
	}
	var st Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if st.ScrapeAge != "never" {
		t.Fatalf("ScrapeAge want never, got %q", st.ScrapeAge)
	}
}

func TestHandler_Healthz(t *testing.T) {
	srv := NewServer(testDeps())
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "ok" {
		t.Fatalf("healthz want 200/ok, got %d/%q", rec.Code, rec.Body.String())
	}
}

// compile-time proof the render helper writes to any io.Writer.
var _ = func(w io.Writer) { _ = renderPage(w, view{}) }
