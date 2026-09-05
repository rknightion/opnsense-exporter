package webui

import (
	"bytes"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/metricsnap"

	"github.com/rknightion/opnsense2otel/v4/internal/collector"
	"github.com/rknightion/opnsense2otel/v4/internal/geoip"
	"github.com/rknightion/opnsense2otel/v4/internal/options"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
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
			Service: ServiceInfo{Name: "opnsense2otel", Version: "v1.2.3", GoVersion: "go1.26"},
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
		"opnsense2otel", "v1.2.3",
		`data-tab="overview"`, `data-tab="collectors"`, `data-tab="api"`, `data-tab="cardinality"`,
		"opnsense-theme", "Next run",
		`id="themeToggle"`, `id="pauseBtn"`, `id="staleBanner"`, `id="tabs"`, `id="collBody"`,
		`id="healthBadge"`, `id="upstreamBadge"`, `id="captureBadge"`,
		`id="chGoroutines"`, "function showTab", "function toggleTheme", "Gateways",
		// Trend charts: active series, emitted throughput, collector fleet.
		`id="chCard"`, `id="chEmit"`, `id="chFailing"`, `id="chDuration"`,
		"Throughput &amp; fleet trend (~10 min)", "Active series", "Mean run duration",
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
	if strings.ContainsAny(out, "—–") {
		t.Errorf("rendered console contains an em or en dash")
	}
}

func TestConsoleFamilyTokenBlockMatchesSpec(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	spec, err := os.ReadFile(filepath.Join(root, "design", "console-v2", "implementation-spec.md"))
	if err != nil {
		t.Fatalf("read family implementation spec: %v", err)
	}
	const fence = "```css\n"
	start := strings.Index(string(spec), fence)
	if start < 0 {
		t.Fatal("family implementation spec has no CSS token block")
	}
	start += len(fence)
	rest := string(spec)[start:]
	end := strings.Index(rest, "\n```")
	if end < 0 {
		t.Fatal("family implementation spec CSS token block is unterminated")
	}
	want := rest[:end]
	tmpl, err := os.ReadFile(filepath.Join(root, "internal", "webui", "templates", "page.html.tmpl"))
	if err != nil {
		t.Fatalf("read console template: %v", err)
	}
	styleStart := strings.Index(string(tmpl), "<style>\n")
	if styleStart < 0 {
		t.Fatal("console template has no inline style block")
	}
	styleStart += len("<style>\n")
	got := string(tmpl)[styleStart : styleStart+len(want)]
	if got != want {
		t.Fatalf("family token block differs from the canonical spec")
	}
}

func TestConsoleFontsUseFixedAllowlistAndRoute(t *testing.T) {
	for _, name := range []string{
		"hanken-grotesk-latin.woff2",
		"hanken-grotesk-latin-ext.woff2",
		"JetBrainsMono-Variable.woff2",
	} {
		if data, ok := Font(name); !ok || len(data) == 0 {
			t.Fatalf("embedded font %q is unavailable", name)
		}
	}
	if _, ok := Font("../page.html.tmpl"); ok {
		t.Fatal("font allowlist accepted a path traversal name")
	}
	srv := NewServer(testDeps())
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/_static/fonts/hanken-grotesk-latin.woff2", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "font/woff2" {
		t.Fatalf("font route want 200/font/woff2, got %d/%q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("font cache policy = %q", got)
	}
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/_static/fonts/nope.woff2", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown font want 404, got %d", rec.Code)
	}
}

func TestRenderPage_AuthCountersDescribeHistory(t *testing.T) {
	for _, tc := range []struct {
		name string
		api  APIStats
		want string
	}{
		{"no observations", APIStats{AuthOK: true}, "none recorded"},
		// A recovered endpoint retains its earlier 403 in the lifetime counter.
		// That history cannot establish that authentication is still failing.
		{"historical rejection", APIStats{AuthOK: false, Requests: 101}, "errors recorded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := renderPage(&buf, view{Data: Status{API: tc.api}}); err != nil {
				t.Fatal(err)
			}
			out := buf.String()
			if !strings.Contains(out, `id="apiAuth">`+tc.want+`</span>`) {
				t.Fatalf("auth badge does not describe recorded history as %q", tc.want)
			}
			for _, label := range []string{"Auth errors (lifetime)", "Requests (lifetime)", "Avg duration (lifetime)"} {
				if !strings.Contains(out, label) {
					t.Errorf("API card is missing counter scope %q", label)
				}
			}
		})
	}
}

func testDeps() Deps {
	return Deps{
		Version:           "test",
		GoVersion:         "go1.26",
		Host:              "fw.example",
		StartTime:         time.Now().Add(-time.Minute),
		Tracker:           collector.NewStatusTracker(),
		Capture:           func() metricsnap.Capture { return metricsnap.Capture{} },
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
	if !strings.Contains(rec.Body.String(), "opnsense2otel") {
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

// The trend block must be present in the JSON twin — the page's poll-and-patch
// refresh reads its charts from there, so a missing key silently freezes them.
func TestHandler_StatusJSONCarriesTrend(t *testing.T) {
	srv := NewServer(testDeps())
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/status.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("json want 200, got %d", rec.Code)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	blob, ok := raw["Trend"]
	if !ok {
		t.Fatalf("status.json has no Trend key; got %v", slices.Sorted(maps.Keys(raw)))
	}
	var trend map[string]json.RawMessage
	if err := json.Unmarshal(blob, &trend); err != nil {
		t.Fatalf("decode Trend: %v", err)
	}
	for _, key := range []string{
		"SeriesCount", "SeriesCountSeries",
		"LogShipping", "ShippedRate", "DroppedRate", "ShippedRateSeries", "DroppedRateSeries",
		"ActiveCollectors", "FailingCollectors", "MeanDurationMs",
		"FailingSeries", "MeanDurationMsSeries",
	} {
		if _, ok := trend[key]; !ok {
			t.Errorf("status.json Trend missing %q", key)
		}
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

// CC BY 4.0 requires the credit wherever the data or its results are shown, and
// the console is the exporter's one human-facing surface (#549). It renders on
// every page, unconditionally: the console cannot know which database answered a
// given lookup, and a credit that appears only sometimes is a credit that is
// missing sometimes.
func TestConsoleCreditsTheBundledGeoIPProvider(t *testing.T) {
	srv := NewServer(testDeps())
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	body := rec.Body.String()
	for _, want := range []string{geoip.BundledProviderURL, geoip.BundledProvider, geoip.BundledLicense, geoip.BundledLicenseURL} {
		if !strings.Contains(body, want) {
			t.Errorf("console page does not carry the DB-IP attribution fragment %q", want)
		}
	}
}
