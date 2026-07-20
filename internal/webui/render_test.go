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
		Title:          "Status",
		PageID:         "status",
		Nav:            []navItem{{Label: "Status", Href: "/", Key: "status", Active: true}},
		RefreshSeconds: 5,
		Data: Status{
			Service: ServiceInfo{Name: "opnsense-exporter", Version: "v1.2.3"},
			Health:  "healthy",
		},
	}
	if err := renderPage(&buf, "status.html.tmpl", v); err != nil {
		t.Fatalf("renderPage: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "opnsense-exporter") {
		t.Fatalf("output missing service name: %q", out[:min(len(out), 400)])
	}
	if !strings.Contains(out, "v1.2.3") {
		t.Fatalf("output missing version")
	}
	if !strings.Contains(out, "/static/app.css") {
		t.Fatalf("layout missing css link")
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

func TestHandler_StaticContentType(t *testing.T) {
	srv := NewServer(testDeps())
	for path, ct := range map[string]string{
		"/static/app.css": "text/css",
		"/static/app.js":  "text/javascript",
	} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s want 200, got %d", path, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, ct) {
			t.Fatalf("%s content-type want %s, got %q", path, ct, got)
		}
	}
}

// compile-time proof the render helper writes to any io.Writer.
var _ = func(w io.Writer) { _ = renderPage(w, "status.html.tmpl", view{}) }
