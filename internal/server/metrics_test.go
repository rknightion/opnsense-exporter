package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense-exporter/internal/metricsnap"
)

func TestMetricsHandler_RecorderCapturesUnfilteredOnly(t *testing.T) {
	f := &fakeViews{names: []string{"x"}}
	self := prometheus.NewRegistry()
	rec := metricsnap.New()
	h := NewMetricsHandler(f, self, 500*time.Millisecond, promslog.NewNopLogger(), rec)

	// A filtered scrape must NOT populate the recorder (a partial view must never
	// clobber the last full-scrape snapshot the web UI reads).
	serve(h, "/metrics?collect%5B%5D=x", nil)
	if _, at := rec.Snapshot(); !at.IsZero() {
		t.Fatalf("filtered scrape must not populate the recorder")
	}

	// An unfiltered scrape captures the collector family set.
	serve(h, "/metrics", nil)
	mfs, at := rec.Snapshot()
	if at.IsZero() || len(mfs) == 0 {
		t.Fatalf("unfiltered scrape should populate the recorder; got %d families at %v", len(mfs), at)
	}
}

type fakeViews struct {
	names      []string
	calls      int
	gotCtx     context.Context
	gotInclude map[string]bool
}

func (f *fakeViews) EnabledCollectorNames() []string { return f.names }

func (f *fakeViews) ScrapeView(ctx context.Context, include map[string]bool) prometheus.Collector {
	f.calls++
	f.gotCtx = ctx
	f.gotInclude = include
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: "fake_view_metric", Help: "fake"})
	g.Set(1)
	return g
}

func newTestMetricsSetup(names ...string) (*fakeViews, http.Handler) {
	f := &fakeViews{names: names}
	self := prometheus.NewRegistry()
	selfGauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "fake_self_metric", Help: "fake"})
	selfGauge.Set(1)
	self.MustRegister(selfGauge)
	return f, NewMetricsHandler(f, self, 500*time.Millisecond, promslog.NewNopLogger(), nil)
}

func serve(h http.Handler, target string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMetricsHandlerDefault(t *testing.T) {
	f, h := newTestMetricsSetup("a", "b")
	rec := serve(h, "/metrics", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "fake_view_metric") {
		t.Error("expected per-request view metric in output")
	}
	if !strings.Contains(body, "fake_self_metric") {
		t.Error("expected self-registry metric in output")
	}
	if f.gotInclude != nil {
		t.Errorf("include = %v, want nil (all collectors)", f.gotInclude)
	}
}

func TestMetricsHandlerCollectParam(t *testing.T) {
	f, h := newTestMetricsSetup("a", "b", "c")
	rec := serve(h, "/metrics?collect[]=a&collect[]=c", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	want := map[string]bool{"a": true, "c": true}
	if len(f.gotInclude) != len(want) || !f.gotInclude["a"] || !f.gotInclude["c"] {
		t.Errorf("include = %v, want %v", f.gotInclude, want)
	}
}

func TestMetricsHandlerExcludeParam(t *testing.T) {
	f, h := newTestMetricsSetup("a", "b", "c")
	rec := serve(h, "/metrics?exclude[]=a", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if f.gotInclude == nil {
		t.Fatal("include = nil, want non-nil complement set")
	}
	if f.gotInclude["a"] || !f.gotInclude["b"] || !f.gotInclude["c"] {
		t.Errorf("include = %v, want {b, c}", f.gotInclude)
	}
}

func TestMetricsHandlerCollectAndExcludeIs400(t *testing.T) {
	f, h := newTestMetricsSetup("a", "b")
	rec := serve(h, "/metrics?collect[]=a&exclude[]=b", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "mutually exclusive") {
		t.Errorf("body = %q, want mention of mutual exclusivity", rec.Body.String())
	}
	if f.calls != 0 {
		t.Errorf("ScrapeView calls = %d, want 0 on rejected request", f.calls)
	}
}

func TestMetricsHandlerUnknownCollectorIs400(t *testing.T) {
	f, h := newTestMetricsSetup("a", "b")
	for _, target := range []string{"/metrics?collect[]=nope", "/metrics?exclude[]=nope"} {
		rec := serve(h, target, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400", target, rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, `"nope"`) {
			t.Errorf("%s: body %q does not name the unknown collector", target, body)
		}
		if !strings.Contains(body, "a, b") {
			t.Errorf("%s: body %q does not list valid collectors", target, body)
		}
	}
	if f.calls != 0 {
		t.Errorf("ScrapeView calls = %d, want 0", f.calls)
	}
}

func TestMetricsHandlerScrapeTimeoutHeader(t *testing.T) {
	f, h := newTestMetricsSetup("a")
	before := time.Now()
	rec := serve(h, "/metrics", map[string]string{"X-Prometheus-Scrape-Timeout-Seconds": "10"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	deadline, ok := f.gotCtx.Deadline()
	if !ok {
		t.Fatal("expected a deadline on the scrape context")
	}
	// 10s header minus 500ms offset => ~9.5s from request start.
	remaining := time.Until(deadline) + time.Since(before)
	if remaining < 9*time.Second || remaining > 10*time.Second {
		t.Errorf("deadline budget = %s, want ~9.5s", remaining)
	}
}

func TestMetricsHandlerTinyTimeoutFallsBackToRawHeader(t *testing.T) {
	f, h := newTestMetricsSetup("a")
	before := time.Now()
	serve(h, "/metrics", map[string]string{"X-Prometheus-Scrape-Timeout-Seconds": "0.3"})
	deadline, ok := f.gotCtx.Deadline()
	if !ok {
		t.Fatal("expected a deadline on the scrape context")
	}
	remaining := time.Until(deadline) + time.Since(before)
	if remaining <= 0 || remaining > 400*time.Millisecond {
		t.Errorf("deadline budget = %s, want ~0.3s (raw header, offset skipped)", remaining)
	}
}

func TestMetricsHandlerMalformedTimeoutHeaderIgnored(t *testing.T) {
	f, h := newTestMetricsSetup("a")
	rec := serve(h, "/metrics", map[string]string{"X-Prometheus-Scrape-Timeout-Seconds": "bogus"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (malformed header ignored)", rec.Code)
	}
	if _, ok := f.gotCtx.Deadline(); ok {
		t.Error("expected no deadline for malformed header")
	}
}

func TestScrapeTimeoutTable(t *testing.T) {
	cases := []struct {
		header string
		offset time.Duration
		want   time.Duration
		ok     bool
	}{
		{"", 500 * time.Millisecond, 0, false},
		{"10", 500 * time.Millisecond, 9500 * time.Millisecond, true},
		{"0.3", 500 * time.Millisecond, 300 * time.Millisecond, true},
		{"10", 0, 10 * time.Second, true},
		{"-5", 500 * time.Millisecond, 0, false},
		{"0", 500 * time.Millisecond, 0, false},
		{"abc", 500 * time.Millisecond, 0, false},
		// Non-finite / absurd client-controlled values must be rejected, not accepted
		// as a zero (immediately-expired) or ~292-year deadline (#124).
		{"NaN", 500 * time.Millisecond, 0, false},
		{"+Inf", 500 * time.Millisecond, 0, false},
		{"-Inf", 500 * time.Millisecond, 0, false},
		{"1e300", 500 * time.Millisecond, 0, false},
	}
	for _, tc := range cases {
		got, ok := scrapeTimeout(tc.header, tc.offset)
		if ok != tc.ok || got != tc.want {
			t.Errorf("scrapeTimeout(%q, %s) = (%s, %v), want (%s, %v)",
				tc.header, tc.offset, got, ok, tc.want, tc.ok)
		}
	}
}

// TestScrapeTimeoutRejectsNonFinite pins the #124 guard: NaN / ±Inf / absurdly large
// client-controlled header values must yield ok=false (no deadline) rather than a
// zero-duration "valid" timeout (immediately-expired, drops all OPNsense data) or an
// effectively infinite one (defeats the budget). Supersedes the earlier assertion that
// a NaN header produced (0, true).
func TestScrapeTimeoutRejectsNonFinite(t *testing.T) {
	for _, h := range []string{"NaN", "+Inf", "-Inf", "Inf", "1e300", "1e309"} {
		if got, ok := scrapeTimeout(h, 500*time.Millisecond); ok || got != 0 {
			t.Errorf("scrapeTimeout(%q) = (%s, %v), want (0s, false)", h, got, ok)
		}
	}
}
