package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense2otel/v5/internal/metricsnap"
)

func TestMetricsHandler_RecorderCapturesUnfilteredOnly(t *testing.T) {
	f := &fakeViews{names: []string{"x"}}
	self := prometheus.NewRegistry()
	rec := metricsnap.New()
	h := NewMetricsHandler(f, self, promslog.NewNopLogger(), rec, nil)

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
	return f, NewMetricsHandler(f, self, promslog.NewNopLogger(), nil, nil)
}

// newTestMetricsSetupWithObs is newTestMetricsSetup but also wires a real
// registry for the handler's own self-observability metrics (#426), so a test
// can gather and assert on them.
func newTestMetricsSetupWithObs(names ...string) (*fakeViews, http.Handler, *prometheus.Registry) {
	f := &fakeViews{names: names}
	self := prometheus.NewRegistry()
	selfGauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "fake_self_metric", Help: "fake"})
	selfGauge.Set(1)
	self.MustRegister(selfGauge)
	obs := prometheus.NewRegistry()
	return f, NewMetricsHandler(f, self, promslog.NewNopLogger(), nil, obs), obs
}

// counterValue reads the current value of a zero-label Counter registered on reg,
// or fails the test if it cannot be found.
func counterValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if labelsMatch(m, labels) {
				if c := m.GetCounter(); c != nil {
					return c.GetValue()
				}
			}
		}
	}
	t.Fatalf("metric %s{%v} not found", name, labels)
	return 0
}

func gaugeValue(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		if len(mf.GetMetric()) != 1 {
			t.Fatalf("gauge %s has %d series, want exactly 1 (no labels)", name, len(mf.GetMetric()))
		}
		return mf.GetMetric()[0].GetGauge().GetValue()
	}
	t.Fatalf("metric %s not found", name)
	return 0
}

func histogramCount(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) uint64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if labelsMatch(m, labels) {
				if h := m.GetHistogram(); h != nil {
					return h.GetSampleCount()
				}
			}
		}
	}
	t.Fatalf("histogram %s{%v} not found", name, labels)
	return 0
}

func labelsMatch(m *dto.Metric, want map[string]string) bool {
	if len(m.GetLabel()) != len(want) {
		return false
	}
	for _, lp := range m.GetLabel() {
		if wv, ok := want[lp.GetName()]; !ok || wv != lp.GetValue() {
			return false
		}
	}
	return true
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

// TestMetricsHandlerIgnoresPrometheusScrapeTimeoutHeader is the #439 regression
// guard. Before #336 the handler parsed X-Prometheus-Scrape-Timeout-Seconds,
// subtracted --exporter.scrape-timeout-offset and handed the result to the collector
// fan-out as a collection deadline. Serving is now a pure replay of the in-memory
// poll snapshot and makes no OPNsense API call, so that budget governed nothing —
// the collector discarded the context outright. Both surfaces are gone: the handler
// must hand the scrape view the bare request context, with no derived deadline, no
// matter what the client sends in that header.
func TestMetricsHandlerIgnoresPrometheusScrapeTimeoutHeader(t *testing.T) {
	for _, header := range []string{"10", "0.3", "0", "-5", "bogus", "NaN", "+Inf", "1e300"} {
		f, h := newTestMetricsSetup("a")
		rec := serve(h, "/metrics", map[string]string{"X-Prometheus-Scrape-Timeout-Seconds": header})
		if rec.Code != http.StatusOK {
			t.Fatalf("header %q: status = %d, want 200", header, rec.Code)
		}
		if f.calls != 1 {
			t.Fatalf("header %q: ScrapeView calls = %d, want 1", header, f.calls)
		}
		if deadline, ok := f.gotCtx.Deadline(); ok {
			t.Errorf("header %q: scrape context carries a deadline (%s); the timeout header must "+
				"not derive one — it cannot bound OPNsense polling", header, time.Until(deadline))
		}
	}
}

// TestMetricsHandlerScrapeContextIsTheRequestContext pins what the scrape context IS
// after #439: the request's own context and nothing else, so an aborted HTTP scrape
// still cancels cleanly while no client-supplied budget can reach the poll scheduler.
func TestMetricsHandlerScrapeContextIsTheRequestContext(t *testing.T) {
	f, h := newTestMetricsSetup("a")
	serve(h, "/metrics", nil)
	if f.gotCtx == nil {
		t.Fatal("ScrapeView received a nil context")
	}
	if _, ok := f.gotCtx.Deadline(); ok {
		t.Error("scrape context must carry no deadline of the handler's own making")
	}
	if err := f.gotCtx.Err(); err != nil {
		t.Errorf("scrape context already cancelled: %v", err)
	}
}

// blockingViews holds every ScrapeView call open until release is closed, so a
// test can pin N requests inside the handler at once.
type blockingViews struct {
	names   []string
	release chan struct{}

	mu      sync.Mutex
	entered int
}

func (b *blockingViews) EnabledCollectorNames() []string { return b.names }

func (b *blockingViews) ScrapeView(ctx context.Context, include map[string]bool) prometheus.Collector {
	b.mu.Lock()
	b.entered++
	b.mu.Unlock()
	<-b.release
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: "fake_view_metric", Help: "fake"})
	g.Set(1)
	return g
}

func (b *blockingViews) inHandler() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.entered
}

// TestMetricsHandler_ConcurrencyLimitReturns503 pins the in-flight bound on
// /metrics. The listener is unauthenticated by default, so without a cap an
// unbounded number of concurrent scrapes each materialize a full gathered metric
// set in memory. Overflow must degrade to 503, and a normal single scrape must
// still succeed once the pressure clears.
func TestMetricsHandler_ConcurrencyLimitReturns503(t *testing.T) {
	if maxMetricsInFlight <= 0 {
		t.Fatalf("maxMetricsInFlight = %d, want a positive bound", maxMetricsInFlight)
	}
	b := &blockingViews{names: []string{"a"}, release: make(chan struct{})}
	h := NewMetricsHandler(b, prometheus.NewRegistry(), promslog.NewNopLogger(), nil, nil)

	var wg sync.WaitGroup
	for range maxMetricsInFlight {
		wg.Add(1)
		go func() {
			defer wg.Done()
			serve(h, "/metrics", nil)
		}()
	}
	// Wait until every slot is genuinely occupied inside the handler.
	deadline := time.Now().Add(5 * time.Second)
	for b.inHandler() < maxMetricsInFlight {
		if time.Now().After(deadline) {
			close(b.release)
			wg.Wait()
			t.Fatalf("only %d/%d requests reached the handler", b.inHandler(), maxMetricsInFlight)
		}
		time.Sleep(time.Millisecond)
	}

	over := serve(h, "/metrics", nil)
	if over.Code != http.StatusServiceUnavailable {
		t.Fatalf("overflow status = %d, want 503; body: %s", over.Code, over.Body.String())
	}
	if !strings.Contains(over.Body.String(), "concurrent requests") {
		t.Errorf("overflow body = %q, want a concurrency message", over.Body.String())
	}
	if b.inHandler() != maxMetricsInFlight {
		t.Errorf("overflow request entered the handler: %d", b.inHandler())
	}

	close(b.release)
	wg.Wait()

	// Slots are released, so a normal scrape succeeds again.
	after := serve(h, "/metrics", nil)
	if after.Code != http.StatusOK {
		t.Fatalf("post-drain status = %d, want 200; body: %s", after.Code, after.Body.String())
	}
}

// deadlineRecorder is a ResponseWriter that supports SetWriteDeadline (as a real
// net/http connection does) and records every deadline set on it.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	set []time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.set = append(d.set, t)
	return nil
}

// TestMetricsHandler_SetsAndClearsWriteDeadline pins the slow-reader bound.
// promhttp gathers the whole metric set into memory before writing, so a client
// that dribbles its response otherwise pins that set plus a goroutine forever
// (IdleTimeout does not apply to an actively-writing connection). The deadline
// must be cleared before returning, or it would leak onto the next request on a
// kept-alive connection — net/http only resets write deadlines per request when
// Server.WriteTimeout is set, and it is deliberately unset here.
func TestMetricsHandler_SetsAndClearsWriteDeadline(t *testing.T) {
	_, h := newTestMetricsSetup("a")
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	before := time.Now()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if len(w.set) != 2 {
		t.Fatalf("write deadlines set = %v, want exactly 2 (set then clear)", w.set)
	}
	got := w.set[0].Sub(before)
	if got < metricsWriteDeadline-time.Second || got > metricsWriteDeadline+time.Second {
		t.Errorf("write deadline = %s from request start, want ~%s", got, metricsWriteDeadline)
	}
	if !w.set[1].IsZero() {
		t.Errorf("final write deadline = %v, want the zero time (cleared)", w.set[1])
	}
}

// TestMetricsHandler_WriteDeadlineUnsupportedIsIgnored asserts a ResponseWriter
// that cannot carry a deadline (any wrapper without Unwrap, and every
// httptest.ResponseRecorder) still serves normally — the cap is best-effort
// hardening, not a correctness requirement.
func TestMetricsHandler_WriteDeadlineUnsupportedIsIgnored(t *testing.T) {
	_, h := newTestMetricsSetup("a")
	rec := serve(h, "/metrics", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "fake_view_metric") {
		t.Errorf("expected metrics body, got %q", rec.Body.String())
	}
}

// --- self-observability (#426) --------------------------------------------

// TestMetricsHandler_SuccessfulScrapeRecordsCompletionAndDuration pins the
// happy-path bookkeeping: a served scrape counts once under the "ok" status, its
// duration lands in the matching histogram bucket series, and the in-flight
// gauge returns to zero once the request has fully returned (its own admission
// window is over).
func TestMetricsHandler_SuccessfulScrapeRecordsCompletionAndDuration(t *testing.T) {
	_, h, obs := newTestMetricsSetupWithObs("a")

	rec := serve(h, "/metrics", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	got := counterValue(t, obs, metricNameRequestsTotal, map[string]string{"status": requestStatusOK})
	if got != 1 {
		t.Errorf("%s{status=%s} = %v, want 1", metricNameRequestsTotal, requestStatusOK, got)
	}
	if n := histogramCount(t, obs, metricNameRequestDuration, map[string]string{"status": requestStatusOK}); n != 1 {
		t.Errorf("%s{status=%s} sample count = %d, want 1", metricNameRequestDuration, requestStatusOK, n)
	}
	if g := gaugeValue(t, obs, metricNameRequestsInFlight); g != 0 {
		t.Errorf("%s = %v after the request returned, want 0", metricNameRequestsInFlight, g)
	}
}

// TestMetricsHandler_BadRequestRecordsCompletion pins the 400 path: a rejected
// collect[]/exclude[] combination is still a completed request from the
// admission cap's point of view, tallied under its own bounded status value
// rather than silently missing from the completion counter.
func TestMetricsHandler_BadRequestRecordsCompletion(t *testing.T) {
	_, h, obs := newTestMetricsSetupWithObs("a", "b")

	rec := serve(h, "/metrics?collect[]=a&exclude[]=b", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	got := counterValue(t, obs, metricNameRequestsTotal, map[string]string{"status": requestStatusBadRequest})
	if got != 1 {
		t.Errorf("%s{status=%s} = %v, want 1", metricNameRequestsTotal, requestStatusBadRequest, got)
	}
}

// TestMetricsHandler_RejectedRequestIncrementsAdmissionCounter drives a real
// 41st request through the actual handler (not a reimplementation of its
// admission check) and asserts the rejection lands on a bounded reason label,
// separately from the completion counter above — a rejected request was never
// admitted, so it must not also appear as a "completed" request.
func TestMetricsHandler_RejectedRequestIncrementsAdmissionCounter(t *testing.T) {
	b := &blockingViews{names: []string{"a"}, release: make(chan struct{})}
	obs := prometheus.NewRegistry()
	h := NewMetricsHandler(b, prometheus.NewRegistry(), promslog.NewNopLogger(), nil, obs)

	var wg sync.WaitGroup
	for range maxMetricsInFlight {
		wg.Add(1)
		go func() {
			defer wg.Done()
			serve(h, "/metrics", nil)
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for b.inHandler() < maxMetricsInFlight {
		if time.Now().After(deadline) {
			close(b.release)
			wg.Wait()
			t.Fatalf("only %d/%d requests reached the handler", b.inHandler(), maxMetricsInFlight)
		}
		time.Sleep(time.Millisecond)
	}

	// The 41st request: forced to overflow the admission cap while the first 40
	// are still parked inside ScrapeView.
	over := serve(h, "/metrics", nil)
	if over.Code != http.StatusServiceUnavailable {
		t.Fatalf("overflow status = %d, want 503", over.Code)
	}

	got := counterValue(t, obs, metricNameRequestsRejectedTotal, map[string]string{"reason": rejectReasonInFlightLimit})
	if got != 1 {
		t.Errorf("%s{reason=%s} = %v, want 1", metricNameRequestsRejectedTotal, rejectReasonInFlightLimit, got)
	}
	// A rejected request was never admitted, so it must not also show up as a
	// completed request under any status. requestsTotal pre-initialises every
	// status to zero (so a dashboard never has to distinguish "never happened"
	// from "this build predates the label" via NO DATA), so the assertion is on
	// VALUE, not on the series' mere existence.
	mfs, err := obs.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != metricNameRequestsTotal {
			continue
		}
		for _, m := range mf.GetMetric() {
			if got := m.GetCounter().GetValue(); got != 0 {
				t.Errorf("%s unexpectedly recorded for the rejected request: %v", metricNameRequestsTotal, m)
			}
		}
	}

	close(b.release)
	wg.Wait()
}
