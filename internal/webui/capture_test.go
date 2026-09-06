package webui

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/rknightion/opnsense2otel/v5/internal/metricsnap"
)

// captureFamilies is a small family set standing in for a real gather result.
func captureFamilies() []*dto.MetricFamily {
	return []*dto.MetricFamily{
		{Name: sp("opnsense_up"), Metric: []*dto.Metric{counterMetric(1)}},
		{Name: sp("opnsense_exporter_api_requests_total"), Metric: []*dto.Metric{
			counterMetric(4, "endpoint", "api/a", "code", "200"),
		}},
	}
}

// TestBuildStatus_PartialCaptureIsMarked is the #389 console half. The recorder
// now stores families that arrived WITH a gather error, so the console shows
// CURRENT data during a persistent consistency error instead of being pinned to
// an old snapshot. That is only honest if the page says the capture was partial.
func TestBuildStatus_PartialCaptureIsMarked(t *testing.T) {
	now := time.Now()
	capt := metricsnap.Capture{
		Families:    captureFamilies(),
		At:          now.Add(-4 * time.Second),
		Partial:     true,
		LastErrorAt: now.Add(-4 * time.Second),
		ErrorCount:  17,
	}

	st := buildStatus(nil, capt, nil, ServiceInfo{}, nil, nil)

	if !st.Capture.Partial {
		t.Errorf("Capture.Partial = false for an error-accompanied capture")
	}
	if st.Capture.State != "partial" {
		t.Errorf("Capture.State = %q, want partial", st.Capture.State)
	}
	if st.Capture.ErrorCount != 17 {
		t.Errorf("Capture.ErrorCount = %d, want 17", st.Capture.ErrorCount)
	}
	if st.Capture.LastErrorAgo == "" {
		t.Errorf("Capture.LastErrorAgo empty; the last erroring gather must be visible")
	}
	if st.Capture.LastErrorAt == "" {
		t.Errorf("Capture.LastErrorAt empty; want an RFC3339 timestamp")
	}
	// The current numbers must keep flowing — that is the whole point of storing
	// the partial families rather than pinning the console to an old snapshot.
	if st.Stats.MetricFamilies != 2 || st.Stats.Series != 2 {
		t.Errorf("families/series = %d/%d, want 2/2 from the partial capture",
			st.Stats.MetricFamilies, st.Stats.Series)
	}
	if st.API.Requests != 4 {
		t.Errorf("API.Requests = %v, want 4 from the partial capture", st.API.Requests)
	}
	if st.ScrapeAge == "never" {
		t.Errorf(`ScrapeAge = "never" for a capture that did happen`)
	}
}

// A clean gather is marked full, with no error furniture.
func TestBuildStatus_CleanCaptureIsFull(t *testing.T) {
	capt := metricsnap.Capture{Families: captureFamilies(), At: time.Now()}
	st := buildStatus(nil, capt, nil, ServiceInfo{}, nil, nil)
	if st.Capture.Partial {
		t.Errorf("Capture.Partial = true for a clean gather")
	}
	if st.Capture.State != "full" {
		t.Errorf("Capture.State = %q, want full", st.Capture.State)
	}
	if st.Capture.LastErrorAgo != "" || st.Capture.LastErrorAt != "" {
		t.Errorf("clean capture carries error furniture: %+v", st.Capture)
	}
}

// Never captured is its own state, distinct from a clean capture of nothing.
func TestBuildStatus_NeverCaptured(t *testing.T) {
	st := buildStatus(nil, metricsnap.Capture{}, nil, ServiceInfo{}, nil, nil)
	if st.Capture.State != "never" {
		t.Errorf("Capture.State = %q, want never", st.Capture.State)
	}
	if st.Capture.Age != "never" {
		t.Errorf("Capture.Age = %q, want never", st.Capture.Age)
	}
	if st.ScrapeAge != "never" {
		t.Errorf("ScrapeAge = %q, want never", st.ScrapeAge)
	}
}

// A gather that errored but has never yet produced families keeps the error
// counters visible without claiming a capture exists.
func TestBuildStatus_ErrorsBeforeFirstCapture(t *testing.T) {
	st := buildStatus(nil, metricsnap.Capture{
		LastErrorAt: time.Now().Add(-time.Second), ErrorCount: 3,
	}, nil, ServiceInfo{}, nil, nil)
	if st.Capture.State != "never" {
		t.Errorf("Capture.State = %q, want never", st.Capture.State)
	}
	if st.Capture.ErrorCount != 3 {
		t.Errorf("Capture.ErrorCount = %d, want 3", st.Capture.ErrorCount)
	}
}

// The page's poll-and-patch refresh reads Upstream and Capture out of the JSON
// twin, so a missing key silently freezes both badges at their first-paint value.
func TestHandler_StatusJSONCarriesUpstreamAndCapture(t *testing.T) {
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
	for block, keys := range map[string][]string{
		"Upstream": {"Known", "State", "Polled", "CheckOK", "Reason", "CheckedAgo"},
		"Capture":  {"State", "Partial", "Age", "ErrorCount", "LastErrorAt", "LastErrorAgo"},
	} {
		blob, ok := raw[block]
		if !ok {
			t.Errorf("status.json has no %q key; got %v", block, slices.Sorted(maps.Keys(raw)))
			continue
		}
		var inner map[string]json.RawMessage
		if err := json.Unmarshal(blob, &inner); err != nil {
			t.Errorf("decode %s: %v", block, err)
			continue
		}
		for _, k := range keys {
			if _, ok := inner[k]; !ok {
				t.Errorf("status.json %s missing %q", block, k)
			}
		}
	}
	// Existing keys must survive — the console's JSON twin is a compatibility
	// surface for anything already polling it.
	for _, k := range []string{"Health", "Reasons", "Stats", "Collectors", "ScrapeAge", "Trend"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("status.json lost pre-existing key %q", k)
		}
	}
}

// Every per-collector clock must survive into the JSON twin too — the table is
// rebuilt from it on every poll.
func TestHandler_StatusJSONCarriesCollectorClocks(t *testing.T) {
	d := testDeps()
	d.Tracker = trackerWithSuccess(t, "gateways", "Gateways")
	srv := NewServer(d)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/status.json", nil))

	var raw struct{ Collectors []map[string]json.RawMessage }
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(raw.Collectors) != 1 {
		t.Fatalf("want 1 collector row, got %d", len(raw.Collectors))
	}
	for _, k := range []string{
		"Freshness", "FreshnessState", "DataAgeSec", "HasData",
		"AttemptAge", "AttemptAgeSec", "LastSuccessAgo",
		"NextRunIn", "NextRunInSec", "Scheduled",
	} {
		if _, ok := raw.Collectors[0][k]; !ok {
			t.Errorf("collector row missing %q", k)
		}
	}
}

// The partial marker must actually reach the rendered page, not just the JSON.
func TestRenderPage_ShowsPartialCaptureMarker(t *testing.T) {
	d := testDeps()
	d.Capture = func() metricsnap.Capture {
		return metricsnap.Capture{
			Families: captureFamilies(), At: time.Now(),
			Partial: true, LastErrorAt: time.Now(), ErrorCount: 2,
		}
	}
	srv := NewServer(d)
	var sb strings.Builder
	if err := renderPage(&sb, srv.pageView()); err != nil {
		t.Fatalf("renderPage: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "partial") {
		t.Errorf("rendered page does not mark the capture as partial")
	}
	if !strings.Contains(out, "captureBadge") {
		t.Errorf("rendered page has no capture badge element for the poll refresh to patch")
	}
}
