package zenarmor

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// serverWithMetrics builds an httptest server whose handler carries a real metrics
// registry and a buffer logger, so a test can assert on both the unhandled counter
// and the WARN.
func serverWithMetrics(t *testing.T) (*httptest.Server, prometheus.Gatherer, *strings.Builder) {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := newMetrics(reg, nil)
	var logbuf strings.Builder
	log := slog.New(slog.NewTextHandler(&logbuf, nil))
	srv := httptest.NewServer(newServer(Config{}, func(string, []byte, netip.Addr) {}, m, log))
	t.Cleanup(srv.Close)
	return srv, reg, &logbuf
}

func getBody(t *testing.T, url string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(url) //nolint:noctx // test client
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, b
}

// TestAliasProbeHandled: the hourly GET /<family>*/_alias probe is answered 200 {}
// with the product header, and is NOT counted or logged as unhandled (#331).
func TestAliasProbeHandled(t *testing.T) {
	srv, reg, logbuf := serverWithMetrics(t)

	resp, body := getBody(t, srv.URL+"/zenarmor_0000000000_019695d7_conn%2A/_alias")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("X-Elastic-Product") != "Elasticsearch" {
		t.Fatal("missing product header")
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("body not JSON object: %v (%q)", err, body)
	}
	if len(obj) != 0 {
		t.Fatalf("alias body = %s, want {}", body)
	}
	if n := rejectCount(t, reg, "unhandled_endpoint"); n != 0 {
		t.Fatalf("unhandled_endpoint counted %v for an _alias probe, want 0", n)
	}
	if strings.Contains(logbuf.String(), "does not implement") {
		t.Fatalf("_alias probe logged as unhandled:\n%s", logbuf.String())
	}
}

// TestSettingsProbeHandled: the GET /<family>_write/_settings probe is answered 200
// with a valid settings doc keyed by the requested index, not counted as unhandled.
func TestSettingsProbeHandled(t *testing.T) {
	srv, reg, logbuf := serverWithMetrics(t)

	idx := "zenarmor_0000000000_019695d7_conn_write"
	resp, body := getBody(t, srv.URL+"/"+idx+"/_settings")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("X-Elastic-Product") != "Elasticsearch" {
		t.Fatal("missing product header")
	}
	var obj map[string]map[string]map[string]map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("body not the settings shape: %v (%q)", err, body)
	}
	idxDoc, ok := obj[idx]
	if !ok {
		t.Fatalf("settings body not keyed by the requested index: %s", body)
	}
	if _, ok := idxDoc["settings"]["index"]; !ok {
		t.Fatalf("settings.index missing: %s", body)
	}
	if n := rejectCount(t, reg, "unhandled_endpoint"); n != 0 {
		t.Fatalf("unhandled_endpoint counted %v for a _settings probe, want 0", n)
	}
	if strings.Contains(logbuf.String(), "does not implement") {
		t.Fatalf("_settings probe logged as unhandled:\n%s", logbuf.String())
	}
}

// TestUnrelatedIndexPathStillUnhandled: a genuinely unknown index sub-resource still
// falls through to unhandled — the two probe routes are the only ones added.
func TestUnrelatedIndexPathStillUnhandled(t *testing.T) {
	srv, reg, _ := serverWithMetrics(t)
	resp, _ := getBody(t, srv.URL+"/some_index/_mapping")
	if resp.StatusCode != http.StatusOK { // unhandled still answers 200 {}
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if n := rejectCount(t, reg, "unhandled_endpoint"); n != 1 {
		t.Fatalf("unhandled_endpoint = %v, want 1 (an unmodelled sub-resource)", n)
	}
}
