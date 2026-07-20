package zenarmor

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/capture"
)

// readCaptures reads every NDJSON capture record the receiver wrote under dir.
func readCaptures(t *testing.T, dir string) []map[string]any {
	t.Helper()
	rdir := filepath.Join(dir, capture.ReceiverZenarmor)
	entries, err := os.ReadDir(rdir)
	if err != nil {
		return nil
	}
	var out []map[string]any
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".ndjson") {
			continue
		}
		f, err := os.Open(filepath.Join(rdir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
		for sc.Scan() {
			if strings.TrimSpace(sc.Text()) == "" {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
				t.Fatalf("bad ndjson: %v (%q)", err, sc.Text())
			}
			out = append(out, m)
		}
		f.Close()
	}
	return out
}

func newCapturer(t *testing.T, dir string) *capture.Capturer {
	t.Helper()
	c, err := capture.New(capture.Config{Dir: dir, MaxBytes: 8 << 20}, prometheus.NewRegistry(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestUnhandledEndpointCapturedAndWarnSuppressed: with capture on, an unhandled
// endpoint is written to disk (method + path + headers) AND the "does not implement"
// WARN is suppressed — the capture file carries the signal instead.
func TestUnhandledEndpointCapturedAndWarnSuppressed(t *testing.T) {
	dir := t.TempDir()
	cap := newCapturer(t, dir)

	var logbuf strings.Builder
	log := slog.New(slog.NewTextHandler(&logbuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	srv := newServer(Config{}, func(string, []byte, netip.Addr) {}, nil, log)
	srv.cap = cap
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// A genuinely unmodelled index sub-resource (the _alias/_settings probes are now
	// handled directly, #331, so they no longer reach unhandled()).
	path := "/zenarmor_0000000000_019695d7_conn/_mapping"
	resp, err := http.Get(ts.URL + path) //nolint:noctx // test client
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if err := cap.Close(); err != nil {
		t.Fatal(err)
	}
	recs := readCaptures(t, dir)
	if len(recs) != 1 {
		t.Fatalf("capture records = %d, want 1: %+v", len(recs), recs)
	}
	r := recs[0]
	if r["kind"] != capture.KindUnhandledEndpoint || r["method"] != "GET" {
		t.Fatalf("wrong envelope: %+v", r)
	}
	if p, _ := r["path"].(string); !strings.Contains(p, "/_mapping") {
		t.Fatalf("path not captured: %+v", r)
	}
	if _, ok := r["headers"]; !ok {
		t.Fatalf("headers not captured: %+v", r)
	}
	if strings.Contains(logbuf.String(), "does not implement") {
		t.Fatalf("WARN was emitted despite capture being on:\n%s", logbuf.String())
	}
}

// TestUnhandledEndpointWarnsWithoutCapture: the existing behaviour is preserved when
// capture is off — the WARN fires and nothing is written.
func TestUnhandledEndpointWarnsWithoutCapture(t *testing.T) {
	var logbuf strings.Builder
	log := slog.New(slog.NewTextHandler(&logbuf, nil))

	srv := newServer(Config{}, func(string, []byte, netip.Addr) {}, nil, log)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/some_index/_mapping") //nolint:noctx // test client
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if !strings.Contains(logbuf.String(), "does not implement") {
		t.Fatalf("expected the unhandled WARN, got:\n%s", logbuf.String())
	}
}

// TestUnknownFamilyCaptured: a bulk document addressed to an index whose family we do
// not recognise is captured as unknown_family, with the raw document embedded.
func TestUnknownFamilyCaptured(t *testing.T) {
	dir := t.TempDir()
	cap := newCapturer(t, dir)

	s := &zenarmorSource{proc: docProcessor{cap: cap, m: newMetrics(prometheus.NewRegistry(), nil)}}
	emitted := 0
	s.emit = func(logship.Record) { emitted++ }
	s.handleDoc("totally_unknown_index", []byte(`{"src":"10.0.0.9"}`), netip.MustParseAddr("10.0.0.9"))

	_ = cap.Close()
	recs := readCaptures(t, dir)
	if len(recs) != 1 || recs[0]["kind"] != capture.KindUnknownFamily {
		t.Fatalf("unknown_family not captured: %+v", recs)
	}
	if recs[0]["index"] != "totally_unknown_index" {
		t.Fatalf("index not captured: %+v", recs[0])
	}
	doc, ok := recs[0]["doc"].(map[string]any)
	if !ok || doc["src"] != "10.0.0.9" {
		t.Fatalf("doc not embedded: %+v", recs[0]["doc"])
	}
	if emitted != 0 {
		t.Fatalf("unknown family should not emit a record, emitted %d", emitted)
	}
}

// TestParseErrorCaptured: a document that is not valid JSON is captured as
// parse_error but still ships (parseDoc keeps the raw body), so the count of emitted
// records is unaffected.
func TestParseErrorCaptured(t *testing.T) {
	dir := t.TempDir()
	cap := newCapturer(t, dir)

	p := &docProcessor{cap: cap, m: newMetrics(prometheus.NewRegistry(), nil)}
	emitted := 0
	p.process("conn", []byte("this is not json"), netip.Addr{}, nil, func(logship.Record) { emitted++ })

	_ = cap.Close()
	recs := readCaptures(t, dir)
	if len(recs) != 1 || recs[0]["kind"] != capture.KindParseError {
		t.Fatalf("parse_error not captured: %+v", recs)
	}
	if recs[0]["family"] != "conn" {
		t.Fatalf("family not captured: %+v", recs[0])
	}
	if emitted != 1 {
		t.Fatalf("parse error still ships the record; emitted = %d, want 1", emitted)
	}
}
