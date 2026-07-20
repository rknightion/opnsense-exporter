package capture

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// readAll reads every NDJSON record written for a receiver, across all rotated
// files, in file order.
func readAll(t *testing.T, dir, receiver string) []map[string]any {
	t.Helper()
	rdir := filepath.Join(dir, receiver)
	entries, err := os.ReadDir(rdir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".ndjson") {
			names = append(names, e.Name())
		}
	}
	// ReadDir already returns sorted names; capture-000 < capture-001 lexically.
	var out []map[string]any
	for _, n := range names {
		f, err := os.Open(filepath.Join(rdir, n))
		if err != nil {
			t.Fatalf("open %s: %v", n, err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
		for sc.Scan() {
			line := sc.Bytes()
			if len(strings.TrimSpace(string(line))) == 0 {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal(line, &m); err != nil {
				t.Fatalf("bad ndjson in %s: %v (%q)", n, err, line)
			}
			out = append(out, m)
		}
		f.Close()
	}
	return out
}

func counterVal(t *testing.T, c prometheus.Collector, labels ...string) float64 {
	t.Helper()
	// Find the metric matching the label VALUES (order-insensitive by value set).
	ch := make(chan prometheus.Metric, 64)
	go func() { c.Collect(ch); close(ch) }()
	want := map[string]bool{}
	for _, l := range labels {
		want[l] = true
	}
	for m := range ch {
		var d dto.Metric
		if err := m.Write(&d); err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, lp := range d.Label {
			got[lp.GetValue()] = true
		}
		if len(got) == len(want) {
			ok := true
			for k := range want {
				if !got[k] {
					ok = false
					break
				}
			}
			if ok {
				return d.GetCounter().GetValue()
			}
		}
	}
	return -1
}

func TestCaptureWritesNDJSON(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{Dir: dir, MaxBytes: 1 << 20}, prometheus.NewRegistry(), nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Capture(ReceiverZenarmor, KindUnhandledEndpoint, map[string]any{
		"method": "GET", "path": "/foo/_alias",
	})
	c.Capture(ReceiverSyslog, KindUnparsed, map[string]any{
		"program": "mystery", "message": "who am i",
	})
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	za := readAll(t, dir, ReceiverZenarmor)
	if len(za) != 1 {
		t.Fatalf("zenarmor records = %d, want 1", len(za))
	}
	rec := za[0]
	if rec["receiver"] != ReceiverZenarmor || rec["kind"] != KindUnhandledEndpoint {
		t.Fatalf("envelope wrong: %+v", rec)
	}
	if rec["method"] != "GET" || rec["path"] != "/foo/_alias" {
		t.Fatalf("fields lost: %+v", rec)
	}
	if _, ok := rec["ts"]; !ok {
		t.Fatalf("no ts: %+v", rec)
	}
	sl := readAll(t, dir, ReceiverSyslog)
	if len(sl) != 1 || sl[0]["program"] != "mystery" {
		t.Fatalf("syslog record wrong: %+v", sl)
	}
}

// TestRawBytesCapturedAsJSON: a []byte doc is embedded as raw JSON, not base64.
func TestRawBytesCapturedAsJSON(t *testing.T) {
	dir := t.TempDir()
	c, _ := New(Config{Dir: dir, MaxBytes: 1 << 20}, prometheus.NewRegistry(), nil)
	doc := []byte(`{"src":"10.0.0.1","dport":443}`)
	c.Capture(ReceiverZenarmor, KindParseError, map[string]any{"family": "conn", "doc": doc})
	// Mutate the caller's buffer AFTER Capture returns: it must not affect the capture.
	for i := range doc {
		doc[i] = 'x'
	}
	c.Close()

	recs := readAll(t, dir, ReceiverZenarmor)
	if len(recs) != 1 {
		t.Fatalf("records = %d", len(recs))
	}
	docField, ok := recs[0]["doc"].(map[string]any)
	if !ok {
		t.Fatalf("doc not embedded as object: %+v", recs[0]["doc"])
	}
	if docField["src"] != "10.0.0.1" {
		t.Fatalf("doc content wrong or corrupted by caller mutation: %+v", docField)
	}
}

// TestByteCapStopsKeepOldest: once the cap is hit, later entries are dropped and
// what was written first survives.
func TestByteCapStopsKeepOldest(t *testing.T) {
	dir := t.TempDir()
	reg := prometheus.NewRegistry()
	// A tiny cap: the first record fits, the rest do not.
	c, _ := New(Config{Dir: dir, MaxBytes: 120, PerFileBytes: 1 << 20}, reg, nil)
	c.Capture(ReceiverSyslog, KindUnparsed, map[string]any{"n": "first", "pad": strings.Repeat("a", 10)})
	for range 50 {
		c.Capture(ReceiverSyslog, KindUnparsed, map[string]any{"n": "later", "pad": strings.Repeat("b", 40)})
	}
	c.Close()

	recs := readAll(t, dir, ReceiverSyslog)
	if len(recs) == 0 {
		t.Fatal("expected at least the first record to survive")
	}
	if recs[0]["n"] != "first" {
		t.Fatalf("oldest not kept: %+v", recs[0])
	}
	if dropped := counterVal(t, c.m.dropped, ReceiverSyslog, "cap_reached"); dropped <= 0 {
		t.Fatalf("cap_reached not counted: %v", dropped)
	}
}

// TestExistingBytesCountTowardCap: a restart with a dir already over the cap
// captures nothing.
func TestExistingBytesCountTowardCap(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, ReceiverSyslog)
	if err := os.MkdirAll(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	// Pre-seed a valid-NDJSON file already larger than the cap.
	seed := []byte(strings.Repeat(`{"n":"seeded"}`+"\n", 40))
	if err := os.WriteFile(filepath.Join(sub, "capture-000.ndjson"), seed, 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := New(Config{Dir: dir, MaxBytes: 100}, prometheus.NewRegistry(), nil)
	c.Capture(ReceiverSyslog, KindUnparsed, map[string]any{"n": "nope"})
	c.Close()

	recs := readAll(t, dir, ReceiverSyslog)
	for _, r := range recs {
		if r["n"] == "nope" {
			t.Fatal("captured despite dir already over cap")
		}
	}
}

// TestRotation: many records with a small per-file cap produce multiple files.
func TestRotation(t *testing.T) {
	dir := t.TempDir()
	c, _ := New(Config{Dir: dir, MaxBytes: 1 << 20, PerFileBytes: 200}, prometheus.NewRegistry(), nil)
	for i := range 40 {
		c.Capture(ReceiverSyslog, KindUnparsed, map[string]any{"i": i, "pad": strings.Repeat("z", 30)})
	}
	c.Close()

	entries, _ := os.ReadDir(filepath.Join(dir, ReceiverSyslog))
	files := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".ndjson") {
			files++
		}
	}
	if files < 2 {
		t.Fatalf("expected rotation into multiple files, got %d", files)
	}
	if got := len(readAll(t, dir, ReceiverSyslog)); got != 40 {
		t.Fatalf("records after rotation = %d, want 40", got)
	}
}

func TestNilCapturerNoop(t *testing.T) {
	var c *Capturer
	c.Capture(ReceiverSyslog, KindUnparsed, map[string]any{"a": "b"}) // must not panic
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentWriters(t *testing.T) {
	dir := t.TempDir()
	c, _ := New(Config{Dir: dir, MaxBytes: 10 << 20, ChanBuf: 4096}, prometheus.NewRegistry(), nil)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := range 100 {
				c.Capture(ReceiverZenarmor, KindUnknownFamily, map[string]any{"g": g, "i": i})
			}
		}(g)
	}
	wg.Wait()
	c.Close()

	captured := counterVal(t, c.m.captured, ReceiverZenarmor, KindUnknownFamily)
	dropped := counterVal(t, c.m.dropped, ReceiverZenarmor, "buffer_full")
	// Every entry either landed on disk or was counted as a buffer_full drop; none vanish.
	onDisk := float64(len(readAll(t, dir, ReceiverZenarmor)))
	if captured != onDisk {
		t.Fatalf("captured counter %v != records on disk %v", captured, onDisk)
	}
	if captured+dropped != 800 {
		t.Fatalf("captured(%v)+dropped(%v) = %v, want 800", captured, dropped, captured+dropped)
	}
}

func TestNewRequiresDir(t *testing.T) {
	if _, err := New(Config{Dir: "  "}, prometheus.NewRegistry(), nil); err == nil {
		t.Fatal("expected error for empty dir")
	}
}
