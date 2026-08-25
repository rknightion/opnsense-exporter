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

// TestCopyFields_RedactsSensitiveHeaders: a "headers" field shaped like
// map[string][]string must have every sensitive header value replaced by a fixed,
// irreversible placeholder — regardless of which receiver built the fields map, since
// copyFields is the one chokepoint every Capture/CaptureShape call passes through
// before enqueue (#561).
func TestCopyFields_RedactsSensitiveHeaders(t *testing.T) {
	in := map[string]any{
		"headers": map[string][]string{
			"Authorization":       {"Basic dXNlcjpwYXNzd29yZA=="},
			"Proxy-Authorization": {"Basic Zm9vOmJhcg=="},
			"Cookie":              {"session=abc123"},
			"Set-Cookie":          {"session=abc123; Path=/"},
			"X-Api-Key":           {"supersecretkey"},
			"X-Auth-Token":        {"tok_live_12345"},
			"Content-Type":        {"application/json"},
			"User-Agent":          {"ipdrstreamer/1.0"},
		},
	}
	out := copyFields(in)
	headers, ok := out["headers"].(map[string][]string)
	if !ok {
		t.Fatalf("headers field missing or wrong type: %+v", out["headers"])
	}

	sensitive := []string{"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-Api-Key", "X-Auth-Token"}
	for _, h := range sensitive {
		vals, ok := headers[h]
		if !ok || len(vals) != 1 {
			t.Fatalf("%s: expected exactly one redacted value, got %+v", h, vals)
		}
		if vals[0] == "" {
			t.Fatalf("%s: redacted to empty string, want a fixed placeholder", h)
		}
		orig := in["headers"].(map[string][]string)[h][0]
		if strings.Contains(vals[0], orig) || vals[0] == orig {
			t.Fatalf("%s: raw value survived redaction: %+v", h, vals)
		}
		// Irreversibility guard: the placeholder must not be a reversible encoding of the
		// secret (e.g. a base64/hex re-encode an attacker could decode back).
		if strings.Contains(vals[0], "dXNlcjpwYXNzd29yZA") || strings.Contains(vals[0], "Zm9vOmJhcg") {
			t.Fatalf("%s: placeholder still embeds the encoded secret: %+v", h, vals)
		}
	}

	nonSensitive := map[string]string{"Content-Type": "application/json", "User-Agent": "ipdrstreamer/1.0"}
	for h, want := range nonSensitive {
		vals, ok := headers[h]
		if !ok || len(vals) != 1 || vals[0] != want {
			t.Fatalf("%s: non-sensitive header must survive unredacted, got %+v", h, vals)
		}
	}
}

// TestCopyFields_RedactsSensitiveHeaders_CaseInsensitive: header names must be
// matched case-insensitively — a capturer must not assume the map passed to it is
// pre-canonicalised the way net/http canonicalises http.Header.
func TestCopyFields_RedactsSensitiveHeaders_CaseInsensitive(t *testing.T) {
	in := map[string]any{
		"headers": map[string][]string{
			"authorization": {"Basic dXNlcjpwYXNzd29yZA=="},
			"COOKIE":        {"session=abc123"},
		},
	}
	out := copyFields(in)
	headers := out["headers"].(map[string][]string)
	for _, h := range []string{"authorization", "COOKIE"} {
		vals := headers[h]
		if len(vals) != 1 || strings.Contains(vals[0], "dXNlcjpwYXNzd29yZA") || strings.Contains(vals[0], "abc123") {
			t.Fatalf("%s: not redacted case-insensitively: %+v", h, vals)
		}
	}
}

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

func TestCaptureRejectsEntryBeforeCopyWhenQueueByteBudgetWouldBeExceeded(t *testing.T) {
	c, err := New(Config{Dir: t.TempDir(), MaxBytes: 1 << 20, QueueMaxBytes: 32}, prometheus.NewRegistry(), nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Capture(ReceiverZenarmor, KindParseError, map[string]any{"document": make([]byte, 1024)})
	if got := c.reserved.Load(); got != 0 {
		t.Fatalf("reserved queue bytes = %d, want 0", got)
	}
	if got := counterVal(t, c.m.dropped, ReceiverZenarmor, "byte_budget"); got != 1 {
		t.Fatalf("byte-budget drops = %v, want 1", got)
	}
	_ = c.Close()
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
