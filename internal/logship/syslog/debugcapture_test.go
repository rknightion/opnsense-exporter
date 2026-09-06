package syslog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/capture"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
)

func readSyslogCaptures(t *testing.T, dir string) []map[string]any {
	t.Helper()
	rdir := filepath.Join(dir, capture.ReceiverSyslog)
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
				t.Fatalf("bad ndjson: %v", err)
			}
			out = append(out, m)
		}
		f.Close()
	}
	return out
}

func newCaptureSource(t *testing.T, cap *capture.Capturer) *source {
	t.Helper()
	return &source{
		cache:  enrich.NewCache(),
		m:      logship.NewReceiverMetrics(prometheus.NewRegistry(), sourceName, logship.ReceiverVocab{Reasons: RejectReasons, Stages: ParseStages}),
		filter: NewFilter(nil, nil, 0, false),
		sink:   logship.NopMetricSink{},
		cap:    cap,
	}
}

// TestUnparsedLineCaptured: a line whose program has no registered parser is
// captured as unparsed (with program + raw line) AND still ships.
func TestUnparsedLineCaptured(t *testing.T) {
	dir := t.TempDir()
	cap, err := capture.New(capture.Config{Dir: dir, MaxBytes: 8 << 20}, prometheus.NewRegistry(), nil)
	if err != nil {
		t.Fatal(err)
	}

	s := newCaptureSource(t, cap)
	shipped := 0
	s.emit = func(logship.Record) { shipped++ }

	line := []byte(`<134>1 2026-07-14T19:50:01+01:00 opnsense mystery-plugin 42 - - something happened`)
	s.handle(line, netip.MustParseAddr("10.0.0.1"))

	if err := cap.Close(); err != nil {
		t.Fatal(err)
	}
	recs := readSyslogCaptures(t, dir)
	if len(recs) != 1 || recs[0]["kind"] != capture.KindUnparsed {
		t.Fatalf("unparsed line not captured: %+v", recs)
	}
	if recs[0]["program"] != "mystery-plugin" {
		t.Fatalf("program not captured: %+v", recs[0])
	}
	if raw, _ := recs[0]["raw"].(string); !strings.Contains(raw, "something happened") {
		t.Fatalf("raw line not captured: %+v", recs[0])
	}
	if shipped != 1 {
		t.Fatalf("unparsed line must still ship; shipped = %d", shipped)
	}
}

// TestRepeatedUnparsedLinesCapturedOnce pins the whole point of #362: a firewall's
// syslog is overwhelmingly programs with no parser, so the capture fired on the
// majority of all lines and filled the SHARED byte cap — starving the NetFlow and
// Zenarmor captures, which are bounded by design. The repeat is captured once per
// shape; it is still SHIPPED every time, because dedupe governs the debug capture
// and never what leaves the exporter.
func TestRepeatedUnparsedLinesCapturedOnce(t *testing.T) {
	dir := t.TempDir()
	cap, err := capture.New(capture.Config{Dir: dir, MaxBytes: 8 << 20}, prometheus.NewRegistry(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := newCaptureSource(t, cap)
	shipped := 0
	s.emit = func(logship.Record) { shipped++ }

	// The real thing: same shape, different counter and address every time.
	for i := range 3 {
		line := fmt.Appendf(nil,
			`<7>1 2026-07-14T19:50:0%d+01:00 opnsense kernel 42 - - [36765%d] arpresolve: can't allocate llinfo for 198.51.100.%d`,
			i, i, 100+i)
		s.handle(line, netip.MustParseAddr("10.0.0.1"))
	}
	if err := cap.Close(); err != nil {
		t.Fatal(err)
	}

	recs := readSyslogCaptures(t, dir)
	if len(recs) != 1 {
		t.Fatalf("capture entries = %d, want 1 (one per shape): %+v", len(recs), recs)
	}
	if recs[0]["program"] != "kernel" {
		t.Fatalf("program not captured: %+v", recs[0])
	}
	if shipped != 3 {
		t.Fatalf("shipped = %d, want 3 - dedupe must never drop a shipped record", shipped)
	}
}

// A genuinely novel program is what the capture exists for, so it writes at once
// even while a noisy neighbour is being suppressed.
func TestNovelUnparsedShapeCapturedImmediately(t *testing.T) {
	dir := t.TempDir()
	cap, err := capture.New(capture.Config{Dir: dir, MaxBytes: 8 << 20}, prometheus.NewRegistry(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := newCaptureSource(t, cap)
	s.emit = func(logship.Record) {}

	for range 5 {
		s.handle([]byte(`<7>1 2026-07-14T19:50:01+01:00 opnsense kernel 42 - - [367655] arpresolve: can't allocate llinfo for 198.51.100.106`),
			netip.MustParseAddr("10.0.0.1"))
	}
	s.handle([]byte(`<134>1 2026-07-14T19:50:01+01:00 opnsense mystery-plugin 42 - - something entirely new`),
		netip.MustParseAddr("10.0.0.1"))
	if err := cap.Close(); err != nil {
		t.Fatal(err)
	}

	recs := readSyslogCaptures(t, dir)
	if len(recs) != 2 {
		t.Fatalf("capture entries = %d, want 2 (kernel once, the novel program once): %+v", len(recs), recs)
	}
	if recs[1]["program"] != "mystery-plugin" {
		t.Fatalf("the novel program was not captured on its first occurrence: %+v", recs)
	}
}

// The envelope-parse-failure capture is deduped for the same reason: a device
// spamming malformed frames floods the shared cap exactly as the unparsed lane did.
// The line still ships with its raw body — that invariant is older than this one.
func TestRepeatedEnvelopeFailuresCapturedOnce(t *testing.T) {
	dir := t.TempDir()
	cap, err := capture.New(capture.Config{Dir: dir, MaxBytes: 8 << 20}, prometheus.NewRegistry(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := newCaptureSource(t, cap)
	shipped := 0
	s.emit = func(logship.Record) { shipped++ }

	for i := range 4 {
		s.handle(fmt.Appendf(nil, "this is not a syslog frame at all %d", i), netip.MustParseAddr("10.0.0.1"))
	}
	if err := cap.Close(); err != nil {
		t.Fatal(err)
	}

	recs := readSyslogCaptures(t, dir)
	if len(recs) != 1 {
		t.Fatalf("capture entries = %d, want 1: %+v", len(recs), recs)
	}
	if recs[0]["parse_error"] != "envelope" {
		t.Fatalf("wrong entry captured: %+v", recs[0])
	}
	if shipped != 4 {
		t.Fatalf("shipped = %d, want 4 - an unparseable line must always ship", shipped)
	}
}

// TestKnownProgramNotCaptured: a line a parser handles (unbound) is NOT captured —
// only unmodelled signals are.
func TestKnownProgramNotCaptured(t *testing.T) {
	dir := t.TempDir()
	cap, err := capture.New(capture.Config{Dir: dir, MaxBytes: 8 << 20}, prometheus.NewRegistry(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := newCaptureSource(t, cap)
	s.emit = func(logship.Record) {}

	// sshd IS a registered syslog parser, and this message matches its shape.
	line := []byte(`<38>1 2026-07-14T19:50:01+01:00 opnsense sshd 42 - - Accepted password for root from 10.0.0.6 port 34776 ssh2`)
	s.handle(line, netip.MustParseAddr("10.0.0.1"))

	_ = cap.Close()
	if recs := readSyslogCaptures(t, dir); len(recs) != 0 {
		t.Fatalf("a parsed line must not be captured: %+v", recs)
	}
}
