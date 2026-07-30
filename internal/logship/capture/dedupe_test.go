package capture

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// The two message families that between them held 70% of a real day's syslog
// capture (#362) are the reason this function exists, so they are the first cases:
// each family must fold to ONE shape however its numbers move.
func TestNormaliseShapeFoldsTheRealFirehoseFamilies(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		same bool
	}{
		{
			name: "arpresolve differs only by the bracketed counter and the address",
			a:    "<7>[367655] arpresolve: can't allocate llinfo for 198.51.100.106",
			b:    "<7>[412900] arpresolve: can't allocate llinfo for 198.51.100.7",
			same: true,
		},
		{
			name: "cron MAIL differs only by the byte count and the hex status",
			a:    "(nobody) MAIL (mailed 37 bytes of output but got status 0x00000000)",
			b:    "(nobody) MAIL (mailed 1284 bytes of output but got status 0x0000004b)",
			same: true,
		},
		{
			name: "dhclient differs only by the interface index",
			a:    "DHCPDISCOVER on ixl1 to 255.255.255.255 port 67",
			b:    "DHCPDISCOVER on ixl0 to 255.255.255.255 port 67",
			same: true,
		},
		{
			name: "padding is not a shape difference",
			a:    "dnsbl_module: updating blocklist.",
			b:    "dnsbl_module:   updating   blocklist.",
			same: true,
		},
		{
			name: "different messages from the same program stay distinct",
			a:    "arpresolve: can't allocate llinfo for 198.51.100.106",
			b:    "arplookup 198.51.100.106 failed: host is not on local network",
			same: false,
		},
		{
			name: "a novel message does not fold into a known one",
			a:    "dnsbl_module: updating blocklist.",
			b:    "dnsbl_module: failed to load blocklist.",
			same: false,
		},
		{
			name: "a long hex token collapses but a word does not",
			a:    "session 9f8e7d6c5b4a3210 closed",
			b:    "session 0011223344556677 closed",
			same: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ga, gb := NormaliseShape(tc.a), NormaliseShape(tc.b)
			if tc.same && ga != gb {
				t.Fatalf("shapes should fold together:\n  %q -> %q\n  %q -> %q", tc.a, ga, tc.b, gb)
			}
			if !tc.same && ga == gb {
				t.Fatalf("shapes should stay distinct, both -> %q\n  %q\n  %q", ga, tc.a, tc.b)
			}
		})
	}
}

// A shape is a map key held for a window, so its length must be bounded no matter
// how long the line was: a program logging a 64KB body must not mint a 64KB key.
func TestNormaliseShapeIsLengthBounded(t *testing.T) {
	long := strings.Repeat("the quick brown fox ", 4000)
	got := NormaliseShape(long)
	if len([]rune(got)) > maxShapeLen {
		t.Fatalf("shape is %d runes, want <= %d", len([]rune(got)), maxShapeLen)
	}
	// Truncation must not split a multi-byte rune: the key is still valid UTF-8.
	multi := strings.Repeat("é", 500)
	if s := NormaliseShape(multi); !strings.HasSuffix(s, "é") {
		t.Fatalf("truncation split a rune: %q", s)
	}
}

func TestShapeLimiterFirstOccurrenceAlwaysAllowed(t *testing.T) {
	l := NewShapeLimiter(15*time.Minute, 8)
	now := time.Unix(1_700_000_000, 0)
	for _, k := range []string{"a", "b", "c"} {
		if !l.Allow(k, now) {
			t.Fatalf("first occurrence of %q suppressed", k)
		}
	}
}

func TestShapeLimiterSuppressesInsideTheWindow(t *testing.T) {
	l := NewShapeLimiter(15*time.Minute, 8)
	now := time.Unix(1_700_000_000, 0)
	if !l.Allow("k", now) {
		t.Fatal("first occurrence suppressed")
	}
	for i := 1; i <= 100; i++ {
		if l.Allow("k", now.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("repeat at +%ds allowed inside the window", i)
		}
	}
	// Exactly at the window boundary the shape is due again.
	if !l.Allow("k", now.Add(15*time.Minute)) {
		t.Fatal("repeat after the window suppressed")
	}
	// ...and that allow re-armed the window from the new instant.
	if l.Allow("k", now.Add(15*time.Minute+time.Second)) {
		t.Fatal("window not re-armed after an allow")
	}
}

// Past the bound every further key folds into one shared slot, so a runaway program
// (or a sender minting a new shape per line) cannot grow the map without limit.
func TestShapeLimiterFoldsPastItsBound(t *testing.T) {
	const max = 16
	l := NewShapeLimiter(15*time.Minute, max)
	now := time.Unix(1_700_000_000, 0)
	for i := range max {
		if !l.Allow(string(rune('a'+i)), now) {
			t.Fatalf("key %d suppressed while under the bound", i)
		}
	}
	if got := l.size(); got != max {
		t.Fatalf("size = %d, want %d", got, max)
	}
	// The first key past the bound takes the folded slot; every later one shares it,
	// so they are suppressed even though each is individually novel.
	if !l.Allow("novel-0", now) {
		t.Fatal("the first folded key should still be allowed once")
	}
	for i := 1; i < 500; i++ {
		if l.Allow("novel-"+strings.Repeat("x", i), now) {
			t.Fatalf("folded key %d allowed; the fold is not holding", i)
		}
	}
	if got := l.size(); got != max+1 {
		t.Fatalf("size = %d after 500 novel keys, want %d (bound + the folded slot)", got, max+1)
	}
}

func TestShapeLimiterIsConcurrencySafe(t *testing.T) {
	l := NewShapeLimiter(15*time.Minute, 64)
	now := time.Unix(1_700_000_000, 0)
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for g := range 8 {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for range 100 {
				if l.Allow("shared", now) {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
			}
		}(g)
	}
	wg.Wait()
	if allowed != 1 {
		t.Fatalf("a single shape was allowed %d times across 8 goroutines, want 1", allowed)
	}
}

func TestNilShapeLimiterAllowsEverything(t *testing.T) {
	var l *ShapeLimiter
	now := time.Unix(1_700_000_000, 0)
	for i := range 3 {
		if !l.Allow("k", now.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("a nil limiter suppressed occurrence %d", i)
		}
	}
}

// CaptureShape writes the first occurrence of a shape and counts the rest as
// duplicate_shape, so the file being small is never mistaken for the lane being quiet.
func TestCaptureShapeWritesOnceAndCountsTheRest(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{Dir: dir, MaxBytes: 8 << 20}, prometheus.NewRegistry(), nil)
	if err != nil {
		t.Fatal(err)
	}
	sink := c.For(ReceiverSyslog)
	for i := range 50 {
		sink.CaptureShape(KindUnparsed, "kernel|arpresolve", map[string]any{"i": i})
	}
	// A different shape is a different fact and writes immediately.
	sink.CaptureShape(KindUnparsed, "cron|MAIL", map[string]any{"i": "other"})
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	recs := readAll(t, dir, ReceiverSyslog)
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2 (one per shape): %+v", len(recs), recs)
	}
	if recs[0]["i"] != float64(0) {
		t.Fatalf("the FIRST occurrence must be the one kept: %+v", recs[0])
	}
	if got := counterVal(t, c.m.dropped, ReceiverSyslog, "duplicate_shape"); got != 49 {
		t.Fatalf("duplicate_shape = %v, want 49", got)
	}
	if got := counterVal(t, c.m.captured, ReceiverSyslog, KindUnparsed); got != 2 {
		t.Fatalf("captured = %v, want 2", got)
	}
}

// The shape key is scoped by receiver and kind, so two receivers reporting the same
// text cannot suppress each other.
func TestCaptureShapeKeyIsScopedByReceiverAndKind(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{Dir: dir, MaxBytes: 8 << 20}, prometheus.NewRegistry(), nil)
	if err != nil {
		t.Fatal(err)
	}
	c.For(ReceiverSyslog).CaptureShape(KindUnparsed, "same", map[string]any{"n": 1})
	c.For(ReceiverZenarmor).CaptureShape(KindUnparsed, "same", map[string]any{"n": 2})
	c.For(ReceiverZenarmor).CaptureShape(KindParseError, "same", map[string]any{"n": 3})
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if got := len(readAll(t, dir, ReceiverSyslog)); got != 1 {
		t.Fatalf("syslog records = %d, want 1", got)
	}
	if got := len(readAll(t, dir, ReceiverZenarmor)); got != 2 {
		t.Fatalf("zenarmor records = %d, want 2 (one per kind)", got)
	}
}

// The dedupe limiter lives on the Capturer, not the sink: For() mints a fresh sink
// on demand (the NetFlow lane calls it inline), so per-sink state would silently
// defeat dedupe for any caller that does not hold one sink for the process's life.
func TestCaptureShapeDedupesAcrossSinkInstances(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{Dir: dir, MaxBytes: 8 << 20}, prometheus.NewRegistry(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		c.For(ReceiverSyslog).CaptureShape(KindUnparsed, "kernel|arpresolve", nil)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if got := len(readAll(t, dir, ReceiverSyslog)); got != 1 {
		t.Fatalf("records = %d, want 1", got)
	}
}

// REGRESSION GUARD (#362): Capture is the path the NetFlow and Zenarmor lanes use,
// and both are already bounded by design — a couple of datagrams at startup, or
// nothing at all. Routing them through the shape window would silently throw away
// samples they need. Capture must write EVERY call, identical fields or not.
func TestCaptureIsNotDeduped(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{Dir: dir, MaxBytes: 8 << 20}, prometheus.NewRegistry(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 25 {
		c.Capture(ReceiverNetflow, KindDatagram, map[string]any{"payload_b64": "AAk="})
	}
	sink := c.For(ReceiverZenarmor)
	for range 25 {
		sink.Capture(KindUnknownFamily, map[string]any{"family": "conn"})
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if got := len(readAll(t, dir, ReceiverNetflow)); got != 25 {
		t.Fatalf("netflow records = %d, want 25 - Capture must never dedupe", got)
	}
	if got := len(readAll(t, dir, ReceiverZenarmor)); got != 25 {
		t.Fatalf("zenarmor records = %d, want 25 - Capture must never dedupe", got)
	}
	if got := counterVal(t, c.m.dropped, ReceiverNetflow, "duplicate_shape"); got != 0 {
		t.Fatalf("duplicate_shape = %v on the plain Capture path, want 0", got)
	}
}

// duplicate_shape is part of the closed reason vocabulary, so it is pre-initialised
// to zero like the others (#280) — a lane that has never deduped reports a flat 0
// rather than no series at all.
func TestDuplicateShapeReasonPreInitialised(t *testing.T) {
	found := false
	for _, r := range dropReasons {
		if r == "duplicate_shape" {
			found = true
		}
	}
	if !found {
		t.Fatalf("duplicate_shape missing from dropReasons: %v", dropReasons)
	}
	c, err := New(Config{Dir: t.TempDir(), MaxBytes: 1 << 20}, prometheus.NewRegistry(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, recv := range receivers {
		if got := counterVal(t, c.m.dropped, recv, "duplicate_shape"); got != 0 {
			t.Fatalf("dropped{%s,duplicate_shape} = %v, want a pre-initialised 0", recv, got)
		}
	}
}
