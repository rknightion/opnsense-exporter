package logship

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/options"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

// row builds a minimal filterlog JSON row with the given digest and action.
func row(digest, action string) string {
	return fmt.Sprintf(`{"rulenr":"1","subrulenr":"0","anchorname":"","rid":"0",`+
		`"interface":"vtnet0","reason":"match","action":%q,"dir":"in","ipversion":"4",`+
		`"protonum":"6","protoname":"tcp","length":"60","src":"10.0.0.1","dst":"10.0.0.2",`+
		`"srcport":"1","dstport":"2","tcpflags":"S","label":"","__timestamp__":"2026-07-13T20:21:57",`+
		`"__digest__":%q}`, action, digest)
}

func batch(rows ...string) string { return "[" + strings.Join(rows, ",") + "]" }

// scriptedServer serves a queue of response bodies (one per call) and records
// the ?digest= query it saw on each call.
type scriptedServer struct {
	mu        sync.Mutex
	responses []string
	digests   []string
	calls     int
}

func newTestFirewallSource(t *testing.T, responses ...string) (*firewallSource, *scriptedServer) {
	t.Helper()
	s := &scriptedServer{responses: responses}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		i := s.calls
		s.calls++
		s.digests = append(s.digests, r.URL.Query().Get("digest"))
		body := "[]"
		if i < len(s.responses) {
			body = s.responses[i]
		}
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	client, err := opnsense.NewClient(options.OPNSenseConfig{
		Protocol:  "http",
		Host:      strings.TrimPrefix(srv.URL, "http://"),
		APIKey:    "k",
		APISecret: "s",
	}, "test", slog.Default())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return newFirewallSource(&client, slog.Default()), s
}

func (s *scriptedServer) digestAt(i int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i >= len(s.digests) {
		return "<no-call>"
	}
	return s.digests[i]
}

func poll(t *testing.T, src *firewallSource) []Record {
	t.Helper()
	recs, err := src.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	return recs
}

// TestFirewall_FirstPollPrimesShipsNothing verifies the resume-from-now start:
// the first poll adopts the newest digest as the cursor and ships nothing.
func TestFirewall_FirstPollPrimesShipsNothing(t *testing.T) {
	src, srv := newTestFirewallSource(t, batch(row("aaa", "pass"), row("bbb", "block")))

	recs := poll(t, src)
	if len(recs) != 0 {
		t.Fatalf("first poll shipped %d records, want 0 (resume-from-now)", len(recs))
	}
	if d := srv.digestAt(0); d != "" {
		t.Errorf("first poll sent digest=%q, want empty", d)
	}
	src.mu.Lock()
	defer src.mu.Unlock()
	if src.cursor != "aaa" {
		t.Errorf("cursor = %q after prime, want newest digest aaa", src.cursor)
	}
}

// TestFirewall_IncrementalShipsNewDropsCursor verifies the steady-state cursor:
// new rows ship (oldest-first), the cursor row is dropped, and the cursor
// advances to the newest digest.
func TestFirewall_IncrementalShipsNewDropsCursor(t *testing.T) {
	src, srv := newTestFirewallSource(t,
		batch(row("aaa", "pass")), // prime -> cursor aaa
		batch(row("ccc", "block"), row("bbb", "pass"), row("aaa", "pass")), // ccc,bbb new; aaa=cursor
	)
	poll(t, src) // prime

	recs := poll(t, src)
	if d := srv.digestAt(1); d != "aaa" {
		t.Fatalf("second poll sent digest=%q, want aaa", d)
	}
	if len(recs) != 2 {
		t.Fatalf("shipped %d records, want 2 (ccc,bbb; aaa dropped)", len(recs))
	}
	// oldest-first: bbb before ccc.
	if recs[0].Attributes["digest"] != "bbb" || recs[1].Attributes["digest"] != "ccc" {
		t.Errorf("records not oldest-first: %q then %q", recs[0].Attributes["digest"], recs[1].Attributes["digest"])
	}
	src.mu.Lock()
	defer src.mu.Unlock()
	if src.cursor != "ccc" {
		t.Errorf("cursor = %q, want ccc", src.cursor)
	}
}

// TestFirewall_EmptyPollShipsNothing verifies a poll that returns only the
// cursor row (no new events) ships nothing and does not report a gap.
func TestFirewall_EmptyPollShipsNothing(t *testing.T) {
	src, _ := newTestFirewallSource(t,
		batch(row("aaa", "pass")), // prime
		batch(row("aaa", "pass")), // only the cursor row
	)
	poll(t, src)
	if recs := poll(t, src); len(recs) != 0 {
		t.Fatalf("shipped %d, want 0 on a no-new-events poll", len(recs))
	}
	src.mu.Lock()
	defer src.mu.Unlock()
	if !src.lastGapWarn.IsZero() {
		t.Error("no gap should be recorded when the cursor row is present")
	}
}

// TestFirewall_GapWhenCursorMissing verifies rotation/overflow handling: when
// the cursor is not in the returned batch, all returned rows ship, the cursor
// resumes from the newest digest, and a gap is recorded.
func TestFirewall_GapWhenCursorMissing(t *testing.T) {
	src, _ := newTestFirewallSource(t,
		batch(row("old", "pass")), // prime -> cursor old
		batch(row("n3", "pass"), row("n2", "block"), row("n1", "pass")), // cursor "old" absent
	)
	poll(t, src)

	recs := poll(t, src)
	if len(recs) != 3 {
		t.Fatalf("shipped %d, want 3 (all returned rows on a gap)", len(recs))
	}
	src.mu.Lock()
	defer src.mu.Unlock()
	if src.cursor != "n3" {
		t.Errorf("cursor = %q, want newest n3 after gap resume", src.cursor)
	}
	if src.lastGapWarn.IsZero() {
		t.Error("a gap should have been recorded (cursor absent from batch)")
	}
}

// TestFirewall_DedupSuppressesReReadRows verifies the dedup ring suppresses a
// previously seen digest that a rotation re-read resurfaces alongside the cursor.
func TestFirewall_DedupSuppressesReReadRows(t *testing.T) {
	src, _ := newTestFirewallSource(t,
		batch(row("aaa", "pass")),                     // prime -> seen{aaa}, cursor aaa
		batch(row("bbb", "pass"), row("aaa", "pass")), // ship bbb; cursor bbb, seen{aaa,bbb}
		batch(row("aaa", "pass"), row("bbb", "pass")), // bbb=cursor(drop); aaa already seen(skip)
	)
	poll(t, src)
	if recs := poll(t, src); len(recs) != 1 || recs[0].Attributes["digest"] != "bbb" {
		t.Fatalf("second poll = %v, want [bbb]", recs)
	}
	if recs := poll(t, src); len(recs) != 0 {
		t.Fatalf("third poll shipped %d, want 0 (aaa deduped, bbb is cursor)", len(recs))
	}
}

// TestFirewall_StateRoundTripResumesFromCursor verifies SaveState/LoadState
// persist the digest cursor and that a resumed source polls with it immediately
// (no from-now re-prime).
func TestFirewall_StateRoundTripResumesFromCursor(t *testing.T) {
	src, _ := newTestFirewallSource(t, batch(row("aaa", "pass")))
	if _, ok := src.SaveState(); ok {
		t.Error("SaveState should report nothing to persist before the first poll")
	}
	poll(t, src) // prime -> cursor aaa

	data, ok := src.SaveState()
	if !ok {
		t.Fatal("SaveState should persist after priming")
	}
	var st firewallState
	if err := json.Unmarshal(data, &st); err != nil || st.Digest != "aaa" {
		t.Fatalf("persisted state = %s (%v), want digest aaa", data, err)
	}

	// A fresh source that loads the state must poll WITH the cursor on its first
	// call, not re-prime from now.
	resumed, srv := newTestFirewallSource(t, batch(row("bbb", "pass"), row("aaa", "pass")))
	resumed.LoadState(data)
	recs := poll(t, resumed)
	if d := srv.digestAt(0); d != "aaa" {
		t.Fatalf("resumed first poll sent digest=%q, want the loaded cursor aaa", d)
	}
	if len(recs) != 1 || recs[0].Attributes["digest"] != "bbb" {
		t.Fatalf("resumed poll = %v, want [bbb] shipped immediately", recs)
	}
}

func TestFirewall_LoadStateCorruptResumesFromNow(t *testing.T) {
	src, srv := newTestFirewallSource(t, batch(row("aaa", "pass")))
	src.LoadState([]byte("not json"))
	// Still unprimed: the next poll primes from now (no digest, ships nothing).
	if recs := poll(t, src); len(recs) != 0 {
		t.Fatalf("corrupt state should leave source unprimed; shipped %d", len(recs))
	}
	if d := srv.digestAt(0); d != "" {
		t.Errorf("primed poll after corrupt state sent digest=%q, want empty", d)
	}
}

func TestFirewall_EnrichmentAttributesBodyAndSeverity(t *testing.T) {
	r := &opnsense.FirewallLogRecord{
		Timestamp: "2026-07-13T20:21:57", Digest: "d1", RuleNr: "16", SubRuleNr: "115",
		RID: "abc", Interface: "vtnet2", Reason: "match", Action: "block", Dir: "out",
		IPVersion: "4", ProtoName: "tcp", ProtoNum: "6", Length: "60",
		Src: "172.16.9.1", Dst: "172.16.9.99", SrcPort: "54046", DstPort: "8082",
		TCPFlags: "S", Label: "allow web",
	}
	rec := recordFromFirewallRow(r, slog.Default())

	if rec.Severity != SeverityWarn {
		t.Errorf("block action should map to SeverityWarn, got %v", rec.Severity)
	}
	want := map[string]string{
		"action": "block", "interface": "vtnet2", "dir": "out", "reason": "match",
		"ipversion": "4", "proto": "tcp", "protonum": "6", "src": "172.16.9.1",
		"dst": "172.16.9.99", "srcport": "54046", "dstport": "8082", "length": "60",
		"tcpflags": "S", "rid": "abc", "rulenr": "16", "subrulenr": "115",
		"label": "allow web", "digest": "d1",
	}
	for k, v := range want {
		if rec.Attributes[k] != v {
			t.Errorf("attr %q = %q, want %q", k, rec.Attributes[k], v)
		}
	}
	if _, ok := rec.Attributes["anchorname"]; ok {
		t.Error("empty anchorname must be omitted from attributes")
	}
	if _, ok := rec.Attributes["source"]; ok {
		t.Error("reserved key source must never be set by the source")
	}
	// Body is compact JSON carrying the label and endpoints.
	var body map[string]string
	if err := json.Unmarshal([]byte(rec.Body), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%q)", err, rec.Body)
	}
	if body["label"] != "allow web" || body["src"] != "172.16.9.1" || body["action"] != "block" {
		t.Errorf("body missing expected fields: %s", rec.Body)
	}
	if !rec.Timestamp.Equal(time.Date(2026, 7, 13, 20, 21, 57, 0, time.Local)) {
		t.Errorf("timestamp = %v, want local 2026-07-13T20:21:57", rec.Timestamp)
	}
}

func TestFirewall_PassActionIsInfoAndOmitsEmptyOptionalFields(t *testing.T) {
	// An icmp pass row with no ports / tcpflags.
	r := &opnsense.FirewallLogRecord{
		Timestamp: "2026-07-13T20:21:57", Digest: "d2", Action: "pass",
		Interface: "vtnet0", Dir: "in", ProtoName: "ipv6-icmp", Src: "fe80::1", Dst: "fe80::2",
	}
	rec := recordFromFirewallRow(r, slog.Default())
	if rec.Severity != SeverityInfo {
		t.Errorf("pass action should map to SeverityInfo, got %v", rec.Severity)
	}
	for _, k := range []string{"srcport", "dstport", "tcpflags", "label"} {
		if _, ok := rec.Attributes[k]; ok {
			t.Errorf("empty %q must be omitted from attributes", k)
		}
	}
}

func TestFirewall_ParseTimestampFallsBackToZero(t *testing.T) {
	if ts := parseFirewallTimestamp("garbage", slog.Default()); !ts.IsZero() {
		t.Errorf("unparseable timestamp should be zero, got %v", ts)
	}
	if ts := parseFirewallTimestamp("", slog.Default()); !ts.IsZero() {
		t.Errorf("empty timestamp should be zero, got %v", ts)
	}
}

func TestFirewall_SourceMetadata(t *testing.T) {
	src, _ := newTestFirewallSource(t)
	if src.Name() != "firewall" {
		t.Errorf("Name = %q, want firewall", src.Name())
	}
	if src.MinInterval() != 10*time.Second {
		t.Errorf("MinInterval = %v, want 10s", src.MinInterval())
	}
	// Contract conformance: the firewall source is a StatefulSource + IntervalSource.
	var _ StatefulSource = src
	var _ IntervalSource = src
}

func TestDigestRing_EvictsOldestBeyondCapacity(t *testing.T) {
	r := newDigestRing(3)
	for _, d := range []string{"a", "b", "c"} {
		r.add(d)
	}
	if !r.contains("a") || !r.contains("c") {
		t.Fatal("ring should hold a and c")
	}
	r.add("d") // evicts a
	if r.contains("a") {
		t.Error("a should have been evicted")
	}
	if !r.contains("b") || !r.contains("c") || !r.contains("d") {
		t.Error("b, c, d should be present")
	}
	r.add("d") // duplicate add is a no-op, must not evict b
	if !r.contains("b") {
		t.Error("duplicate add must not evict anything")
	}
	r.add("") // empty digest ignored
	if r.contains("") {
		t.Error("empty digest must never be stored")
	}
}
