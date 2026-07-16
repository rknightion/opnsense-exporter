package logship

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/opnsense"
)

// fakeIDSFetcher is a test double for idsFetcher: each call to
// FetchIDSAlertRecords returns the next queued batch (newest-first, as the
// wire genuinely returns it — tests deliberately do not pre-sort).
type fakeIDSFetcher struct {
	batches [][]opnsense.IDSAlertRecord
	calls   int
}

func (f *fakeIDSFetcher) FetchIDSAlertRecords() ([]opnsense.IDSAlertRecord, *opnsense.APICallError) {
	f.calls++
	if len(f.batches) == 0 {
		return nil, nil
	}
	b := f.batches[0]
	f.batches = f.batches[1:]
	return b, nil
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(discardWriter{}, nil)) }

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func alertAt(ts time.Time, flowID int64, sid int, action string) opnsense.IDSAlertRecord {
	return opnsense.IDSAlertRecord{
		Timestamp:   ts,
		FlowID:      flowID,
		AlertSID:    sid,
		AlertAction: action,
		Signature:   "GPL ATTACK_RESPONSE id check returned root",
		SrcIP:       "52.85.47.113",
		DestIP:      "172.16.9.50",
		InIface:     "vtnet2",
		Proto:       "TCP",
		Body:        `{"alert_sid":` + itoa(sid) + `}`,
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func TestIDSSource_NameAndMinInterval(t *testing.T) {
	s := newIDSSource(&fakeIDSFetcher{}, testLogger())
	if s.Name() != "ids" {
		t.Fatalf("Name() = %q, want ids", s.Name())
	}
	if s.MinInterval() != 30*time.Second {
		t.Fatalf("MinInterval() = %v, want 30s", s.MinInterval())
	}
}

// --- empty ------------------------------------------------------------

func TestIDSSource_Poll_EmptyReturnsNoRecordsNoError(t *testing.T) {
	fetcher := &fakeIDSFetcher{batches: [][]opnsense.IDSAlertRecord{{}}}
	s := newIDSSource(fetcher, testLogger())

	records, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("records = %d, want 0", len(records))
	}
	if s.cursorSet {
		t.Fatal("cursor must not be set after an empty poll")
	}
}

// --- first poll ---------------------------------------------------------

// TestIDSSource_Poll_FirstPollEmitsWholeWindow proves the first poll (no
// cursor established yet) ships every record in the initial window as a
// startup catch-up, in ascending time order, and seeds the cursor — it must
// NOT be treated as a gap even though there is no prior cursor to compare
// against.
func TestIDSSource_Poll_FirstPollEmitsWholeWindow(t *testing.T) {
	base := time.Date(2026, 7, 13, 18, 15, 0, 0, time.UTC)
	// Wire order is newest-first; Poll must still emit oldest-first.
	fetcher := &fakeIDSFetcher{batches: [][]opnsense.IDSAlertRecord{{
		alertAt(base.Add(2*time.Second), 3, 300, "allowed"),
		alertAt(base.Add(1*time.Second), 2, 200, "blocked"),
		alertAt(base, 1, 100, "allowed"),
	}}}
	s := newIDSSource(fetcher, testLogger())

	records, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("records = %d, want 3", len(records))
	}
	for i, want := range []time.Time{base, base.Add(1 * time.Second), base.Add(2 * time.Second)} {
		if !records[i].Timestamp.Equal(want) {
			t.Errorf("records[%d].Timestamp = %v, want %v (must be oldest-first)", i, records[i].Timestamp, want)
		}
	}
	// Attributes are exactly the bounded Loki-mapping set from the issue.
	attrs := records[0].Attributes
	for _, key := range []string{"alert_sid", "alert_action", "src_ip", "dest_ip", "in_iface", "proto", "signature"} {
		if _, ok := attrs[key]; !ok {
			t.Errorf("Attributes missing %q: %v", key, attrs)
		}
	}
	if attrs["alert_sid"] != "100" {
		t.Errorf("alert_sid = %q, want 100", attrs["alert_sid"])
	}
	if records[1].Severity != SeverityWarn {
		t.Errorf("blocked alert severity = %v, want SeverityWarn", records[1].Severity)
	}
	if records[0].Severity != SeverityInfo {
		t.Errorf("allowed alert severity = %v, want SeverityInfo", records[0].Severity)
	}

	if !s.cursorSet {
		t.Fatal("cursor must be set after the first poll")
	}
	if !s.lastTimestamp.Equal(base.Add(2 * time.Second)) {
		t.Errorf("cursor = %v, want %v (newest observed)", s.lastTimestamp, base.Add(2*time.Second))
	}
}

// --- incremental + dedup ------------------------------------------------

// TestIDSSource_Poll_IncrementalDedupesAtCursorBoundary proves a second poll
// only ships records strictly newer than the cursor, plus records that share
// the cursor's exact timestamp but were NOT part of the previous batch
// (keyed on flow_id+alert_sid, never on timestamp equality alone).
func TestIDSSource_Poll_IncrementalDedupesAtCursorBoundary(t *testing.T) {
	base := time.Date(2026, 7, 13, 18, 15, 0, 0, time.UTC)
	cursorTS := base.Add(1 * time.Second)

	fetcher := &fakeIDSFetcher{batches: [][]opnsense.IDSAlertRecord{
		{ // first poll
			alertAt(cursorTS, 2, 200, "allowed"),
			alertAt(base, 1, 100, "allowed"),
		},
		{ // second poll: same cursorTS record repeated (must be deduped) + a
			// second alert at the exact same cursorTS (must NOT be deduped -
			// different flow/sid) + one genuinely new, newer record.
			alertAt(base.Add(3*time.Second), 4, 400, "blocked"),
			alertAt(cursorTS, 5, 500, "allowed"), // new alert, same instant as cursor
			alertAt(cursorTS, 2, 200, "allowed"), // already shipped - must be skipped
		},
	}}
	s := newIDSSource(fetcher, testLogger())

	if _, err := s.Poll(context.Background()); err != nil {
		t.Fatalf("first Poll: %v", err)
	}

	records, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("second poll records = %d, want 2 (new-at-cursor + newer)", len(records))
	}
	// Oldest-first: the new same-instant alert (sid 500), then the newer one (sid 400).
	if records[0].Attributes["alert_sid"] != "500" {
		t.Errorf("records[0] alert_sid = %q, want 500", records[0].Attributes["alert_sid"])
	}
	if records[1].Attributes["alert_sid"] != "400" {
		t.Errorf("records[1] alert_sid = %q, want 400", records[1].Attributes["alert_sid"])
	}
	if !s.lastTimestamp.Equal(base.Add(3 * time.Second)) {
		t.Errorf("cursor = %v, want %v", s.lastTimestamp, base.Add(3*time.Second))
	}
}

// --- window-overflow gap --------------------------------------------------

// TestIDSSource_Poll_WindowOverflowGapEmitsSyntheticRecord proves that when a
// poll returns a FULL window (== opnsense.IDSAlertRowCap rows) whose oldest
// row is still newer than the prior cursor, the source emits one synthetic
// gap record (Severity=Warn, Attributes["event"]="gap_detected") describing
// the bounds, in addition to the genuinely new records.
func TestIDSSource_Poll_WindowOverflowGapEmitsSyntheticRecord(t *testing.T) {
	base := time.Date(2026, 7, 13, 18, 15, 0, 0, time.UTC)

	// First poll: a single old alert establishes the cursor far in the past.
	firstBatch := []opnsense.IDSAlertRecord{alertAt(base, 1, 100, "allowed")}

	// Second poll: a FULL window (rowCap rows) whose oldest entry is already
	// well after the cursor - i.e. the reverse read could not reach back to the
	// cursor, so whatever happened in between was never observed.
	full := make([]opnsense.IDSAlertRecord, opnsense.IDSAlertRowCap)
	windowStart := base.Add(time.Hour) // far newer than the cursor -> gap
	for i := range full {
		// Newest-first on the wire.
		full[i] = alertAt(windowStart.Add(time.Duration(opnsense.IDSAlertRowCap-1-i)*time.Second),
			int64(1000+i), 1000+i, "allowed")
	}

	fetcher := &fakeIDSFetcher{batches: [][]opnsense.IDSAlertRecord{firstBatch, full}}
	s := newIDSSource(fetcher, testLogger())

	if _, err := s.Poll(context.Background()); err != nil {
		t.Fatalf("first Poll: %v", err)
	}

	records, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	if len(records) != opnsense.IDSAlertRowCap+1 {
		t.Fatalf("records = %d, want %d (gap marker + full window)", len(records), opnsense.IDSAlertRowCap+1)
	}

	gap := records[0]
	if gap.Attributes["event"] != "gap_detected" {
		t.Fatalf("first record must be the gap marker, got attrs %v", gap.Attributes)
	}
	if gap.Severity != SeverityWarn {
		t.Errorf("gap record severity = %v, want SeverityWarn", gap.Severity)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(gap.Body), &payload); err != nil {
		t.Fatalf("gap record body is not valid JSON: %v (%s)", err, gap.Body)
	}
	if payload["event"] != "gap_detected" {
		t.Errorf("gap body event = %v, want gap_detected", payload["event"])
	}
	if payload["gap_start"] != base.Format(time.RFC3339Nano) {
		t.Errorf("gap_start = %v, want %v", payload["gap_start"], base.Format(time.RFC3339Nano))
	}
}

// TestIDSSource_Poll_FullWindowNoGapWhenOldestReachesCursor proves a full
// (rowCap-sized) window is NOT flagged as a gap when its oldest row still
// reaches back to (or before) the prior cursor - the read covered everything.
func TestIDSSource_Poll_FullWindowNoGapWhenOldestReachesCursor(t *testing.T) {
	base := time.Date(2026, 7, 13, 18, 15, 0, 0, time.UTC)
	firstBatch := []opnsense.IDSAlertRecord{alertAt(base, 1, 100, "allowed")}

	full := make([]opnsense.IDSAlertRecord, opnsense.IDSAlertRowCap)
	for i := range full {
		// Oldest row (i == len-1, newest-first) sits exactly at the cursor.
		full[i] = alertAt(base.Add(time.Duration(opnsense.IDSAlertRowCap-1-i)*time.Second),
			int64(2000+i), 2000+i, "allowed")
	}

	fetcher := &fakeIDSFetcher{batches: [][]opnsense.IDSAlertRecord{firstBatch, full}}
	s := newIDSSource(fetcher, testLogger())
	if _, err := s.Poll(context.Background()); err != nil {
		t.Fatalf("first Poll: %v", err)
	}

	records, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	for _, r := range records {
		if r.Attributes["event"] == "gap_detected" {
			t.Fatalf("unexpected gap marker when the window reached the prior cursor")
		}
	}
}

// --- StatefulSource round trip -------------------------------------------

func TestIDSSource_StateRoundTrip(t *testing.T) {
	base := time.Date(2026, 7, 13, 18, 15, 0, 0, time.UTC)
	fetcher := &fakeIDSFetcher{batches: [][]opnsense.IDSAlertRecord{{alertAt(base, 1, 100, "allowed")}}}
	s := newIDSSource(fetcher, testLogger())
	if _, err := s.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	data, ok := s.SaveState()
	if !ok {
		t.Fatal("SaveState ok=false after a successful poll")
	}

	restored := newIDSSource(&fakeIDSFetcher{}, testLogger())
	restored.LoadState(data)
	if !restored.cursorSet {
		t.Fatal("LoadState did not restore the cursor")
	}
	if !restored.lastTimestamp.Equal(base) {
		t.Errorf("restored cursor = %v, want %v", restored.lastTimestamp, base)
	}
	if _, ok := restored.dedupe[idsDedupeKey(alertAt(base, 1, 100, "allowed"))]; !ok {
		t.Error("restored dedupe ring missing the persisted key")
	}
}

func TestIDSSource_SaveState_NothingBeforeFirstPoll(t *testing.T) {
	s := newIDSSource(&fakeIDSFetcher{}, testLogger())
	if _, ok := s.SaveState(); ok {
		t.Fatal("SaveState ok=true before any successful poll")
	}
}

func TestIDSSource_LoadState_CorruptDataResetsToFreshStart(t *testing.T) {
	s := newIDSSource(&fakeIDSFetcher{}, testLogger())
	s.LoadState([]byte("not json"))
	if s.cursorSet {
		t.Fatal("corrupt state must not set a cursor")
	}
}

// The ids poll lane is mutually exclusive with the syslog receiver, but NOT with
// the zenarmor receiver — so its blocks must carry opnsense.action too, or
// {opnsense_action="block"} would silently omit them.
func TestIDSRecordFromAlert_SetsAttrAction(t *testing.T) {
	blocked := idsRecordFromAlert(opnsense.IDSAlertRecord{AlertAction: "blocked", Body: "{}"})
	if got := blocked.Attributes[AttrAction]; got != ActionBlock {
		t.Errorf("opnsense.action = %q, want %q", got, ActionBlock)
	}
	if got := blocked.Attributes["alert_action"]; got != "blocked" {
		t.Errorf("raw alert_action = %q, want blocked", got)
	}

	allowed := idsRecordFromAlert(opnsense.IDSAlertRecord{AlertAction: "allowed", Body: "{}"})
	if got := allowed.Attributes[AttrAction]; got != ActionPass {
		t.Errorf("opnsense.action = %q, want %q", got, ActionPass)
	}

	unknown := idsRecordFromAlert(opnsense.IDSAlertRecord{AlertAction: "", Body: "{}"})
	if v, present := unknown.Attributes[AttrAction]; present {
		t.Errorf("opnsense.action = %q for an empty action; must be absent", v)
	}
}
