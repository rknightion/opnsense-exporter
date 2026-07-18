package collector

import (
	"testing"
	"time"
)

func TestStatusTracker_RecordAndSnapshot(t *testing.T) {
	tr := NewStatusTracker()
	tr.Record("gateways", time.Now(), 12.0, true, "")
	tr.Record("gateways", time.Now(), 20.0, false, "boom")
	snap := tr.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("want 1, got %d", len(snap))
	}
	s := snap[0]
	if s.Runs != 2 || s.Failures != 1 || s.ConsecutiveFails != 1 {
		t.Fatalf("%d/%d/%d", s.Runs, s.Failures, s.ConsecutiveFails)
	}
	if s.LastOK || s.LastError != "boom" || s.LastDurationMs != 20.0 {
		t.Fatalf("%v/%q/%v", s.LastOK, s.LastError, s.LastDurationMs)
	}
	if len(s.DurationMs) != 2 || len(s.Outcomes) != 2 || s.Outcomes[1] {
		t.Fatalf("%v/%v", s.DurationMs, s.Outcomes)
	}
}

func TestStatusTracker_ConsecutiveResetsOnSuccess(t *testing.T) {
	tr := NewStatusTracker()
	tr.Record("x", time.Now(), 1, false, "e")
	tr.Record("x", time.Now(), 1, false, "e")
	tr.Record("x", time.Now(), 1, true, "")
	if tr.Snapshot()[0].ConsecutiveFails != 0 {
		t.Fatal("should reset")
	}
}

func TestStatusTracker_RingBounded(t *testing.T) {
	tr := NewStatusTracker()
	for i := 0; i < StatusRingSize+10; i++ {
		tr.Record("x", time.Now(), float64(i), true, "")
	}
	s := tr.Snapshot()[0]
	if len(s.DurationMs) != StatusRingSize {
		t.Fatalf("ring %d", len(s.DurationMs))
	}
	if s.DurationMs[len(s.DurationMs)-1] != float64(StatusRingSize+9) {
		t.Fatal("newest not last")
	}
}
