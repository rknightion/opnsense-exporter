package collector

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rknightion/opnsense2otel/v4/opnsense"
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

func TestStatusTracker_SetIntervalSurvivesRecord(t *testing.T) {
	tr := NewStatusTracker()
	tr.SetInterval("gw", 15*time.Second)
	tr.Record("gw", time.Now(), 5, true, "")
	snap := tr.Snapshot()
	if len(snap) != 1 || snap[0].Interval != 15*time.Second {
		t.Fatalf("interval should be retained across a Record, got %+v", snap)
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

// TestTrackerCarriesDataClocksAndDeadline pins the console-side seam for #382/#385.
// The console must be able to show retained-data age and a real next-run countdown
// WITHOUT gathering the registry — on a console-only deployment with OTLP disabled
// and no Prometheus scrape, the metricsnap capture may never exist at all, so the
// tracker has to carry these itself.
func TestTrackerCarriesDataClocksAndDeadline(t *testing.T) {
	tr := NewStatusTracker()
	snap := time.Now().Add(-2 * time.Hour)
	succ := time.Now().Add(-3 * time.Hour)
	next := time.Now().Add(30 * time.Second)

	tr.Record("gw", time.Now(), 5, false, "boom") // a recent FAILED attempt
	tr.RecordClocks("gw", snap, succ)
	tr.SetNextDeadline("gw", next)

	got := tr.Snapshot()
	if len(got) != 1 {
		t.Fatalf("want 1 stat, got %d", len(got))
	}
	s := got[0]
	if !s.SnapshotAt.Equal(snap) {
		t.Errorf("SnapshotAt = %v, want %v", s.SnapshotAt, snap)
	}
	if !s.LastSuccessAt.Equal(succ) {
		t.Errorf("LastSuccessAt = %v, want %v", s.LastSuccessAt, succ)
	}
	if !s.NextDeadline.Equal(next) {
		t.Errorf("NextDeadline = %v, want %v", s.NextDeadline, next)
	}
	// The whole point: the attempt is seconds old while the data is hours old.
	if !s.LastFinished.After(s.SnapshotAt) {
		t.Error("this fixture must model a recent attempt over stale data")
	}
}

// TestPollOnceFeedsTrackerClocks pins that the scheduler actually pushes the store's
// clocks into the tracker, so the console and the exported metrics cannot disagree.
func TestPollOnceFeedsTrackerClocks(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	tracker := NewStatusTracker()
	fake := &fakeCollectorInstance{name: "fake", emit: []prometheus.Metric{testMetric("opnsense_x", 1)}}
	c := newScrapeTestCollector(t, client, fake)
	c.statusTracker = tracker

	c.pollOnce(context.Background(), fake)
	good := tracker.Snapshot()[0]
	if good.SnapshotAt.IsZero() || good.LastSuccessAt.IsZero() {
		t.Fatalf("a successful poll must publish both data clocks to the tracker, got %+v", good)
	}

	// Now fail emptily: the tracker's data clocks must stay pinned even though the
	// attempt clock moves — the same contract the store enforces.
	time.Sleep(2 * time.Millisecond)
	fake.emit = nil
	fake.err = &opnsense.APICallError{Endpoint: "ep", Message: "boom"}
	c.pollOnce(context.Background(), fake)

	after := tracker.Snapshot()[0]
	if !after.SnapshotAt.Equal(good.SnapshotAt) {
		t.Errorf("failed poll must not advance the tracker's content clock: %v != %v", after.SnapshotAt, good.SnapshotAt)
	}
	if !after.LastSuccessAt.Equal(good.LastSuccessAt) {
		t.Error("failed poll must not advance the tracker's success clock")
	}
	if !after.LastFinished.After(good.LastFinished) {
		t.Error("failed poll must still advance the tracker's attempt clock")
	}
}
