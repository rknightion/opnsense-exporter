package webui

import (
	"strings"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v5/internal/collector"
)

// TestCollectorRow_FreshnessIsDataAgeNotAttemptAge is the #382 regression. A
// collector that succeeded at 10:00 and has failed every minute since is still
// replaying its 10:00 values at 16:00, but every failed retry refreshes the
// ATTEMPT clock. Freshness derived from LastFinished therefore reads "<1m" while
// the data an operator is looking at is six hours old.
func TestCollectorRow_FreshnessIsDataAgeNotAttemptAge(t *testing.T) {
	now := time.Now()
	s := collector.CollectorStat{
		Name: "gateways", Display: "Gateways",
		Runs: 400, Failures: 359, LastOK: false, LastError: "context deadline exceeded",
		Interval: time.Minute,
		// Last ATTEMPT finished seconds ago — the retries keep landing on time.
		LastFinished: now.Add(-2 * time.Second),
		// but the stored buffer was last REPLACED six hours ago.
		SnapshotAt:    now.Add(-6 * time.Hour),
		LastSuccessAt: now.Add(-6 * time.Hour),
		NextDeadline:  now.Add(58 * time.Second),
	}

	r := collectorRow(s)

	if r.DataAgeSec < 21000 {
		t.Errorf("DataAgeSec = %d, want ~21600 (six-hour-old retained data)", r.DataAgeSec)
	}
	if r.FreshnessState != "stale" {
		t.Errorf("FreshnessState = %q, want stale — six-hour-old data on a 1m interval", r.FreshnessState)
	}
	if r.Freshness == "" || r.Freshness[0] == '2' && len(r.Freshness) < 5 {
		t.Errorf("Freshness = %q, want the six-hour data age", r.Freshness)
	}
	// The attempt clock must still be visible, and must not be the freshness value.
	if r.AttemptAgeSec < 0 || r.AttemptAgeSec > 60 {
		t.Errorf("AttemptAgeSec = %d, want a few seconds (last attempt is recent)", r.AttemptAgeSec)
	}
	if r.AttemptAge == "" {
		t.Errorf("AttemptAge empty; the attempt clock must stay visible")
	}
	if r.AttemptAge == r.Freshness {
		t.Errorf("AttemptAge and Freshness are the same value (%q); they are different clocks", r.Freshness)
	}
}

// A collector that has run but never stored a buffer has no data age at all.
func TestCollectorRow_NoDataYet(t *testing.T) {
	now := time.Now()
	r := collectorRow(collector.CollectorStat{
		Name: "x", Display: "X", Runs: 2, LastOK: false, Interval: time.Minute,
		LastFinished: now.Add(-time.Second),
	})
	if r.HasData {
		t.Errorf("HasData true with a zero SnapshotAt")
	}
	if r.FreshnessState != "none" {
		t.Errorf("FreshnessState = %q, want none", r.FreshnessState)
	}
	if r.DataAgeSec != -1 {
		t.Errorf("DataAgeSec = %d, want -1 (never stored)", r.DataAgeSec)
	}
	if r.AttemptAge == "" {
		t.Errorf("AttemptAge empty; the collector HAS attempted a poll")
	}
}

// Next-run must come from the scheduler's real deadline, not LastFinished+Interval.
// The recomputed value runs late by exactly the poll duration and is a whole
// cadence wrong after a poll that overran its interval.
func TestCollectorRow_NextRunUsesSchedulerDeadline(t *testing.T) {
	now := time.Now()
	r := collectorRow(collector.CollectorStat{
		Name: "gateways", Display: "Gateways", Runs: 5, LastOK: true,
		Interval:   60 * time.Second,
		SnapshotAt: now.Add(-30 * time.Second),
		// A poll that overran: the attempt finished 30s ago but the scheduler's
		// real next tick is only 5s away, not 30s.
		LastFinished: now.Add(-30 * time.Second),
		NextDeadline: now.Add(5 * time.Second),
	})
	if !r.Scheduled {
		t.Fatalf("Scheduled = false with a real NextDeadline")
	}
	if r.NextRunInSec < 3 || r.NextRunInSec > 6 {
		t.Errorf("NextRunInSec = %d, want ~5 (from NextDeadline, not LastFinished+Interval)", r.NextRunInSec)
	}
}

// A zero NextDeadline means the poller is not scheduled. That must NOT render as
// a countdown and must NOT render as "due".
func TestCollectorRow_NoDeadlineIsNotScheduled(t *testing.T) {
	now := time.Now()
	r := collectorRow(collector.CollectorStat{
		Name: "gateways", Display: "Gateways", Runs: 5, LastOK: true,
		Interval: 60 * time.Second, LastFinished: now.Add(-90 * time.Second),
		SnapshotAt: now.Add(-90 * time.Second),
	})
	if r.Scheduled {
		t.Fatalf("Scheduled = true with a zero NextDeadline")
	}
	if r.NextRunIn == "due" {
		t.Errorf(`NextRunIn = "due" for an unscheduled collector; nothing is going to run`)
	}
	if r.NextRunIn == "" {
		t.Errorf("NextRunIn empty; an unscheduled poller must say so")
	}
}

// The collectors table must label the two clocks unambiguously. "Freshness" on its
// own is exactly the word that made attempt age readable as data age, so the
// column headers have to name data age and attempt age separately.
func TestRenderPage_LabelsDataAgeAndAttemptAgeSeparately(t *testing.T) {
	now := time.Now()
	v := view{Title: "Status", RefreshMs: 5000, Data: Status{
		Service: ServiceInfo{Name: "opnsense2otel"},
		Health:  "degraded",
		Collectors: []CollectorRow{collectorRow(collector.CollectorStat{
			Name: "gateways", Display: "Gateways", Runs: 400, Failures: 359,
			Interval: time.Minute, LastFinished: now.Add(-2 * time.Second),
			SnapshotAt: now.Add(-6 * time.Hour), NextDeadline: now.Add(58 * time.Second),
		})},
	}}
	var sb strings.Builder
	if err := renderPage(&sb, v); err != nil {
		t.Fatalf("renderPage: %v", err)
	}
	out := sb.String()
	for _, want := range []string{"Data age", "Last attempt"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered page missing column %q", want)
		}
	}
	if strings.Contains(out, ">Freshness<") {
		t.Errorf(`bare "Freshness" column header survives; it is the ambiguous label being replaced`)
	}
}

// A passing deadline still reads "due" — the scheduler is late, not stopped.
func TestCollectorRow_PastDeadlineIsDue(t *testing.T) {
	now := time.Now()
	r := collectorRow(collector.CollectorStat{
		Name: "gateways", Display: "Gateways", Runs: 5, LastOK: true,
		Interval: 15 * time.Second, LastFinished: now.Add(-40 * time.Second),
		SnapshotAt: now.Add(-40 * time.Second), NextDeadline: now.Add(-2 * time.Second),
	})
	if r.NextRunIn != "due" {
		t.Errorf("NextRunIn = %q, want due", r.NextRunIn)
	}
}
