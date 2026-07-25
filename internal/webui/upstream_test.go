package webui

import (
	"strings"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/collector"
)

// trackerWithSuccess returns a StatusTracker whose only collector has a clean run
// history — the exact state that lets a transport outage hide behind an all-green
// collector table.
func trackerWithSuccess(t *testing.T, name, display string) *collector.StatusTracker {
	t.Helper()
	tr := collector.NewStatusTracker()
	tr.SetInterval(name, 60*time.Second)
	tr.Record(name, time.Now().Add(-2*time.Second), 12, true, "")
	tr.RecordClocks(name, time.Now().Add(-2*time.Second), time.Now().Add(-2*time.Second))
	tr.SetNextDeadline(name, time.Now().Add(58*time.Second))
	_ = display
	return tr
}

// TestDeriveHealth_UnreachableBeatsSuccessfulCollectorHistory is the #384
// regression. During a transport outage the scheduler SKIPS collector polls, so
// no failed run is ever recorded: every collector's last run still reads OK
// while opnsense_up is 0 and readiness is failing. Collector-only health
// therefore reports "healthy" through the exact outage it should be shouting
// about.
func TestDeriveHealth_UnreachableBeatsSuccessfulCollectorHistory(t *testing.T) {
	stats := []collector.CollectorStat{
		{Name: "gateways", Display: "Gateways", Runs: 9, LastOK: true},
		{Name: "unbound", Display: "Unbound", Runs: 12, LastOK: true},
	}
	up := &collector.HealthSnapshot{
		Polled: true, CheckOK: false, Unreachable: true,
		CheckedAt: time.Now(), LastError: "dial tcp 10.0.0.1:443: connect: connection refused",
	}

	h, reasons := deriveHealth(stats, up)

	if h != "degraded" {
		t.Fatalf("health = %q, want degraded (box unreachable, collector history all-green)", h)
	}
	joined := strings.Join(reasons, " | ")
	if !strings.Contains(joined, "OPNsense API unreachable") {
		t.Fatalf("reasons = %v, want one naming the box as unreachable", reasons)
	}
	if len(reasons) == 0 || !strings.Contains(reasons[0], "unreachable") {
		t.Fatalf("upstream reason must lead: %v", reasons)
	}
}

// A reachable box whose health endpoint errors must still degrade the verdict,
// but must NOT be described as transport-unreachable.
func TestDeriveHealth_ReachableHealthErrorDegradesWithoutClaimingUnreachable(t *testing.T) {
	stats := []collector.CollectorStat{
		{Name: "gateways", Display: "Gateways", Runs: 9, LastOK: true},
	}
	up := &collector.HealthSnapshot{
		Polled: true, CheckOK: false, Unreachable: false,
		CheckedAt: time.Now(), LastError: "unexpected status 500",
	}

	h, reasons := deriveHealth(stats, up)

	if h != "degraded" {
		t.Fatalf("health = %q, want degraded (health endpoint failing)", h)
	}
	joined := strings.Join(reasons, " | ")
	if strings.Contains(joined, "unreachable") {
		t.Fatalf("reasons must not claim transport-unreachable for a reachable box: %v", reasons)
	}
	if !strings.Contains(joined, "health check failed") {
		t.Fatalf("reasons = %v, want one naming the failed health check", reasons)
	}
}

// Before the first health poll the console stays "starting" even when every
// collector has already run cleanly.
func TestDeriveHealth_UnpolledUpstreamIsStarting(t *testing.T) {
	stats := []collector.CollectorStat{
		{Name: "gateways", Display: "Gateways", Runs: 3, LastOK: true},
	}
	h, _ := deriveHealth(stats, &collector.HealthSnapshot{})
	if h != "starting" {
		t.Fatalf("health = %q, want starting before the first health poll", h)
	}
}

// A successful health poll after a failure clears the upstream reason.
func TestDeriveHealth_RecoveryClearsUpstreamReason(t *testing.T) {
	stats := []collector.CollectorStat{
		{Name: "gateways", Display: "Gateways", Runs: 3, LastOK: true},
	}
	up := &collector.HealthSnapshot{Polled: true, CheckOK: true, CheckedAt: time.Now()}
	h, reasons := deriveHealth(stats, up)
	if h != "healthy" {
		t.Fatalf("health = %q, want healthy after recovery", h)
	}
	if len(reasons) != 0 {
		t.Fatalf("reasons = %v, want none after recovery", reasons)
	}
}

// The Deps.Health seam must reach the rendered snapshot: an unreachable box has
// to flip the top-level badge and populate the Upstream block that /api/status.json
// and the page both read.
func TestSnapshot_UnreachableUpstreamDegradesBadge(t *testing.T) {
	d := testDeps()
	d.Tracker = trackerWithSuccess(t, "gateways", "Gateways")
	d.Health = func() collector.HealthSnapshot {
		return collector.HealthSnapshot{
			Polled: true, CheckOK: false, Unreachable: true,
			CheckedAt: time.Now().Add(-3 * time.Second), LastError: "connection refused",
		}
	}
	st := NewServer(d).snapshot()

	if st.Health != "degraded" {
		t.Fatalf("Status.Health = %q, want degraded", st.Health)
	}
	if !st.Upstream.Known {
		t.Fatalf("Upstream.Known = false; the health seam was wired")
	}
	if st.Upstream.State != "unreachable" {
		t.Fatalf("Upstream.State = %q, want unreachable", st.Upstream.State)
	}
	if st.Upstream.CheckedAgo == "" || st.Upstream.CheckedAgo == "never" {
		t.Fatalf("Upstream.CheckedAgo = %q, want a rendered age", st.Upstream.CheckedAgo)
	}
	if !strings.Contains(st.Upstream.Reason, "unreachable") {
		t.Fatalf("Upstream.Reason = %q, want it to name the box unreachable", st.Upstream.Reason)
	}
}

// A reachable-but-erroring box gets its own state, distinct from unreachable.
func TestSnapshot_ReachableUpstreamErrorState(t *testing.T) {
	d := testDeps()
	d.Tracker = trackerWithSuccess(t, "gateways", "Gateways")
	d.Health = func() collector.HealthSnapshot {
		return collector.HealthSnapshot{
			Polled: true, CheckOK: false, Unreachable: false,
			CheckedAt: time.Now(), LastError: "status 500",
		}
	}
	st := NewServer(d).snapshot()
	if st.Upstream.State != "error" {
		t.Fatalf("Upstream.State = %q, want error", st.Upstream.State)
	}
	if strings.Contains(st.Upstream.Reason, "unreachable") {
		t.Fatalf("Upstream.Reason must not claim unreachable: %q", st.Upstream.Reason)
	}
}

// A nil Health dep must not panic and must not assert anything about the box.
func TestSnapshot_NilHealthDepIsUnknownNotPanic(t *testing.T) {
	d := testDeps()
	d.Health = nil
	st := NewServer(d).snapshot()
	if st.Upstream.Known {
		t.Fatalf("Upstream.Known = true with no health seam wired")
	}
	if st.Upstream.State != "unknown" {
		t.Fatalf("Upstream.State = %q, want unknown", st.Upstream.State)
	}
}

// The upstream verdict must reach the PAGE, not only /api/status.json — with an
// element id the poll-and-patch refresh can target, or the badge freezes at its
// first-paint value.
func TestRenderPage_ShowsUpstreamState(t *testing.T) {
	d := testDeps()
	d.Tracker = trackerWithSuccess(t, "gateways", "Gateways")
	d.Health = func() collector.HealthSnapshot {
		return collector.HealthSnapshot{
			Polled: true, CheckOK: false, Unreachable: true,
			CheckedAt: time.Now(), LastError: "connection refused",
		}
	}
	var sb strings.Builder
	if err := renderPage(&sb, NewServer(d).pageView()); err != nil {
		t.Fatalf("renderPage: %v", err)
	}
	out := sb.String()
	for _, want := range []string{"upstreamBadge", "unreachable", "OPNsense API"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}
}

// A nil snapshot (no health seam wired) must degrade to the collector-only
// verdict rather than panicking or inventing a "starting" state.
func TestDeriveHealth_NilUpstreamFallsBackToCollectorHistory(t *testing.T) {
	stats := []collector.CollectorStat{
		{Name: "gateways", Display: "Gateways", Runs: 3, LastOK: true},
	}
	h, reasons := deriveHealth(stats, nil)
	if h != "healthy" || len(reasons) != 0 {
		t.Fatalf("nil upstream: got %q/%v, want healthy with no reasons", h, reasons)
	}
}
