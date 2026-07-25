package collector

import (
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// testMetric builds a trivial const metric for store tests.
func testMetric(name string, v float64) prometheus.Metric {
	desc := prometheus.NewDesc(name, "test", nil, nil)
	return prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, v)
}

func TestSnapshotStore_PutOKReplacesMetrics(t *testing.T) {
	s := newSnapshotStore()
	s.put("gw", []prometheus.Metric{testMetric("a", 1)}, 10*time.Millisecond, true)
	s.put("gw", []prometheus.Metric{testMetric("b", 2), testMetric("c", 3)}, 20*time.Millisecond, true)

	got := s.view(nil)["gw"]
	if len(got.metrics) != 2 {
		t.Fatalf("ok put should replace buffer wholesale, got %d metrics want 2", len(got.metrics))
	}
	if !got.lastOK || !got.polled {
		t.Fatalf("expected lastOK && polled after successful put, got lastOK=%v polled=%v", got.lastOK, got.polled)
	}
}

func TestSnapshotStore_PutOKEmptyDropsSeries(t *testing.T) {
	s := newSnapshotStore()
	s.put("svc", []prometheus.Metric{testMetric("a", 1)}, time.Millisecond, true)
	// A clean poll that returns no data (D8 clean-absence) must drop the series.
	s.put("svc", nil, time.Millisecond, true)

	got := s.view(nil)["svc"]
	if len(got.metrics) != 0 {
		t.Fatalf("clean empty poll must drop series, got %d metrics", len(got.metrics))
	}
	if !got.lastOK {
		t.Fatalf("empty-but-ok poll should still be lastOK=true")
	}
}

func TestSnapshotStore_PutErrorRetainsLastGood(t *testing.T) {
	s := newSnapshotStore()
	s.put("ipsec", []prometheus.Metric{testMetric("a", 1), testMetric("b", 2)}, time.Millisecond, true)
	// D8 error retention: a failed poll keeps the last-good metrics, only meta flips.
	s.put("ipsec", nil, 5*time.Millisecond, false)

	got := s.view(nil)["ipsec"]
	if len(got.metrics) != 2 {
		t.Fatalf("error poll must retain last-good metrics, got %d want 2", len(got.metrics))
	}
	if got.lastOK {
		t.Fatalf("error poll must flip lastOK to false")
	}
	if !got.polled {
		t.Fatalf("polled should remain true after an error poll")
	}
}

func TestSnapshotStore_PutErrorWithMetricsReplacesPartial(t *testing.T) {
	s := newSnapshotStore()
	s.put("ifaces", []prometheus.Metric{testMetric("a", 1)}, time.Millisecond, true)
	// A partial-success poll (emitted real data then errored on a secondary endpoint)
	// must export what it fetched, not the older last-good.
	s.put("ifaces", []prometheus.Metric{testMetric("b", 2), testMetric("c", 3)}, time.Millisecond, false)

	got := s.view(nil)["ifaces"]
	if len(got.metrics) != 2 {
		t.Fatalf("partial-on-error poll must replace with the emitted metrics, got %d want 2", len(got.metrics))
	}
	if got.lastOK {
		t.Fatalf("partial-on-error poll must still flip lastOK to false")
	}
}

func TestSnapshotStore_ViewIncludeFilter(t *testing.T) {
	s := newSnapshotStore()
	s.put("a", []prometheus.Metric{testMetric("x", 1)}, time.Millisecond, true)
	s.put("b", []prometheus.Metric{testMetric("y", 1)}, time.Millisecond, true)

	got := s.view(map[string]bool{"a": true})
	if _, ok := got["a"]; !ok {
		t.Fatalf("include filter should keep a")
	}
	if _, ok := got["b"]; ok {
		t.Fatalf("include filter should drop b")
	}
	if len(s.view(nil)) != 2 {
		t.Fatalf("nil include should return all")
	}
}

func TestSnapshotStore_ConcurrentReadWrite(t *testing.T) {
	s := newSnapshotStore()
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(2)
		go func() { defer wg.Done(); s.put("c", []prometheus.Metric{testMetric("z", 1)}, time.Millisecond, true) }()
		go func() { defer wg.Done(); _ = s.view(nil) }()
	}
	wg.Wait() // -race must stay clean
}

// TestPutClocksDistinguishAttemptContentAndSuccess pins the #382 three-clock
// contract exactly. Each row is one poll outcome; the assertions are about which
// clocks moved, which is the whole point — a single timestamp cannot express
// "the buffer is new but the poll was not clean".
func TestPutClocksDistinguishAttemptContentAndSuccess(t *testing.T) {
	s := newSnapshotStore()
	m := []prometheus.Metric{testMetric("opnsense_x", 1)}

	// 1. Clean success: all three clocks advance.
	s.put("c", m, time.Millisecond, true)
	first := s.entry("c")
	if first.lastPoll.IsZero() || first.snapshotAt.IsZero() || first.lastSuccess.IsZero() {
		t.Fatalf("a clean success must set all three clocks, got %+v", first)
	}

	time.Sleep(2 * time.Millisecond)

	// 2. Partial error (error + non-empty emit): the buffer IS replaced with real
	//    new data, so attempt and content advance — but the poll was not clean, so
	//    the success clock must not move.
	s.put("c", []prometheus.Metric{testMetric("opnsense_x", 2)}, time.Millisecond, false)
	partial := s.entry("c")
	if !partial.lastPoll.After(first.lastPoll) {
		t.Error("partial-error poll must advance the attempt clock")
	}
	if !partial.snapshotAt.After(first.snapshotAt) {
		t.Error("partial-error poll replaces the buffer, so the content clock must advance")
	}
	if !partial.lastSuccess.Equal(first.lastSuccess) {
		t.Error("partial-error poll must NOT advance the last-success clock")
	}

	time.Sleep(2 * time.Millisecond)

	// 3. Empty error: last-good buffer retained, so BOTH content and success clocks
	//    must stay pinned while the attempt clock moves. This is the exact case that
	//    let six hours of stale data read as one minute old.
	s.put("c", nil, time.Millisecond, false)
	empty := s.entry("c")
	if !empty.lastPoll.After(partial.lastPoll) {
		t.Error("failed poll must still advance the attempt clock")
	}
	if !empty.snapshotAt.Equal(partial.snapshotAt) {
		t.Error("empty-error poll retains the buffer, so the content clock must NOT advance")
	}
	if !empty.lastSuccess.Equal(first.lastSuccess) {
		t.Error("empty-error poll must NOT advance the last-success clock")
	}
	if len(empty.metrics) != 1 {
		t.Errorf("empty-error poll must retain the last-good buffer, got %d metrics", len(empty.metrics))
	}

	// 4. Clean EMPTY success is genuine absence, not failure: the buffer is replaced
	//    with nothing and both content and success clocks advance.
	time.Sleep(2 * time.Millisecond)
	s.put("c", nil, time.Millisecond, true)
	clean := s.entry("c")
	if len(clean.metrics) != 0 {
		t.Error("clean empty success must drop the buffer (data is genuinely gone)")
	}
	if !clean.snapshotAt.After(empty.snapshotAt) || !clean.lastSuccess.After(empty.lastSuccess) {
		t.Error("clean empty success must advance both the content and success clocks")
	}
}

// TestRetainedDataAgeGrowsWhileAttemptStaysRecent reproduces the scenario in #382:
// a collector succeeds once, then fails emptily on every subsequent poll. Its
// retained values get steadily older, but every failed retry used to refresh the
// only exported timestamp — so the dashboard's "freshness" panel and the console
// both reported sub-minute age for data that was hours old.
func TestRetainedDataAgeGrowsWhileAttemptStaysRecent(t *testing.T) {
	s := newSnapshotStore()
	s.put("c", []prometheus.Metric{testMetric("opnsense_x", 1)}, time.Millisecond, true)
	good := s.entry("c")

	for range 6 {
		time.Sleep(time.Millisecond)
		s.put("c", nil, time.Millisecond, false)
	}
	after := s.entry("c")

	if !after.lastPoll.After(good.lastPoll) {
		t.Error("the attempt clock must stay recent — the scheduler IS still running")
	}
	if !after.snapshotAt.Equal(good.snapshotAt) {
		t.Errorf("the content clock must stay pinned to the last good data: %v != %v", after.snapshotAt, good.snapshotAt)
	}
	if !after.lastSuccess.Equal(good.lastSuccess) {
		t.Error("the success clock must stay pinned to the last clean poll")
	}
	if len(after.metrics) != 1 {
		t.Error("retention itself must be unchanged — this issue changes observability, not retention")
	}
}
