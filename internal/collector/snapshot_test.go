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
