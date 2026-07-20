package collector

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rknightion/opnsense-exporter/opnsense"
)

// intervalFake is a fakeCollectorInstance that also declares a poll tier.
type intervalFake struct {
	fakeCollectorInstance
	d time.Duration
}

func (f *intervalFake) PollInterval() time.Duration { return f.d }

func TestPollOnceCapturesRecordsAndPropagatesCtx(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	tracker := NewStatusTracker()
	fake := &fakeCollectorInstance{name: "fake", emit: []prometheus.Metric{testMetric("opnsense_x", 7)}}
	c := newScrapeTestCollector(t, client, fake)
	c.statusTracker = tracker

	ctx := context.WithValue(context.Background(), scrapeCtxKey{}, "marker")
	c.pollOnce(ctx, fake)

	e := c.store.entry("fake")
	if len(e.metrics) != 1 || !e.lastOK || !e.polled {
		t.Fatalf("poll should capture 1 metric, lastOK, polled; got metrics=%d ok=%v polled=%v", len(e.metrics), e.lastOK, e.polled)
	}
	stats := tracker.Snapshot()
	if len(stats) != 1 || stats[0].Runs != 1 || !stats[0].LastOK {
		t.Fatalf("poll should record one successful run, got %+v", stats)
	}
	if got := fake.contextValue(scrapeCtxKey{}); got != "marker" {
		t.Errorf("request context must reach Update, got %v", got)
	}
}

func TestPollOnceErrorRetainsAndRecordsFailure(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	fake := &fakeCollectorInstance{name: "fake", emit: []prometheus.Metric{testMetric("opnsense_x", 1)}}
	c := newScrapeTestCollector(t, client, fake)

	c.pollOnce(context.Background(), fake) // seed last-good
	fake.emit = nil
	fake.err = &opnsense.APICallError{Endpoint: "ep", Message: "boom"}
	c.pollOnce(context.Background(), fake)

	e := c.store.entry("fake")
	if len(e.metrics) != 1 {
		t.Errorf("error poll must retain last-good metrics, got %d", len(e.metrics))
	}
	if e.lastOK {
		t.Error("error poll must set lastOK=false")
	}
	if got := counterValue(t, c.endpointErrors.WithLabelValues("ep", "test")); got != 1 {
		t.Errorf("endpoint error should be counted, got %v", got)
	}
}

func TestPollOncePanicRecordsSentinel(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	fake := &fakeCollectorInstance{name: "fake", panics: true}
	c := newScrapeTestCollector(t, client, fake)

	c.pollOnce(context.Background(), fake) // must recover, not crash the test
	if got := counterValue(t, c.endpointErrors.WithLabelValues("panic:fake", "test")); got != 1 {
		t.Errorf("panic must increment the panic:-sentinel endpoint, got %v", got)
	}
	if c.store.entry("fake").lastOK {
		t.Error("panic poll must set lastOK=false")
	}
}

func TestPollCollectorSkipsWhenUnreachable(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	fake := &fakeCollectorInstance{name: "fake"}
	c := newScrapeTestCollector(t, client, fake)
	c.pollSem = make(chan struct{}, 1)
	c.unreachable.Store(true)

	c.pollCollector(context.Background(), fake)
	if fake.callCount() != 0 {
		t.Errorf("poll must skip Update while the box is unreachable, got %d calls", fake.callCount())
	}
}

func TestStartPollingColdStartPolls(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	fake := &fakeCollectorInstance{name: "fake", emit: []prometheus.Metric{testMetric("opnsense_x", 1)}}
	c := newScrapeTestCollector(t, client, fake)

	c.StartPolling(context.Background())
	defer c.StopPolling()

	deadline := time.Now().Add(3 * time.Second) // cold-start jitter is capped at 5s but usually far less
	for time.Now().Before(deadline) {
		if c.store.entry("fake").polled {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !c.store.entry("fake").polled {
		t.Fatal("cold start should poll the collector shortly after StartPolling")
	}
}

func TestResolvePollIntervalClamp(t *testing.T) {
	fast := &intervalFake{fakeCollectorInstance: fakeCollectorInstance{name: "f"}, d: IntervalFast}
	if got := resolvePollInterval(fast, IntervalMedium); got != IntervalFast {
		t.Errorf("declared interval should win, got %v", got)
	}
	tooLow := &intervalFake{fakeCollectorInstance: fakeCollectorInstance{name: "l"}, d: time.Second}
	if got := resolvePollInterval(tooLow, IntervalMedium); got != IntervalFloor {
		t.Errorf("interval below floor should clamp to floor, got %v", got)
	}
	tooHigh := &intervalFake{fakeCollectorInstance: fakeCollectorInstance{name: "h"}, d: time.Hour}
	if got := resolvePollInterval(tooHigh, IntervalMedium); got != IntervalCeil {
		t.Errorf("interval above ceil should clamp to ceil, got %v", got)
	}
	plain := &fakeCollectorInstance{name: "p"}
	if got := resolvePollInterval(plain, IntervalSlow); got != IntervalSlow {
		t.Errorf("no declaration should use the clamped global default, got %v", got)
	}
}
