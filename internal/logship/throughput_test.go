package logship

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// The operator console reads the log-shipping rate by differencing these
// process-lifetime totals, so they must move in lockstep with logs_shipped_total
// / logs_dropped_total: a confirmed export counts shipped, an abandoned batch
// counts dropped, and a failed-but-retried attempt counts neither.
//
// The counters are package-level and process-lifetime, so every assertion here is
// on a DELTA — another test in this package may have shipped records already.
func TestThroughput_TracksConfirmedShipsAndAbandonedBatches(t *testing.T) {
	shipped0, dropped0 := Throughput()

	p, cancel := newDeliveryPipeline(&flakySink{failN: 1}, prometheus.NewRegistry())
	p.shipBatch([]Entry{
		{Source: "firewall", Record: Record{Body: "a"}},
		{Source: "firewall", Record: Record{Body: "b"}},
	})
	cancel()

	shipped1, dropped1 := Throughput()
	if shipped1-shipped0 != 2 {
		t.Fatalf("shipped delta = %d, want 2 (both records confirmed after one retry)", shipped1-shipped0)
	}
	if dropped1-dropped0 != 0 {
		t.Fatalf("dropped delta = %d, want 0 (the retry succeeded; nothing was lost)", dropped1-dropped0)
	}

	// A batch abandoned during shutdown IS lost, and must be counted as such —
	// never as shipped.
	p2, cancel2 := newDeliveryPipeline(&flakySink{always: true}, prometheus.NewRegistry())
	cancel2() // shutdown already in progress
	p2.shipBatch([]Entry{{Source: "firewall", Record: Record{Body: "c"}}})

	shipped2, dropped2 := Throughput()
	if shipped2 != shipped1 {
		t.Fatalf("shipped moved on an undelivered batch: %d -> %d", shipped1, shipped2)
	}
	if dropped2-dropped1 != 1 {
		t.Fatalf("dropped delta = %d, want 1 (the abandoned record)", dropped2-dropped1)
	}
}

// Queue overflow is the common real-world loss mode, so it must reach the console
// counter too — a "dropped" rate that only ever saw shutdown losses would
// under-report loss exactly when the pipeline is drowning.
func TestThroughput_QueueOverflowCountsAsDropped(t *testing.T) {
	shipped0, dropped0 := Throughput()

	p, cancel := newDeliveryPipeline(&fakeSink{}, prometheus.NewRegistry())
	defer cancel()
	p.queue = newBoundedQueue(1, p.noteOverflow)
	p.queue.push(Entry{Source: "firewall", Record: Record{Body: "a"}})
	p.queue.push(Entry{Source: "firewall", Record: Record{Body: "b"}}) // evicts "a"

	shipped1, dropped1 := Throughput()
	if dropped1-dropped0 != 1 {
		t.Fatalf("dropped delta = %d, want 1 (one evicted record)", dropped1-dropped0)
	}
	if shipped1 != shipped0 {
		t.Fatalf("shipped moved on an evicted record: %d -> %d", shipped0, shipped1)
	}
}
