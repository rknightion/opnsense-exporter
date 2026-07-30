package collector

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

// floodCollector emits a fixed number of metrics from one Update, standing in
// for a real high-volume collector without needing its fixture.
type floodCollector struct {
	count int
	desc  *prometheus.Desc
}

func (f *floodCollector) Name() string { return "flood" }

func (f *floodCollector) Register(namespace, instance string, _ *slog.Logger) {
	f.desc = prometheus.NewDesc(
		namespace+"_flood_value",
		"Test-only series used to pin the collectMetrics helper's behaviour.",
		[]string{"n"}, prometheus.Labels{"opnsense_instance": instance},
	)
}

func (f *floodCollector) Describe(ch chan<- *prometheus.Desc) { ch <- f.desc }

func (f *floodCollector) Update(_ context.Context, _ *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	for i := 0; i < f.count; i++ {
		ch <- prometheus.MustNewConstMetric(f.desc, prometheus.GaugeValue, float64(i), string(rune('a'+i%26))+itoa(i))
	}
	return nil
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// TestCollectMetricsHandlesMoreThan500Metrics pins the #547 fix. Before it, the
// shared helper handed Update a 500-slot buffered channel and read nothing until
// Update returned, so a collector emitting more than that blocked forever on the
// write. The failure presented as a 120s package timeout with no indication of
// the cause, which is why this test enforces its own deadline: a regression here
// must fail with this message rather than hang the whole package.
//
// 776 is the real figure — the netisr prod capture emits exactly that — so the
// number is a captured fact rather than a round one picked to be safely large.
func TestCollectMetricsHandlesMoreThan500Metrics(t *testing.T) {
	const emitted = 776

	f := &floodCollector{count: emitted}
	f.Register("opnsense", "test", nil)

	done := make(chan []prometheus.Metric, 1)
	go func() { done <- collectMetrics(t, f, nil) }()

	select {
	case got := <-done:
		if len(got) != emitted {
			t.Fatalf("collectMetrics returned %d metrics, want %d", len(got), emitted)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("collectMetrics deadlocked above its channel buffer (#547): it must " +
			"drain concurrently with Update, not rely on the buffer being large enough")
	}
}
