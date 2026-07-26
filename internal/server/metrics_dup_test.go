package server

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// dupCollector emits two metrics with an identical descriptor and label values,
// which makes a checked registry's Gather() error — the exact condition a
// duplicate config-derived label tuple produces in a real sub-collector.
type dupCollector struct{ desc *prometheus.Desc }

func (d *dupCollector) Describe(ch chan<- *prometheus.Desc) { ch <- d.desc }
func (d *dupCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(d.desc, prometheus.GaugeValue, 1, "same")
	ch <- prometheus.MustNewConstMetric(d.desc, prometheus.GaugeValue, 2, "same")
}

type dupViews struct{}

func (dupViews) EnabledCollectorNames() []string { return []string{"dup"} }
func (dupViews) ScrapeView(_ context.Context, _ map[string]bool) prometheus.Collector {
	return &dupCollector{desc: prometheus.NewDesc("opnsense_dup_metric", "dup", []string{"k"}, nil)}
}

// TestMetricsHandler_DuplicateSeriesDegradesGracefully asserts that a duplicate
// label tuple no longer blanks the whole /metrics response with a 500: the scrape
// still returns 200 with the unrelated self/process metrics intact, and the
// gather error is logged rather than silently swallowed (#81).
func TestMetricsHandler_DuplicateSeriesDegradesGracefully(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	self := prometheus.NewRegistry()
	selfGauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "fake_self_metric", Help: "fake"})
	selfGauge.Set(1)
	self.MustRegister(selfGauge)

	h := NewMetricsHandler(dupViews{}, self, logger, nil)
	rec := serve(h, "/metrics", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (duplicate tuple must not blank the scrape); body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "fake_self_metric") {
		t.Errorf("expected unrelated self metric to survive the duplicate collision; body: %s", rec.Body.String())
	}
	if !strings.Contains(buf.String(), "error gathering metrics for scrape") {
		t.Errorf("expected the gather error to be logged, got: %s", buf.String())
	}
}
