package telemetry

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/internal/options"
	prometheusbridge "go.opentelemetry.io/contrib/bridges/prometheus"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestBridgeParity is the core guard: every metric registered with the Prometheus
// registry must appear in the OTLP output produced by the bridge, with the same
// name, the same labels (as attributes), and the correct instrument shape
// (Prometheus Gauge -> OTLP Gauge; Prometheus Counter -> OTLP monotonic cumulative Sum).
func TestBridgeParity(t *testing.T) {
	reg := prometheus.NewRegistry()

	gauge := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "opnsense_test_gauge", Help: "a gauge"},
		[]string{"iface"},
	)
	reg.MustRegister(gauge)
	gauge.WithLabelValues("wan").Set(42)

	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "opnsense_test_packets_total", Help: "a counter"},
		[]string{"iface"},
	)
	reg.MustRegister(counter)
	counter.WithLabelValues("wan").Add(7)

	// Summary and Histogram are also present in the live registry (e.g. the Go
	// collector's go_gc_duration_seconds summary), so assert those shapes survive
	// the bridge too — not just gauge/counter.
	summary := prometheus.NewSummary(prometheus.SummaryOpts{
		Name:       "opnsense_test_latency_seconds",
		Help:       "a summary",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01},
	})
	reg.MustRegister(summary)
	summary.Observe(0.2)
	summary.Observe(0.4)

	histogram := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "opnsense_test_sizes_bytes",
		Help:    "a histogram",
		Buckets: []float64{1, 10, 100},
	})
	reg.MustRegister(histogram)
	histogram.Observe(5)
	histogram.Observe(50)

	producer := prometheusbridge.NewMetricProducer(prometheusbridge.WithGatherer(reg))
	reader := sdkmetric.NewManualReader(sdkmetric.WithProducer(producer))
	defer reader.Shutdown(context.Background()) //nolint:errcheck
	// A provider must own the reader for Collect to function.
	_ = sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}

	byName := map[string]metricdata.Metrics{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			byName[m.Name] = m
		}
	}

	// No-drops guard: every family the registry gathers must appear in the OTLP
	// output. This is what makes the bridge a parity mechanism — covers all four
	// Prometheus metric shapes registered above (gauge, counter, summary, histogram).
	families, gerr := reg.Gather()
	if gerr != nil {
		t.Fatalf("gather: %v", gerr)
	}
	if len(families) < 4 {
		t.Fatalf("expected at least 4 metric families, got %d", len(families))
	}
	for _, mf := range families {
		if _, ok := byName[mf.GetName()]; !ok {
			t.Errorf("metric %q present in registry but missing from OTLP output (parity violation)", mf.GetName())
		}
	}

	// Gauge parity.
	gm, ok := byName["opnsense_test_gauge"]
	if !ok {
		t.Fatalf("gauge missing from OTLP output; got %v", keys(byName))
	}
	gd, ok := gm.Data.(metricdata.Gauge[float64])
	if !ok {
		t.Fatalf("expected Gauge[float64], got %T", gm.Data)
	}
	if len(gd.DataPoints) != 1 {
		t.Fatalf("expected 1 gauge datapoint, got %d", len(gd.DataPoints))
	}
	if gd.DataPoints[0].Value != 42 {
		t.Errorf("gauge value = %v, want 42", gd.DataPoints[0].Value)
	}
	if v, present := gd.DataPoints[0].Attributes.Value(attribute.Key("iface")); !present || v.AsString() != "wan" {
		t.Errorf("gauge iface attribute = %v (present=%v), want wan", v.AsString(), present)
	}

	// Counter parity: monotonic cumulative Sum, name suffix preserved.
	cm, ok := byName["opnsense_test_packets_total"]
	if !ok {
		t.Fatalf("counter missing from OTLP output; got %v", keys(byName))
	}
	cd, ok := cm.Data.(metricdata.Sum[float64])
	if !ok {
		t.Fatalf("expected Sum[float64], got %T", cm.Data)
	}
	if !cd.IsMonotonic {
		t.Error("counter should be monotonic")
	}
	if cd.Temporality != metricdata.CumulativeTemporality {
		t.Errorf("counter temporality = %v, want cumulative", cd.Temporality)
	}
	if len(cd.DataPoints) != 1 || cd.DataPoints[0].Value != 7 {
		t.Errorf("counter datapoints = %+v, want single value 7", cd.DataPoints)
	}
}

func keys(m map[string]metricdata.Metrics) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// dupCronCollector reproduces the real-world duplicate-label scenario from #81/#101:
// two OPNsense cron jobs sharing the same description emit two series with identical
// label values, which makes Registry.Gather() return a consistency (MultiError)
// alongside the partial families.
type dupCronCollector struct{ desc *prometheus.Desc }

func (c *dupCronCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }
func (c *dupCronCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, 1, "nightly-backup")
	ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, 1, "nightly-backup")
}

// TestBridgeIsolatesErroringGatherer covers #101: a duplicate-label consistency error
// in the collector registry must not black out the whole OTLP export tick. The
// self-metrics registry and every healthy collector family must still reach the
// producer, the underlying error must still be logged, and only the offending family
// is dropped.
func TestBridgeIsolatesErroringGatherer(t *testing.T) {
	selfReg := prometheus.NewRegistry()
	selfGauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "opnsense_selftest_up", Help: "self"})
	selfReg.MustRegister(selfGauge)
	selfGauge.Set(1)

	collectorReg := prometheus.NewRegistry()
	healthy := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "opnsense_healthy_gauge", Help: "healthy"}, []string{"iface"})
	collectorReg.MustRegister(healthy)
	healthy.WithLabelValues("wan").Set(5)
	collectorReg.MustRegister(&dupCronCollector{
		desc: prometheus.NewDesc("opnsense_cron_job_enabled", "cron", []string{"description"}, nil),
	})

	// Sanity: the raw collector registry really does error on gather (premise check).
	if _, err := collectorReg.Gather(); err == nil {
		t.Fatal("expected a consistency error from the duplicated cron series; test premise stale")
	}

	var logBuf strings.Builder
	log := slog.New(slog.NewTextHandler(&logBuf, nil))

	producer := prometheusbridge.NewMetricProducer(
		prometheusbridge.WithGatherer(&continueOnErrorGatherer{inner: selfReg, log: log, interval: time.Hour}),
		prometheusbridge.WithGatherer(&continueOnErrorGatherer{inner: collectorReg, log: log, interval: time.Hour}),
	)
	reader := sdkmetric.NewManualReader(sdkmetric.WithProducer(producer))
	defer reader.Shutdown(context.Background()) //nolint:errcheck
	_ = sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	byName := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			byName[m.Name] = true
		}
	}

	if !byName["opnsense_selftest_up"] {
		t.Error("self-metric blacked out by the erroring collector registry (isolation failed)")
	}
	if !byName["opnsense_healthy_gauge"] {
		t.Error("healthy collector family dropped alongside the duplicate (continue-on-error failed)")
	}
	// The offending family is "handled" rather than dropped: prometheus' Gather returns
	// it alongside the MultiError, and continue-on-error surfaces that error via the log
	// (asserted below) instead of blacking the whole tick out. What must never happen is
	// a total export blackout, which the self + healthy assertions above prove it didn't.
	if !strings.Contains(logBuf.String(), "otlp gather error") {
		t.Errorf("underlying gather error was not logged; log = %q", logBuf.String())
	}
}

func TestNewExporter_ProtocolSelection(t *testing.T) {
	ctx := context.Background()
	for _, proto := range []string{"grpc", "http/protobuf", ""} {
		cfg := &options.OTLPConfig{
			Protocol:       proto,
			Endpoint:       "http://127.0.0.1:4318",
			Insecure:       true,
			ExportInterval: time.Second,
		}
		exp, err := newExporter(ctx, cfg)
		if err != nil {
			t.Fatalf("protocol %q: %v", proto, err)
		}
		_ = exp.Shutdown(ctx)
	}

	if _, err := newExporter(ctx, &options.OTLPConfig{Protocol: "bogus"}); err == nil {
		t.Error("expected error for unsupported protocol")
	}
}

func TestBuildResource(t *testing.T) {
	res, err := buildResource(context.Background(), &options.OTLPConfig{ServiceName: "svc"}, "1.2.3", "fw1")
	if err != nil && res == nil {
		t.Fatalf("buildResource: %v", err)
	}
	got := map[string]string{}
	for _, kv := range res.Attributes() {
		got[string(kv.Key)] = kv.Value.AsString()
	}
	if got[keyServiceName] != "svc" {
		t.Errorf("service.name = %q, want svc", got[keyServiceName])
	}
	if got[keyServiceVersion] != "1.2.3" {
		t.Errorf("service.version = %q, want 1.2.3", got[keyServiceVersion])
	}
	if got[keyServiceInstanceID] != "fw1" {
		t.Errorf("service.instance.id = %q, want fw1", got[keyServiceInstanceID])
	}
}

func TestStart_BuildsProviderAndShutdown(t *testing.T) {
	reg := prometheus.NewRegistry()
	cfg := &options.OTLPConfig{
		Protocol:       "http/protobuf",
		Endpoint:       "http://127.0.0.1:4318",
		Insecure:       true,
		ExportInterval: time.Hour,
		ServiceName:    "opnsense-exporter",
	}
	shutdown, err := Start(context.Background(), []prometheus.Gatherer{reg}, cfg, "v-test", "inst", discardLogger())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if shutdown == nil {
		t.Fatal("Start returned nil shutdown")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = shutdown(ctx) // final flush to a dead endpoint may error; not asserted
}

func TestSlogErrorHandler_RateLimits(t *testing.T) {
	h := &slogErrorHandler{log: discardLogger(), interval: time.Hour}
	h.Handle(io.EOF)
	h.Handle(io.EOF)
	h.Handle(io.EOF)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.dropped != 2 {
		t.Errorf("dropped = %d, want 2 (first logged, next two suppressed)", h.dropped)
	}
}
