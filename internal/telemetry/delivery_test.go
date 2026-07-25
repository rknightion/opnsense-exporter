package telemetry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/rknightion/opnsense-exporter/internal/options"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// fakeExporter is a fully controllable sdkmetric.Exporter. It performs no network
// I/O: Export pops the next queued result, so a test can script an
// error -> error -> success sequence deterministically.
type fakeExporter struct {
	mu         sync.Mutex
	results    []error
	exports    int
	lastRM     *metricdata.ResourceMetrics
	flushes    int
	shutdowns  int
	flushErr   error
	shutdown   error
	temporalit metricdata.Temporality
}

func (f *fakeExporter) Temporality(sdkmetric.InstrumentKind) metricdata.Temporality {
	if f.temporalit == 0 {
		return metricdata.CumulativeTemporality
	}
	return f.temporalit
}

func (f *fakeExporter) Aggregation(sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.AggregationDefault{}
}

func (f *fakeExporter) Export(_ context.Context, rm *metricdata.ResourceMetrics) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.exports++
	f.lastRM = rm
	if len(f.results) == 0 {
		return nil
	}
	err := f.results[0]
	f.results = f.results[1:]
	return err
}

func (f *fakeExporter) ForceFlush(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushes++
	return f.flushErr
}

func (f *fakeExporter) Shutdown(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shutdowns++
	return f.shutdown
}

func (f *fakeExporter) exportCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.exports
}

// --- assertion helpers (prometheus/testutil is not vendored in this repo) ---

func gatherFamily(t *testing.T, reg *prometheus.Registry, name string) *dto.MetricFamily {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf
		}
	}
	return nil
}

func counterValue(t *testing.T, reg *prometheus.Registry, name, result string) float64 {
	t.Helper()
	mf := gatherFamily(t, reg, name)
	if mf == nil {
		t.Fatalf("metric family %q not registered", name)
	}
	if mf.GetType() != dto.MetricType_COUNTER {
		t.Fatalf("metric %q type = %v, want COUNTER", name, mf.GetType())
	}
	for _, m := range mf.GetMetric() {
		for _, lp := range m.GetLabel() {
			if lp.GetName() == "result" && lp.GetValue() == result {
				return m.GetCounter().GetValue()
			}
		}
	}
	t.Fatalf("metric %q has no series with result=%q", name, result)
	return 0
}

func gaugeValue(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	mf := gatherFamily(t, reg, name)
	if mf == nil {
		t.Fatalf("metric family %q not registered", name)
	}
	if mf.GetType() != dto.MetricType_GAUGE {
		t.Fatalf("metric %q type = %v, want GAUGE", name, mf.GetType())
	}
	if len(mf.GetMetric()) != 1 {
		t.Fatalf("metric %q has %d series, want exactly 1 (must be unlabelled)", name, len(mf.GetMetric()))
	}
	if len(mf.GetMetric()[0].GetLabel()) != 0 {
		t.Fatalf("metric %q must carry no labels, got %v", name, mf.GetMetric()[0].GetLabel())
	}
	return mf.GetMetric()[0].GetGauge().GetValue()
}

const (
	mExports     = "opnsense_exporter_otlp_exports_total"
	mLastSuccess = "opnsense_exporter_otlp_last_success_timestamp_seconds"
	mConsecutive = "opnsense_exporter_otlp_consecutive_failures"
	mEnabled     = "opnsense_exporter_otlp_enabled"
)

// TestObservingExporter_ErrorErrorSuccess is the core acceptance case from #388:
// a failing endpoint that recovers must be fully reconstructible from the
// self-metrics alone.
func TestObservingExporter_ErrorErrorSuccess(t *testing.T) {
	reg := prometheus.NewRegistry()
	boom := errors.New("connection refused")
	fake := &fakeExporter{results: []error{boom, boom, nil}}
	obs := observeExports(fake, newDeliveryMetrics(reg))

	ctx := context.Background()
	rm := &metricdata.ResourceMetrics{}

	// Before any export: no success has ever happened, so the timestamp must be 0
	// (not "now"), and there are no failures yet.
	if got := gaugeValue(t, reg, mLastSuccess); got != 0 {
		t.Errorf("last_success before any export = %v, want 0", got)
	}
	if got := gaugeValue(t, reg, mConsecutive); got != 0 {
		t.Errorf("consecutive_failures before any export = %v, want 0", got)
	}

	// First failure.
	if err := obs.Export(ctx, rm); !errors.Is(err, boom) {
		t.Fatalf("export 1 err = %v, want %v", err, boom)
	}
	if got := gaugeValue(t, reg, mConsecutive); got != 1 {
		t.Errorf("consecutive_failures after 1 error = %v, want 1", got)
	}
	if got := gaugeValue(t, reg, mLastSuccess); got != 0 {
		t.Errorf("last_success after only errors = %v, want 0", got)
	}

	// Second failure.
	if err := obs.Export(ctx, rm); !errors.Is(err, boom) {
		t.Fatalf("export 2 err = %v, want %v", err, boom)
	}
	if got := gaugeValue(t, reg, mConsecutive); got != 2 {
		t.Errorf("consecutive_failures after 2 errors = %v, want 2", got)
	}

	// Recovery.
	before := float64(time.Now().Unix())
	if err := obs.Export(ctx, rm); err != nil {
		t.Fatalf("export 3 err = %v, want nil", err)
	}
	if got := counterValue(t, reg, mExports, resultError); got != 2 {
		t.Errorf("exports_total{result=error} = %v, want 2", got)
	}
	if got := counterValue(t, reg, mExports, resultSuccess); got != 1 {
		t.Errorf("exports_total{result=success} = %v, want 1", got)
	}
	if got := gaugeValue(t, reg, mConsecutive); got != 0 {
		t.Errorf("consecutive_failures after recovery = %v, want 0", got)
	}
	if got := gaugeValue(t, reg, mLastSuccess); got < before-2 {
		t.Errorf("last_success after recovery = %v, want >= %v", got, before-2)
	}
}

// TestObservingExporter_CountsOncePerExportCall pins the accounting granularity:
// one increment per Export call, regardless of how many metrics or scopes the
// batch carries.
func TestObservingExporter_CountsOncePerExportCall(t *testing.T) {
	reg := prometheus.NewRegistry()
	fake := &fakeExporter{}
	obs := observeExports(fake, newDeliveryMetrics(reg))

	rm := &metricdata.ResourceMetrics{
		ScopeMetrics: []metricdata.ScopeMetrics{
			{Metrics: []metricdata.Metrics{{Name: "a"}, {Name: "b"}, {Name: "c"}}},
			{Metrics: []metricdata.Metrics{{Name: "d"}, {Name: "e"}}},
		},
	}
	if err := obs.Export(context.Background(), rm); err != nil {
		t.Fatalf("export: %v", err)
	}
	if got := counterValue(t, reg, mExports, resultSuccess); got != 1 {
		t.Errorf("exports_total{result=success} = %v after one Export of 5 metrics, want 1", got)
	}
	if got := fake.exportCalls(); got != 1 {
		t.Errorf("inner Export called %d times, want 1", got)
	}
}

// TestObservingExporter_PropagatesErrorVerbatim guards the requirement that the
// decorator observes without swallowing: the SDK must still see the exact error so
// the existing rate-limited slogErrorHandler keeps logging it.
func TestObservingExporter_PropagatesErrorVerbatim(t *testing.T) {
	reg := prometheus.NewRegistry()
	sentinel := errors.New("tls: bad certificate")
	fake := &fakeExporter{results: []error{sentinel}}
	obs := observeExports(fake, newDeliveryMetrics(reg))

	err := obs.Export(context.Background(), &metricdata.ResourceMetrics{})
	if err != sentinel { //nolint:errorlint // identity is the assertion: no wrapping
		t.Fatalf("export err = %#v, want the identical sentinel %#v", err, sentinel)
	}
}

// TestObservingExporter_DelegatesNonExportMethods: the decorator must be a faithful
// sdkmetric.Exporter, and must NOT count flush/shutdown as exports.
func TestObservingExporter_DelegatesNonExportMethods(t *testing.T) {
	reg := prometheus.NewRegistry()
	flushErr := errors.New("flush failed")
	shutErr := errors.New("shutdown failed")
	fake := &fakeExporter{flushErr: flushErr, shutdown: shutErr, temporalit: metricdata.DeltaTemporality}
	obs := observeExports(fake, newDeliveryMetrics(reg))

	if got := obs.Temporality(sdkmetric.InstrumentKindCounter); got != metricdata.DeltaTemporality {
		t.Errorf("Temporality = %v, want delegated DeltaTemporality", got)
	}
	if _, ok := obs.Aggregation(sdkmetric.InstrumentKindCounter).(sdkmetric.AggregationDefault); !ok {
		t.Errorf("Aggregation = %T, want delegated AggregationDefault", obs.Aggregation(sdkmetric.InstrumentKindCounter))
	}
	if err := obs.ForceFlush(context.Background()); !errors.Is(err, flushErr) {
		t.Errorf("ForceFlush err = %v, want %v", err, flushErr)
	}
	if err := obs.Shutdown(context.Background()); !errors.Is(err, shutErr) {
		t.Errorf("Shutdown err = %v, want %v", err, shutErr)
	}

	// Neither flush nor shutdown is an export: a final flush routes through Export on
	// the reader path already, so counting them here would double-count.
	if got := counterValue(t, reg, mExports, resultSuccess); got != 0 {
		t.Errorf("exports_total{result=success} = %v after only flush/shutdown, want 0", got)
	}
	if got := counterValue(t, reg, mExports, resultError); got != 0 {
		t.Errorf("exports_total{result=error} = %v after only flush/shutdown, want 0", got)
	}
	if got := gaugeValue(t, reg, mConsecutive); got != 0 {
		t.Errorf("consecutive_failures = %v after a failing flush/shutdown, want 0", got)
	}
}

// TestObservingExporter_NilRegistererIsInert: Start may be called without a
// self-metrics registry (existing tests do). That must register nothing, record
// nothing, and never panic — while still delivering to the inner exporter.
func TestObservingExporter_NilRegistererIsInert(t *testing.T) {
	m := newDeliveryMetrics(nil)
	if m != nil {
		t.Fatalf("newDeliveryMetrics(nil) = %v, want nil", m)
	}
	m.markEnabled() // must be a safe no-op on a nil receiver

	boom := errors.New("nope")
	fake := &fakeExporter{results: []error{boom, nil}}
	obs := observeExports(fake, m)

	if err := obs.Export(context.Background(), &metricdata.ResourceMetrics{}); !errors.Is(err, boom) {
		t.Fatalf("export 1 err = %v, want %v", err, boom)
	}
	if err := obs.Export(context.Background(), &metricdata.ResourceMetrics{}); err != nil {
		t.Fatalf("export 2 err = %v, want nil", err)
	}
	if got := fake.exportCalls(); got != 2 {
		t.Errorf("inner Export called %d times, want 2", got)
	}
}

// TestNewDeliveryMetrics_SecondRegistrationReusesExisting pins the documented
// contract: registering a second time against the same registry adopts the already
// registered collectors instead of panicking or duplicating the series.
func TestNewDeliveryMetrics_SecondRegistrationReusesExisting(t *testing.T) {
	reg := prometheus.NewRegistry()
	first := newDeliveryMetrics(reg)
	second := newDeliveryMetrics(reg)
	if second == nil {
		t.Fatal("second newDeliveryMetrics returned nil")
	}

	first.recordExport(nil)
	second.recordExport(errors.New("boom"))

	// One family, one series per result value — not two registrations' worth.
	mf := gatherFamily(t, reg, mExports)
	if mf == nil {
		t.Fatal("exports_total missing")
	}
	if len(mf.GetMetric()) != 2 {
		t.Fatalf("exports_total has %d series, want exactly 2 (success + error)", len(mf.GetMetric()))
	}
	if got := counterValue(t, reg, mExports, resultSuccess); got != 1 {
		t.Errorf("exports_total{result=success} = %v, want 1 (both handles share one counter)", got)
	}
	if got := counterValue(t, reg, mExports, resultError); got != 1 {
		t.Errorf("exports_total{result=error} = %v, want 1", got)
	}
	if got := gaugeValue(t, reg, mConsecutive); got != 1 {
		t.Errorf("consecutive_failures = %v, want 1 (shared gauge)", got)
	}
}

// TestStart_BooksRealExports is the end-to-end guard that Start actually wraps the
// exporter the reader owns. Registering the series and setting otlp_enabled=1 is not
// enough: if the decorator were dropped from the pipeline, the counters would sit at
// zero forever and look exactly like a healthy idle exporter.
func TestStart_BooksRealExports(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	selfReg := prometheus.NewRegistry()
	dataReg := prometheus.NewRegistry()
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: "opnsense_test_e2e_gauge", Help: "e2e"})
	dataReg.MustRegister(g)
	g.Set(1)

	cfg := &options.OTLPConfig{
		Protocol:       "http/protobuf",
		Endpoint:       srv.URL,
		Insecure:       true,
		ExportInterval: time.Hour, // no periodic tick; the shutdown flush drives the export
		ServiceName:    "opnsense-exporter",
	}
	shutdown, err := Start(
		context.Background(), []prometheus.Gatherer{dataReg},
		cfg, "v-test", "inst", selfReg, discardLogger(),
	)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	if got := counterValue(t, selfReg, mExports, resultSuccess); got < 1 {
		t.Errorf("%s{result=success} = %v after a real export, want >= 1 "+
			"(the observing decorator is not in the reader's pipeline)", mExports, got)
	}
	if got := counterValue(t, selfReg, mExports, resultError); got != 0 {
		t.Errorf("%s{result=error} = %v against a healthy endpoint, want 0", mExports, got)
	}
	if got := gaugeValue(t, selfReg, mLastSuccess); got == 0 {
		t.Errorf("%s = 0 after a successful export, want a real timestamp", mLastSuccess)
	}
	if got := gaugeValue(t, selfReg, mConsecutive); got != 0 {
		t.Errorf("%s = %v after a successful export, want 0", mConsecutive, got)
	}
}

// TestDeliveryMetrics_ZeroSeeded: both result values must exist at zero from
// registration, so a healthy exporter reports a flat 0 error rate rather than an
// absent series that rate() cannot evaluate.
func TestDeliveryMetrics_ZeroSeeded(t *testing.T) {
	reg := prometheus.NewRegistry()
	newDeliveryMetrics(reg)

	if got := counterValue(t, reg, mExports, resultSuccess); got != 0 {
		t.Errorf("seeded exports_total{result=success} = %v, want 0", got)
	}
	if got := counterValue(t, reg, mExports, resultError); got != 0 {
		t.Errorf("seeded exports_total{result=error} = %v, want 0", got)
	}
	mf := gatherFamily(t, reg, mExports)
	if mf == nil || len(mf.GetMetric()) != 2 {
		t.Fatalf("exports_total must be seeded with exactly the closed {success,error} label set")
	}
	// The closed vocabulary must be exactly two values.
	seen := map[string]bool{}
	for _, m := range mf.GetMetric() {
		for _, lp := range m.GetLabel() {
			if lp.GetName() != "result" {
				t.Errorf("unexpected label %q on exports_total; result is the only permitted label", lp.GetName())
			}
			seen[lp.GetValue()] = true
		}
	}
	if !seen[resultSuccess] || !seen[resultError] || len(seen) != 2 {
		t.Errorf("result label vocabulary = %v, want exactly {success,error}", seen)
	}

	if got := gaugeValue(t, reg, mEnabled); got != 0 {
		t.Errorf("otlp_enabled before Start = %v, want 0", got)
	}
}
