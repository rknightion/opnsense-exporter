package telemetry

import (
	"context"
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// Values of the `result` label on opnsense_exporter_otlp_exports_total. This is a
// CLOSED, code-defined vocabulary of exactly two values. Error text, endpoint,
// tenant, headers and credentials must NEVER become labels: they are unbounded
// and/or secret, and one bad endpoint would otherwise blow up cardinality on the
// very series an operator reaches for during an outage.
const (
	resultSuccess = "success"
	resultError   = "error"
)

// deliveryMetrics is the self-observability for the OTLP metric push path (#388).
//
// Without it, export success is visible only through rate-limited logs: Start
// performs no network I/O (the exporter connects lazily), so "otlp metrics export
// enabled" is logged before anything has ever been sent, and a wrong endpoint,
// expired credential or backend outage delivers zero metrics indefinitely with no
// queryable local state.
//
// Known and deliberate limitation: an exporter cannot ship its own failure metric
// through the path that is failing. These series are immediately useful at /metrics
// and to the passive operator console, and become historical evidence in OTLP once
// delivery recovers — but they are NOT an in-band outage alert for a pure-OTLP
// backend. Alert on staleness there.
//
// A nil *deliveryMetrics is valid and inert: every method is nil-receiver safe, so
// a caller with no self-metrics registry needs no branch.
type deliveryMetrics struct {
	exports             *prometheus.CounterVec // otlp_exports_total{result}
	lastSuccess         prometheus.Gauge       // otlp_last_success_timestamp_seconds
	consecutiveFailures prometheus.Gauge       // otlp_consecutive_failures
	enabled             prometheus.Gauge       // otlp_enabled
}

// newDeliveryMetrics constructs and registers the OTLP delivery-health series on
// reg, seeding both `result` label values to zero (#280) so a healthy exporter
// reports a flat 0 error rate rather than an absent series that rate() cannot
// evaluate.
//
// A nil reg returns nil — registration and all accounting are skipped, which is how
// callers that have no self-metrics registry (and the package's own tests) opt out.
//
// Registering twice against the same registry is safe and non-duplicating: each
// collector that is already present is ADOPTED, so both returned handles drive the
// same underlying series. Any other registration error is a programming error and
// panics, matching prometheus.MustRegister.
func newDeliveryMetrics(reg prometheus.Registerer) *deliveryMetrics {
	if reg == nil {
		return nil
	}
	m := &deliveryMetrics{
		exports: registerOrAdopt(reg, prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: prometheus.BuildFQName(deliveryNamespace, deliverySubsystem, "otlp_exports_total"),
			Help: "Total OTLP metric export attempts by outcome (success = the endpoint " +
				"accepted the batch; error = the export call returned an error, which is also " +
				"logged rate-limited). Counted exactly once per export call, never per metric. " +
				"Note the exporter cannot deliver this series through a failing OTLP path — read " +
				"it at /metrics or on the operator console during an outage.",
		}, []string{"result"})),
		lastSuccess: registerOrAdopt(reg, prometheus.NewGauge(prometheus.GaugeOpts{
			Name: prometheus.BuildFQName(deliveryNamespace, deliverySubsystem, "otlp_last_success_timestamp_seconds"),
			Help: "Unix timestamp of the last successful OTLP metric export. 0 means no export " +
				"has ever succeeded, which is the startup state — the OTLP exporter connects " +
				"lazily, so a successful start proves nothing about delivery.",
		})),
		consecutiveFailures: registerOrAdopt(reg, prometheus.NewGauge(prometheus.GaugeOpts{
			Name: prometheus.BuildFQName(deliveryNamespace, deliverySubsystem, "otlp_consecutive_failures"),
			Help: "Number of OTLP metric exports that have failed back-to-back. Reset to 0 by the " +
				"next success, so a sustained non-zero value is an ongoing delivery outage rather " +
				"than a transient blip.",
		})),
		enabled: registerOrAdopt(reg, prometheus.NewGauge(prometheus.GaugeOpts{
			Name: prometheus.BuildFQName(deliveryNamespace, deliverySubsystem, "otlp_enabled"),
			Help: "1 when OTLP metric export is running. Construction failure is fatal at startup, " +
				"so there is no configured-but-inactive state: this is either 1 or the metric is " +
				"absent because OTLP export was never enabled.",
		})),
	}
	// Seed the closed label set so both series exist from t=0.
	m.exports.WithLabelValues(resultSuccess)
	m.exports.WithLabelValues(resultError)
	return m
}

const (
	deliveryNamespace = "opnsense"
	deliverySubsystem = "exporter"
)

// registerOrAdopt registers c on reg, returning the already-registered collector
// instead of panicking when an identical one is present. That makes a second
// newDeliveryMetrics against the same registry share one set of series rather than
// duplicating or exploding.
func registerOrAdopt[T prometheus.Collector](reg prometheus.Registerer, c T) T {
	if err := reg.Register(c); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(T); ok {
				return existing
			}
		}
		panic(err)
	}
	return c
}

// recordExport books the outcome of exactly one export call. A nil receiver is a
// no-op.
func (m *deliveryMetrics) recordExport(err error) {
	if m == nil {
		return
	}
	if err != nil {
		m.exports.WithLabelValues(resultError).Inc()
		m.consecutiveFailures.Inc()
		return
	}
	m.exports.WithLabelValues(resultSuccess).Inc()
	m.lastSuccess.SetToCurrentTime()
	m.consecutiveFailures.Set(0)
}

// markEnabled publishes that OTLP export is running. A nil receiver is a no-op.
func (m *deliveryMetrics) markEnabled() {
	if m == nil {
		return
	}
	m.enabled.Set(1)
}

// observingExporter decorates an sdkmetric.Exporter with delivery accounting. It is
// a pure observer: every method delegates to inner, and Export returns inner's error
// UNCHANGED so the SDK still routes it to the rate-limited slogErrorHandler.
//
// Only Export is counted. ForceFlush and Shutdown are not exports — the reader's
// final flush already routes through Export, so counting them here would
// double-count a shutdown.
type observingExporter struct {
	inner sdkmetric.Exporter
	m     *deliveryMetrics
}

// observeExports wraps inner so each Export call updates m. When m is nil there is
// nothing to record, so inner is returned undecorated.
func observeExports(inner sdkmetric.Exporter, m *deliveryMetrics) sdkmetric.Exporter {
	if m == nil {
		return inner
	}
	return &observingExporter{inner: inner, m: m}
}

func (e *observingExporter) Temporality(k sdkmetric.InstrumentKind) metricdata.Temporality {
	return e.inner.Temporality(k)
}

func (e *observingExporter) Aggregation(k sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return e.inner.Aggregation(k)
}

func (e *observingExporter) Export(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	err := e.inner.Export(ctx, rm)
	e.m.recordExport(err)
	return err
}

func (e *observingExporter) ForceFlush(ctx context.Context) error { return e.inner.ForceFlush(ctx) }

func (e *observingExporter) Shutdown(ctx context.Context) error { return e.inner.Shutdown(ctx) }
