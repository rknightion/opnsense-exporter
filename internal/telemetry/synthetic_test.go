package telemetry

import (
	"context"
	"testing"

	dto "github.com/prometheus/client_model/go"
	prometheusbridge "go.opentelemetry.io/contrib/bridges/prometheus"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// TestSyntheticUpGatherer verifies the push-mode `up` series: a single `up`
// family fixed at 1 and carrying the exporter instance label. This is the
// OTLP-only replacement for the target-up series a Prometheus scraper would
// otherwise synthesize.
func TestSyntheticUpGatherer(t *testing.T) {
	g, err := newSyntheticUpGatherer("fw1")
	if err != nil {
		t.Fatalf("newSyntheticUpGatherer: %v", err)
	}

	mfs, err := g.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if len(mfs) != 1 {
		t.Fatalf("expected exactly 1 metric family, got %d", len(mfs))
	}

	mf := mfs[0]
	if mf.GetName() != "up" {
		t.Errorf("metric name = %q, want %q", mf.GetName(), "up")
	}
	if mf.GetType() != dto.MetricType_GAUGE {
		t.Errorf("metric type = %v, want GAUGE", mf.GetType())
	}
	if len(mf.GetMetric()) != 1 {
		t.Fatalf("expected 1 series, got %d", len(mf.GetMetric()))
	}
	m := mf.GetMetric()[0]
	if got := m.GetGauge().GetValue(); got != 1 {
		t.Errorf("up value = %v, want 1", got)
	}

	labels := map[string]string{}
	for _, lp := range m.GetLabel() {
		labels[lp.GetName()] = lp.GetValue()
	}
	if labels[syntheticInstanceLabel] != "fw1" {
		t.Errorf("%s label = %q, want fw1", syntheticInstanceLabel, labels[syntheticInstanceLabel])
	}
}

// TestSyntheticUpReachesOTLPOutput proves the synthetic `up` survives the
// Prometheus->OTLP bridge intact — a Gauge named `up`, valued 1, carrying the
// instance as an attribute. This is the property the whole feature depends on:
// the series must actually appear in the pushed OTLP stream.
func TestSyntheticUpReachesOTLPOutput(t *testing.T) {
	g, err := newSyntheticUpGatherer("fw1")
	if err != nil {
		t.Fatalf("newSyntheticUpGatherer: %v", err)
	}

	producer := prometheusbridge.NewMetricProducer(prometheusbridge.WithGatherer(g))
	reader := sdkmetric.NewManualReader(sdkmetric.WithProducer(producer))
	defer reader.Shutdown(context.Background()) //nolint:errcheck
	_ = sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}

	var up *metricdata.Metrics
	for _, sm := range rm.ScopeMetrics {
		for i := range sm.Metrics {
			if sm.Metrics[i].Name == "up" {
				up = &sm.Metrics[i]
			}
		}
	}
	if up == nil {
		t.Fatal("synthetic up missing from OTLP output")
	}
	gd, ok := up.Data.(metricdata.Gauge[float64])
	if !ok {
		t.Fatalf("expected Gauge[float64], got %T", up.Data)
	}
	if len(gd.DataPoints) != 1 || gd.DataPoints[0].Value != 1 {
		t.Fatalf("up datapoints = %+v, want single value 1", gd.DataPoints)
	}
	if v, present := gd.DataPoints[0].Attributes.Value(attribute.Key(syntheticInstanceLabel)); !present || v.AsString() != "fw1" {
		t.Errorf("%s attribute = %q (present=%v), want fw1", syntheticInstanceLabel, v.AsString(), present)
	}
}

// TestSyntheticUpLabelMatchesCollector guards against drift between the
// duplicated instance-label name here and the collector package's canonical
// "opnsense_instance". If the collector ever renames its instance label, this
// value must be updated in lockstep — a mismatch would give the synthetic `up`
// a different instance identity than every other exported series.
func TestSyntheticUpLabelMatchesCollector(t *testing.T) {
	if syntheticInstanceLabel != "opnsense_instance" {
		t.Fatalf("syntheticInstanceLabel = %q, must stay in lockstep with collector.instanceLabelName (%q)",
			syntheticInstanceLabel, "opnsense_instance")
	}
}
