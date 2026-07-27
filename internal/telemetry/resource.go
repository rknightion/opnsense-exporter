package telemetry

import (
	"context"

	"github.com/rknightion/opnsense-exporter/internal/options"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
)

// Well-known resource attribute keys. Plain keys (rather than a versioned semconv
// package) are used deliberately so resource.Merge never hits a schema-URL conflict
// with the SDK's own detectors.
//
// These belong to the RESOURCE and are never copied onto datapoints. That is the
// OTLP->Prometheus convention: service.name(+service.namespace) becomes `job`,
// service.instance.id becomes `instance`, and every other resource attribute —
// service.version included — belongs on `target_info`, never as a label on each
// series. Version is exposed the Prometheus-native way instead, as a label on the
// opnsense_exporter_build_info gauge (see collector.collectExporterInfo).
//
// Grafana Cloud does NOT follow that convention: its OTLP gateway promotes a fixed
// list of resource attributes — service.version among them — to a label on every
// series. Changing that list would require contacting Grafana Support:
// https://grafana.com/docs/grafana-cloud/send-data/otlp/otlp-format-considerations/#metrics
//
// #270 CONCLUDED THIS WAS UNFIXABLE HERE. THAT WAS WRONG (#472). The gateway can only
// promote an attribute the resource actually carries, so omitting service.version from
// the METRICS resource prevents the label outright — no Support request, no tenant
// change. Measured before the fix: `service_version` was a label on 552 metric names,
// including every go_* runtime metric, so every redeploy minted a fresh series set and
// any sum-style panel double-counted for the query-lookback window. The sibling
// exporters were already doing this (rknightion/graph2otel#104, which measures 0
// affected metric names, and rknightion/tailscale2otel#187).
//
// So the split is deliberate and asymmetric — see buildResource's includeServiceVersion:
// OFF for metrics (a per-series label surface), ON for logs, whose resource is built
// separately in internal/logship/sink_otlp.go. Log records are never summed and have no
// per-series label surface, so version there is free and lands in structured metadata.
const (
	keyServiceName       = "service.name"
	keyServiceVersion    = "service.version"
	keyServiceInstanceID = "service.instance.id"
)

// metricsResourceIncludesServiceVersion is the one place the metrics lane's answer to
// includeServiceVersion is written down. It is a named constant rather than a literal
// `false` at the call site so the #472 regression guard can assert the wiring, not just
// buildResource's behaviour in isolation — passing `true` in provider.go would otherwise
// restore the 552-metric label with every unit test still green.
const metricsResourceIncludesServiceVersion = false

// buildResource composes the OTLP resource. Explicit configuration (service name,
// build version, the resolved instance label) is applied last so it takes
// precedence over OTEL_SERVICE_NAME / OTEL_RESOURCE_ATTRIBUTES read by WithFromEnv.
// resource.New may return a non-nil resource alongside a partial/schema error; the
// caller decides whether that is fatal.
//
// includeServiceVersion must be FALSE for any resource feeding a MeterProvider: see the
// const block above for why (#472). It is a parameter rather than an unconditional
// omission so the decision stays visible at the call site, and so a future traces
// resource — which, like logs, has no per-series label surface — can opt back in.
func buildResource(ctx context.Context, cfg *options.OTLPConfig, version, instance string,
	includeServiceVersion bool) (*resource.Resource, error) {
	attrs := make([]attribute.KeyValue, 0, 3)
	if cfg.ServiceName != "" {
		attrs = append(attrs, attribute.String(keyServiceName, cfg.ServiceName))
	}
	if includeServiceVersion && version != "" {
		attrs = append(attrs, attribute.String(keyServiceVersion, version))
	}
	if instance != "" {
		attrs = append(attrs, attribute.String(keyServiceInstanceID, instance))
	}

	return resource.New(ctx,
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithFromEnv(),
		resource.WithAttributes(attrs...),
	)
}
