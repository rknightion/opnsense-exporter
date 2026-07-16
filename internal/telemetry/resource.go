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
// What a backend then does with the resource is out of our hands, and Grafana
// Cloud does NOT follow that convention: its OTLP gateway promotes a fixed list of
// resource attributes — service.version among them — to a label on every series,
// which no exporter-side change can prevent (#270). Do not read a `service_version`
// label in a Grafana Cloud query as evidence that this package emits one; verify
// against a second, unrelated app on the same tenant before going looking for a bug
// here. Changing that list requires contacting Grafana Support:
// https://grafana.com/docs/grafana-cloud/send-data/otlp/otlp-format-considerations/#metrics
const (
	keyServiceName       = "service.name"
	keyServiceVersion    = "service.version"
	keyServiceInstanceID = "service.instance.id"
)

// buildResource composes the OTLP resource. Explicit configuration (service name,
// build version, the resolved instance label) is applied last so it takes
// precedence over OTEL_SERVICE_NAME / OTEL_RESOURCE_ATTRIBUTES read by WithFromEnv.
// resource.New may return a non-nil resource alongside a partial/schema error; the
// caller decides whether that is fatal.
func buildResource(ctx context.Context, cfg *options.OTLPConfig, version, instance string) (*resource.Resource, error) {
	attrs := make([]attribute.KeyValue, 0, 3)
	if cfg.ServiceName != "" {
		attrs = append(attrs, attribute.String(keyServiceName, cfg.ServiceName))
	}
	if version != "" {
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
