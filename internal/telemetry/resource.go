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
