// Package telemetry builds an OpenTelemetry MeterProvider that exports the
// exporter's existing Prometheus metrics over OTLP, with exact name/label/value
// parity. It introduces no instruments of its own: a Prometheus-bridge producer
// gathers the shared *prometheus.Registry on each export tick and converts every
// metric family to OTLP. The /metrics pull endpoint is unaffected.
package telemetry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/rknightion/opnsense2otel/v4/internal/options"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"google.golang.org/grpc/credentials"
)

// buildTLSConfig assembles a *tls.Config from the configured CA / client cert /
// client key files, or returns (nil, nil) when none are set (use system defaults).
func buildTLSConfig(cfg *options.OTLPConfig) (*tls.Config, error) {
	if cfg.TLSCAFile == "" && cfg.TLSCertFile == "" && cfg.TLSKeyFile == "" {
		return nil, nil
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.TLSCAFile != "" {
		ca, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("read otlp tls-ca-file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("otlp tls-ca-file %q contains no valid certificates", cfg.TLSCAFile)
		}
		tc.RootCAs = pool
	}
	if cfg.TLSCertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load otlp client keypair: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return tc, nil
}

// metricsEndpointURL ensures an OTLP HTTP endpoint targets the metrics signal
// path. The OTel SDK's WithEndpointURL uses the URL's path verbatim, only
// defaulting to /v1/metrics when the path is empty — unlike the
// OTEL_EXPORTER_OTLP_ENDPOINT env var, which does path.Join(path, "/v1/metrics").
// Grafana Cloud (and our own docs) hand out a base URL of the form
// https://otlp-gateway-<zone>.grafana.net/otlp, so without this the exporter
// would POST to /otlp — which the gateway doesn't serve — and silently deliver
// zero metrics (#80). We mirror the env-var semantics by appending the signal
// path when the endpoint has a non-empty path that doesn't already target it,
// rewriting the URL string (rather than switching to WithEndpoint) so the
// scheme-derived TLS/insecure behaviour of WithEndpointURL is preserved.
func metricsEndpointURL(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse otlp endpoint %q: %w", endpoint, err)
	}
	trimmed := strings.TrimRight(u.Path, "/")
	// Empty/root path: leave it so the SDK applies its default /v1/metrics.
	// Already targeting the metrics signal path: leave it so we don't double it.
	if trimmed == "" || strings.HasSuffix(trimmed, "/v1/metrics") {
		return endpoint, nil
	}
	u.Path = path.Join(u.Path, "v1", "metrics")
	return u.String(), nil
}

// newExporter builds an OTLP metric exporter for the configured protocol. Fields
// left empty are not passed as options, so the OTEL SDK falls back to the standard
// OTEL_EXPORTER_OTLP_* environment variables for them.
func newExporter(ctx context.Context, cfg *options.OTLPConfig) (sdkmetric.Exporter, error) {
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Temporality is intentionally not set: the metrics come from the Prometheus
	// bridge producer already aggregated as cumulative, and an exporter-side
	// selector does not re-aggregate producer-supplied data. Cumulative is also the
	// exporter default and what Grafana Cloud / Prometheus require.
	switch cfg.Protocol {
	case "grpc":
		var opts []otlpmetricgrpc.Option
		// Ask for gzip unless the operator set OTEL_EXPORTER_OTLP[_METRICS]_COMPRESSION.
		// The bridged Prometheus registry re-sends every metric name and label string on
		// every export tick, so this payload is unusually repetitive and compresses hard.
		// See options.OTLPGzipDefault for why this must be conditional rather than an
		// unconditional option — a passed option beats the env var in the SDK, which
		// would silently disable the documented override.
		if options.OTLPGzipDefault(options.OTLPSignalMetrics) {
			opts = append(opts, otlpmetricgrpc.WithCompressor("gzip"))
		}
		if cfg.Endpoint != "" {
			opts = append(opts, otlpmetricgrpc.WithEndpointURL(cfg.Endpoint))
		}
		if cfg.Insecure {
			opts = append(opts, otlpmetricgrpc.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlpmetricgrpc.WithHeaders(cfg.Headers))
		}
		if tlsCfg != nil {
			opts = append(opts, otlpmetricgrpc.WithTLSCredentials(credentials.NewTLS(tlsCfg)))
		}
		return otlpmetricgrpc.New(ctx, opts...)
	case "http/protobuf", "":
		var opts []otlpmetrichttp.Option
		// See the grpc branch above for why this is conditional.
		if options.OTLPGzipDefault(options.OTLPSignalMetrics) {
			opts = append(opts, otlpmetrichttp.WithCompression(otlpmetrichttp.GzipCompression))
		}
		if cfg.Endpoint != "" {
			ep, err := metricsEndpointURL(cfg.Endpoint)
			if err != nil {
				return nil, err
			}
			opts = append(opts, otlpmetrichttp.WithEndpointURL(ep))
		}
		if cfg.Insecure {
			opts = append(opts, otlpmetrichttp.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlpmetrichttp.WithHeaders(cfg.Headers))
		}
		if tlsCfg != nil {
			opts = append(opts, otlpmetrichttp.WithTLSClientConfig(tlsCfg))
		}
		return otlpmetrichttp.New(ctx, opts...)
	default:
		return nil, fmt.Errorf("unsupported otlp protocol %q", cfg.Protocol)
	}
}
