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
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/rknightion/opnsense2otel/v5/internal/options"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"google.golang.org/grpc/credentials"
)

// buildTLSConfig assembles a *tls.Config from the configured CA / client cert /
// client key files, or returns (nil, nil) when none are set (use system defaults).
// Explicit flags win; unset fields fall back to the standard signal-specific and
// general OTEL_EXPORTER_OTLP_* certificate environment variables. This must be
// resolved here because WithHTTPClient bypasses the SDK's environment-built TLS.
func buildTLSConfig(cfg *options.OTLPConfig) (*tls.Config, error) {
	caFile := cfg.TLSCAFile
	if caFile == "" {
		caFile = firstMetricsEnv("OTEL_EXPORTER_OTLP_METRICS_CERTIFICATE", "OTEL_EXPORTER_OTLP_CERTIFICATE")
	}
	certFile, keyFile := cfg.TLSCertFile, cfg.TLSKeyFile
	if certFile == "" && keyFile == "" {
		certFile = firstMetricsEnv("OTEL_EXPORTER_OTLP_METRICS_CLIENT_CERTIFICATE", "OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE")
		keyFile = firstMetricsEnv("OTEL_EXPORTER_OTLP_METRICS_CLIENT_KEY", "OTEL_EXPORTER_OTLP_CLIENT_KEY")
	}
	if caFile == "" && certFile == "" && keyFile == "" {
		return nil, nil
	}
	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("otlp metrics: client certificate and key must be configured together")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		ca, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read otlp tls-ca-file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("otlp tls-ca-file %q contains no valid certificates", caFile)
		}
		tc.RootCAs = pool
	}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load otlp client keypair: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return tc, nil
}

func firstMetricsEnv(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

func validateMetricsTransport(cfg *options.OTLPConfig, tlsCfg *tls.Config) error {
	if cfg.Insecure && tlsCfg != nil {
		return fmt.Errorf("otlp metrics: insecure transport cannot be combined with TLS certificate configuration")
	}
	if tlsCfg != nil && cfg.Endpoint != "" {
		u, err := url.Parse(cfg.Endpoint)
		if err != nil {
			return fmt.Errorf("parse otlp endpoint %q: %w", cfg.Endpoint, err)
		}
		if strings.EqualFold(u.Scheme, "http") {
			return fmt.Errorf("otlp metrics: http endpoint cannot be combined with TLS certificate configuration")
		}
	}
	return nil
}

// metricsEndpointURL ensures an OTLP HTTP endpoint targets the metrics signal
// path. The OTel SDK's WithEndpointURL uses the URL's path verbatim — unlike the
// OTEL_EXPORTER_OTLP_ENDPOINT env var, which does path.Join(path, "/v1/metrics").
// Grafana Cloud (and our own docs) hand out a base URL of the form
// https://otlp-gateway-<zone>.grafana.net/otlp, so without this the exporter
// would POST to /otlp — which the gateway doesn't serve — and silently deliver
// zero metrics (#80). We mirror the env-var semantics by appending the signal
// path unless the endpoint already targets it, rewriting the URL string (rather
// than switching to WithEndpoint) so the scheme-derived TLS/insecure behaviour
// of WithEndpointURL is preserved.
//
// A PATHLESS endpoint is written out in full here rather than left to the SDK.
// It used to be safe to leave: WithEndpointURL copied the empty path through and
// cleanPath substituted the /v1/metrics default. otel v1.45.0 changed that to set
// an explicit "/" for an empty path, which suppresses the default — so relying on
// it silently started POSTing every metric to the server root. Setting the signal
// path ourselves makes this independent of which side owns the default.
func metricsEndpointURL(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse otlp endpoint %q: %w", endpoint, err)
	}
	trimmed := strings.TrimRight(u.Path, "/")
	// Already targeting the metrics signal path: leave it so we don't double it.
	if strings.HasSuffix(trimmed, "/v1/metrics") {
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
	if err := validateMetricsTransport(cfg, tlsCfg); err != nil {
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
		client, err := newMetricsHTTPClient(tlsCfg)
		if err != nil {
			return nil, err
		}
		opts = append(opts, otlpmetrichttp.WithHTTPClient(client))
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
		return otlpmetrichttp.New(ctx, opts...)
	default:
		return nil, fmt.Errorf("unsupported otlp protocol %q", cfg.Protocol)
	}
}

func newMetricsHTTPClient(tlsCfg *tls.Config) (*http.Client, error) {
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("otlp metrics: http.DefaultTransport is not an *http.Transport (%T)", http.DefaultTransport)
	}
	base := tr.Clone()
	base.TLSClientConfig = tlsCfg
	return &http.Client{
		Transport: base,
		Timeout:   metricsExportTimeout(),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func metricsExportTimeout() time.Duration {
	const defaultTimeout = 10 * time.Second
	for _, env := range []string{"OTEL_EXPORTER_OTLP_METRICS_TIMEOUT", "OTEL_EXPORTER_OTLP_TIMEOUT"} {
		raw := strings.TrimSpace(os.Getenv(env))
		if raw == "" {
			continue
		}
		ms, err := strconv.Atoi(raw)
		if err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return defaultTimeout
}
