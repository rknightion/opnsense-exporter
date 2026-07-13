package logship

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/options"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"google.golang.org/grpc/credentials"
)

// otlpSink ships records over OTLP logs. It reuses the exporter's --otlp.*
// transport family. The SDK LoggerProvider's BatchProcessor owns the network
// batching and retry; the pipeline's own bounded queue is the primary,
// COUNTED backpressure valve in front of it (the SDK batch queue drops silently).
//
// The pre-1.0 otel logs SDK is deliberately confined to this file (pinned +
// Renovate) so the rest of the codebase never imports it.
type otlpSink struct {
	provider *sdklog.LoggerProvider
	logger   otellog.Logger
}

// newOTLPSink builds the OTLP logs sink. It fails fast with an actionable error
// when no endpoint is resolvable (neither --otlp.endpoint / Grafana Cloud nor an
// OTEL_EXPORTER_OTLP*_ENDPOINT env var), so logs.enabled with an unconfigured
// transport is a clear startup error rather than silent no-delivery.
func newOTLPSink(cfg *options.OTLPConfig, version, instance string, _ *slog.Logger) (Sink, error) {
	if !endpointResolvable(cfg.Endpoint) {
		return nil, fmt.Errorf("logs sink=otlp requires an OTLP endpoint: set --otlp.endpoint " +
			"(or --otlp.grafana-cloud-endpoint, or the OTEL_EXPORTER_OTLP_ENDPOINT / " +
			"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT environment variable)")
	}

	exporter, err := newLogExporter(context.Background(), cfg)
	if err != nil {
		return nil, fmt.Errorf("build otlp log exporter: %w", err)
	}

	res, err := buildLogResource(context.Background(), cfg.ServiceName, version, instance)
	if err != nil {
		return nil, fmt.Errorf("build otlp log resource: %w", err)
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
	)
	return &otlpSink{
		provider: provider,
		logger:   provider.Logger("github.com/rknightion/opnsense-exporter/logship"),
	}, nil
}

func (s *otlpSink) Emit(ctx context.Context, batch []Entry) error {
	now := time.Now()
	for _, e := range batch {
		var r otellog.Record
		ts := e.Record.Timestamp
		if ts.IsZero() {
			ts = now
		}
		r.SetTimestamp(ts)
		r.SetObservedTimestamp(now)
		r.SetBody(otellog.StringValue(e.Record.Body))
		r.SetSeverity(otlpSeverity(e.Record.Severity))
		// `source` is the promotable identity attribute; everything else is
		// structured metadata. Reserved keys were already stripped upstream.
		r.AddAttributes(otellog.String(attrSource, e.Source))
		for k, v := range e.Record.Attributes {
			r.AddAttributes(otellog.String(k, v))
		}
		s.logger.Emit(ctx, r)
	}
	return nil
}

func (s *otlpSink) Shutdown(ctx context.Context) error {
	return s.provider.Shutdown(ctx)
}

// otlpSeverity maps a logship Severity to an OTLP severity number.
func otlpSeverity(sv Severity) otellog.Severity {
	switch sv {
	case SeverityTrace:
		return otellog.SeverityTrace
	case SeverityDebug:
		return otellog.SeverityDebug
	case SeverityWarn:
		return otellog.SeverityWarn
	case SeverityError:
		return otellog.SeverityError
	case SeverityFatal:
		return otellog.SeverityFatal
	case SeverityInfo:
		return otellog.SeverityInfo
	default:
		return otellog.SeverityInfo
	}
}

// endpointResolvable reports whether an OTLP endpoint can be determined from the
// explicit config or the standard OTEL env vars the SDK consults.
func endpointResolvable(explicit string) bool {
	if strings.TrimSpace(explicit) != "" {
		return true
	}
	for _, env := range []string{"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT"} {
		if strings.TrimSpace(os.Getenv(env)) != "" {
			return true
		}
	}
	return false
}

// buildLogResource composes the OTLP resource with ONLY the identity attributes
// that the Loki OTLP ingest promotes to labels (service.name, service.instance.id)
// plus service.version (structured metadata). No host/SDK detectors are added, so
// no other attribute can leak into the fixed Loki label set. Plain attribute keys
// avoid a schema-URL conflict.
func buildLogResource(ctx context.Context, serviceName, version, instance string) (*resource.Resource, error) {
	attrs := make([]attribute.KeyValue, 0, 3)
	if serviceName != "" {
		attrs = append(attrs, attribute.String("service.name", serviceName))
	}
	if version != "" {
		attrs = append(attrs, attribute.String("service.version", version))
	}
	if instance != "" {
		attrs = append(attrs, attribute.String("service.instance.id", instance))
	}
	return resource.New(ctx, resource.WithAttributes(attrs...))
}

// newLogExporter builds an OTLP log exporter for the configured protocol,
// mirroring the metrics exporter's option handling. Empty fields are omitted so
// the SDK falls back to the standard OTEL_EXPORTER_OTLP_* env vars.
func newLogExporter(ctx context.Context, cfg *options.OTLPConfig) (sdklog.Exporter, error) {
	tlsCfg, err := buildLogTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	switch cfg.Protocol {
	case "grpc":
		var opts []otlploggrpc.Option
		if cfg.Endpoint != "" {
			opts = append(opts, otlploggrpc.WithEndpointURL(cfg.Endpoint))
		}
		if cfg.Insecure {
			opts = append(opts, otlploggrpc.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlploggrpc.WithHeaders(cfg.Headers))
		}
		if tlsCfg != nil {
			opts = append(opts, otlploggrpc.WithTLSCredentials(credentials.NewTLS(tlsCfg)))
		}
		return otlploggrpc.New(ctx, opts...)
	case "http/protobuf", "":
		var opts []otlploghttp.Option
		if cfg.Endpoint != "" {
			ep, err := logsEndpointURL(cfg.Endpoint)
			if err != nil {
				return nil, err
			}
			opts = append(opts, otlploghttp.WithEndpointURL(ep))
		}
		if cfg.Insecure {
			opts = append(opts, otlploghttp.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlploghttp.WithHeaders(cfg.Headers))
		}
		if tlsCfg != nil {
			opts = append(opts, otlploghttp.WithTLSClientConfig(tlsCfg))
		}
		return otlploghttp.New(ctx, opts...)
	default:
		return nil, fmt.Errorf("unsupported otlp protocol %q", cfg.Protocol)
	}
}

// logsEndpointURL ensures an OTLP HTTP endpoint targets the logs signal path,
// mirroring the metrics sink's /v1/metrics fix (#80): the SDK's WithEndpointURL
// uses the path verbatim, so a Grafana-Cloud-style base URL of the form
// https://otlp-gateway-<zone>.grafana.net/otlp would POST to /otlp and silently
// deliver zero logs. Append /v1/logs when a non-empty path doesn't already
// target it.
func logsEndpointURL(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse otlp endpoint %q: %w", endpoint, err)
	}
	trimmed := strings.TrimRight(u.Path, "/")
	if trimmed == "" || strings.HasSuffix(trimmed, "/v1/logs") {
		return endpoint, nil
	}
	u.Path = path.Join(u.Path, "v1", "logs")
	return u.String(), nil
}

// buildLogTLSConfig assembles a *tls.Config from the configured CA / client cert
// / key files, or (nil, nil) when none are set.
func buildLogTLSConfig(cfg *options.OTLPConfig) (*tls.Config, error) {
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
