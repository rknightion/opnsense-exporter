package logship

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
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

// maxLogResources bounds the number of distinct OTLP resources — and therefore
// LoggerProviders — the sink will build.
//
// Both dimensions of the resource key are closed sets defined in OUR code: ~4
// sources and ~22 subsystems. The cap is therefore unreachable in practice. It
// exists so that a future Source which put something wire-derived behind
// `subsystem` could not leak providers here, nor (once a tenant promotes the
// attribute) explode Loki's label cardinality. Past the cap we degrade to the base
// resource: records still ship, they just stop being partitioned.
const maxLogResources = 64

// otlpSink ships records over OTLP logs. It reuses the exporter's --otlp.*
// transport family. Each provider's syncBatchProcessor (#290) exports synchronously and
// returns the real export error, so the pipeline's own bounded queue is the single
// COUNTED backpressure valve and delivery is observable — there is no second, silent SDK
// batch queue in front of the wire. The exporter itself still applies OTLP's transient
// retry/backoff; a returned error means it gave up, and the pipeline retries the batch.
//
// LABELS VS STRUCTURED METADATA (#263). Loki promotes only RESOURCE attributes to
// index labels; scope and log attributes can only ever become structured metadata,
// because `otlp_config` has no index_label action for them. So the two attributes
// worth selecting a stream on — `opnsense.source` and `opnsense.subsystem` — are
// hoisted off the record onto the resource, which means one resource, and one
// LoggerProvider, per distinct (source, subsystem) pair. The otel logs SDK binds a
// LoggerProvider, not to a Record, so there is no cheaper way to vary it.
//
// This is safe by construction ONLY because both keys are closed code-defined sets
// (see AttrSubsystem). Everything genuinely high-cardinality — IPs, ports, rule
// ids, hostnames, MACs, SIDs — stays on the record and therefore can never be
// promoted, which is the point.
//
// Whether they ARE promoted is the tenant's choice and costs us nothing either way:
// an unpromoted resource attribute lands in structured metadata, exactly where these
// two used to live, so queries keep working unchanged until an operator opts in with
//
//	limits_config:
//	  otlp_config:
//	    resource_attributes:
//	      attributes_config:
//	        - action: index_label
//	          attributes: [opnsense.subsystem, opnsense.source]
//
// The providers share ONE exporter, so partitioning costs no extra connections.
//
// The pre-1.0 otel logs SDK is deliberately confined to this file (pinned +
// Renovate) so the rest of the codebase never imports it.
type otlpSink struct {
	exporter sdklog.Exporter
	base     []attribute.KeyValue
	log      *slog.Logger

	mu        sync.Mutex
	providers map[resourceKey]*resourceLogger
	order     []resourceKey // creation order, so Shutdown is deterministic
	// cappedOnce keeps the cardinality-cap warning to one line per process. The
	// counter carries the ongoing rate; the log line is there so the first
	// occurrence is discoverable without already knowing to look for the metric.
	cappedOnce sync.Once
}

// resourceKey identifies one OTLP resource. All three fields are closed sets.
type resourceKey struct{ source, subsystem, action string }

type resourceLogger struct {
	provider *sdklog.LoggerProvider
	logger   otellog.Logger
}

// sharedExporter lends the one real exporter to many LoggerProviders. Shutdown is
// suppressed: a provider shutting down would otherwise close the exporter out from
// under its siblings, and whichever of them still had records queued would fail to
// flush them. otlpSink.Shutdown closes the real exporter once, after every provider
// has drained.
type sharedExporter struct{ sdklog.Exporter }

func (sharedExporter) Shutdown(context.Context) error { return nil }

// syncBatchProcessor exports synchronously and observably, replacing the SDK's
// asynchronous BatchProcessor (#290). The BatchProcessor owns a background queue that
// drops records silently when full and, because otellog.Logger.Emit has no error
// return, swallows export failures entirely — so records the pipeline had already
// counted as "shipped" could vanish with no signal, while cursors advanced past them.
//
// This processor instead ACCUMULATES the records emitted during one sink.Emit call and,
// on ForceFlush, hands them to the exporter in a single synchronous Export whose real
// error propagates back to the sink. That makes the sink's own bounded queue the only
// place a record can be dropped, collapses the previous double-buffering (one uncounted
// SDK queue per resource key) into one accounted path, and lets the pipeline retry a
// failed batch instead of losing it. One emitter goroutine drives it; the mutex only
// satisfies the Processor concurrency contract.
type syncBatchProcessor struct {
	exporter sdklog.Exporter
	mu       sync.Mutex
	buf      []sdklog.Record
}

func newSyncBatchProcessor(exp sdklog.Exporter) *syncBatchProcessor {
	return &syncBatchProcessor{exporter: exp}
}

// OnEmit clones the record — the provider may reuse the pointer after we return — and
// buffers it for the next flush.
func (p *syncBatchProcessor) OnEmit(_ context.Context, r *sdklog.Record) error {
	p.mu.Lock()
	p.buf = append(p.buf, r.Clone())
	p.mu.Unlock()
	return nil
}

// Enabled always processes: the sink alone decides what to emit.
func (p *syncBatchProcessor) Enabled(context.Context, sdklog.EnabledParameters) bool { return true }

// export drains the buffer and ships it in one synchronous call, returning the real
// export error. A nil error means the exporter acknowledged the batch.
func (p *syncBatchProcessor) export(ctx context.Context) error {
	p.mu.Lock()
	batch := p.buf
	p.buf = nil
	p.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	return p.exporter.Export(ctx, batch)
}

func (p *syncBatchProcessor) ForceFlush(ctx context.Context) error { return p.export(ctx) }

// Shutdown flushes any residual buffer (there should be none — the sink ForceFlushes
// after every batch) but does NOT close the exporter: it is shared across providers and
// closed exactly once by otlpSink.Shutdown.
func (p *syncBatchProcessor) Shutdown(ctx context.Context) error { return p.export(ctx) }

// newOTLPSink builds the OTLP logs sink. It fails fast with an actionable error
// when no endpoint is resolvable (neither --otlp.endpoint / Grafana Cloud nor an
// OTEL_EXPORTER_OTLP*_ENDPOINT env var), so logs.enabled with an unconfigured
// transport is a clear startup error rather than silent no-delivery.
func newOTLPSink(cfg *options.OTLPConfig, version, instance string, log *slog.Logger) (Sink, error) {
	if !endpointResolvable(cfg.Endpoint) {
		return nil, fmt.Errorf("logs sink=otlp requires an OTLP endpoint: set --otlp.endpoint " +
			"(or --otlp.grafana-cloud-endpoint, or the OTEL_EXPORTER_OTLP_ENDPOINT / " +
			"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT environment variable)")
	}

	exporter, err := newLogExporter(context.Background(), cfg)
	if err != nil {
		return nil, fmt.Errorf("build otlp log exporter: %w", err)
	}

	return &otlpSink{
		exporter:  exporter,
		log:       log,
		base:      baseLogAttributes(cfg.ServiceName, version, instance),
		providers: make(map[resourceKey]*resourceLogger),
	}, nil
}

// Emit ships a batch synchronously: it emits every record into its resource's logger
// (which buffers it in that provider's syncBatchProcessor), then ForceFlushes each
// touched provider, which exports its buffered records in one call. A returned error
// means the export was NOT acknowledged, so the pipeline can retry the batch rather
// than counting it shipped — the delivery signal the old fire-and-forget path lacked.
func (s *otlpSink) Emit(ctx context.Context, batch []Entry) error {
	now := time.Now()
	touched := make(map[*resourceLogger]struct{})
	for _, e := range batch {
		rl, err := s.loggerFor(ctx, resourceKey{
			source:    e.Source,
			subsystem: e.Record.Attributes[AttrSubsystem],
			action:    e.Record.Attributes[AttrAction],
		})
		if err != nil {
			return err
		}

		var r otellog.Record
		ts := e.Record.Timestamp
		if ts.IsZero() {
			ts = now
		}
		r.SetTimestamp(ts)
		r.SetObservedTimestamp(now)
		r.SetBody(otellog.StringValue(e.Record.Body))
		r.SetSeverity(otlpSeverity(e.Record.Severity))
		r.SetSeverityText(otlpSeverityText(e.Record.Severity))
		for k, v := range e.Record.Attributes {
			// `opnsense.source`, `opnsense.subsystem` and `opnsense.action` live on the
			// resource, not the record: emitting them here as well would duplicate them
			// into structured metadata beside the label. (`source` was stripped from
			// Attributes upstream anyway; the pipeline carries it in Entry.Source.)
			if k == AttrSubsystem || k == attrSource || k == AttrAction {
				continue
			}
			r.AddAttributes(otellog.String(k, v))
		}
		rl.logger.Emit(ctx, r)
		touched[rl] = struct{}{}
	}

	// Flush every resource stream touched by this batch and surface the first export
	// failure. errors.Join keeps the others visible in logs without hiding that at
	// least one stream failed — the pipeline treats any non-nil result as "retry".
	var errs []error
	for rl := range touched {
		if err := rl.provider.ForceFlush(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// loggerFor returns the resource-logger bound to key's resource, building it on first
// use. The caller needs both the logger (to emit) and its provider (to ForceFlush).
func (s *otlpSink) loggerFor(ctx context.Context, key resourceKey) (*resourceLogger, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if rl, ok := s.providers[key]; ok {
		return rl, nil
	}
	// Degrade rather than leak: ship under the base resource instead of building an
	// unbounded provider set. The +1 reserves the last slot FOR that base resource,
	// so the cap holds exactly even when the base is itself the provider we are
	// about to create.
	//
	// This is NOT data loss — the record still ships (TestOTLPSink_ResourceCountIsCapped
	// proves it) — but it IS silent label loss: the degraded record has no
	// opnsense.* index labels, so label-scoped queries under-report, and which
	// records lose them depends on arrival order. That is intolerable for
	// forensic/SIEM data, where an under-reporting {opnsense_action="block"} looks
	// exactly like a quiet network. So count it and say so once, loudly.
	if len(s.providers)+1 >= maxLogResources {
		recordResourceCapped()
		s.cappedOnce.Do(func() {
			if s.log == nil {
				return
			}
			s.log.Warn("log resource cardinality cap reached; further records ship without opnsense.* index labels, "+
				"so label-scoped queries will under-report",
				"cap", maxLogResources, "dropped_key", key)
		})
		key = resourceKey{}
		if rl, ok := s.providers[key]; ok {
			return rl, nil
		}
	}

	attrs := make([]attribute.KeyValue, 0, len(s.base)+3)
	attrs = append(attrs, s.base...)
	if key.source != "" {
		attrs = append(attrs, attribute.String(attrSource, key.source))
	}
	if key.subsystem != "" {
		attrs = append(attrs, attribute.String(AttrSubsystem, key.subsystem))
	}
	// Only when set: an unknown disposition must not become opnsense.action="".
	if key.action != "" {
		attrs = append(attrs, attribute.String(AttrAction, key.action))
	}
	res, err := resource.New(ctx, resource.WithAttributes(attrs...))
	if err != nil {
		return nil, fmt.Errorf("build otlp log resource: %w", err)
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		// Every provider exports through the SAME exporter, so partitioning the resource
		// costs no extra connections — and the synchronous processor adds no background
		// queue, so it costs no uncounted buffer either (#290).
		sdklog.WithProcessor(newSyncBatchProcessor(sharedExporter{s.exporter})),
	)
	rl := &resourceLogger{
		provider: provider,
		logger:   provider.Logger("github.com/rknightion/opnsense-exporter/logship"),
	}
	s.providers[key] = rl
	s.order = append(s.order, key)
	return rl, nil
}

// Shutdown drains every provider, THEN closes the shared exporter. The order is
// load-bearing: closing the exporter first would discard whatever the providers
// still had queued.
func (s *otlpSink) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	providers := make([]*resourceLogger, 0, len(s.order))
	for _, k := range s.order {
		providers = append(providers, s.providers[k])
	}
	s.providers = make(map[resourceKey]*resourceLogger)
	s.order = nil
	s.mu.Unlock()

	var errs []error
	for _, rl := range providers {
		if err := rl.provider.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if err := s.exporter.Shutdown(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
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

// otlpSeverityText returns the canonical text for a severity, set on the log record
// alongside the numeric SeverityNumber per the OTel log data model. The original
// syslog keyword is already lost by this point (Severity is the mapped enum), so this
// is the OTLP-canonical name, not the raw syslog word.
func otlpSeverityText(sv Severity) string {
	switch sv {
	case SeverityTrace:
		return "TRACE"
	case SeverityDebug:
		return "DEBUG"
	case SeverityWarn:
		return "WARN"
	case SeverityError:
		return "ERROR"
	case SeverityFatal:
		return "FATAL"
	case SeverityInfo:
		return "INFO"
	default:
		return "INFO"
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

// baseLogAttributes are the identity attributes every log resource carries:
// service.name and service.instance.id (which Loki's DEFAULT OTLP config promotes
// to index labels) plus service.version (which it does not, so it lands in
// structured metadata). loggerFor adds `source` and `subsystem` on top.
//
// No host/SDK resource detectors are added. That is deliberate: a detector would
// contribute host.name, os.type and friends, and any attribute matching Loki's
// default promotion list would silently become part of the label set. Plain
// attribute keys also avoid a schema-URL conflict.
func baseLogAttributes(serviceName, version, instance string) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 3)
	if serviceName != "" {
		attrs = append(attrs, attribute.String(attrServiceName, serviceName))
	}
	if version != "" {
		attrs = append(attrs, attribute.String("service.version", version))
	}
	if instance != "" {
		attrs = append(attrs, attribute.String(attrServiceInstanceID, instance))
	}
	return attrs
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
