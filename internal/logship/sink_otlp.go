package logship

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
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
	collogpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
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

// Emit ships a batch synchronously, ONE RESOURCE PARTITION AT A TIME, and reports per
// entry what the destination did with it (#392).
//
// The old shape emitted every record first, then ForceFlushed the touched providers in
// Go MAP ORDER and joined the errors into one verdict. Two bugs fell out of that. The
// order was nondeterministic, so which partitions had already reached the wire when a
// sibling failed varied run to run. And because the verdict was one error for the whole
// logical batch, the pipeline resent ALL of it — duplicating every partition the server
// had already acknowledged. For firewall/IDS data that is a data-integrity bug: the
// duplicates are indistinguishable from real repeated events.
//
// Now each partition is emitted and flushed on its own, in sorted resourceKey order, and
// each flush is classified independently against the wire outcome observed by the
// transport hook (see deliveryObservation). Only the partitions that genuinely failed
// transiently come back in Retry; an acknowledged sibling is never sent twice.
func (s *otlpSink) Emit(ctx context.Context, batch []Entry) SinkResult {
	if len(batch) == 0 {
		return SinkResult{}
	}
	now := time.Now()

	var res SinkResult
	parts := make(map[resourceKey]*logPartition, len(batch))
	order := make([]resourceKey, 0, len(batch))

	for _, e := range batch {
		rl, eff, err := s.loggerFor(ctx, resourceKey{
			source:    e.Source,
			subsystem: e.Record.Attributes[AttrSubsystem],
			action:    e.Record.Attributes[AttrAction],
		})
		if err != nil {
			// Building the resource failed locally — nothing reached the wire, so this
			// entry is retryable. Per-entry rather than per-batch: a sibling partition
			// that DID build must still get its delivery attempt.
			res.Retry = append(res.Retry, e)
			res.Err = errors.Join(res.Err, err)
			continue
		}
		p, ok := parts[eff]
		if !ok {
			p = &logPartition{rl: rl}
			parts[eff] = p
			order = append(order, eff)
		}
		p.entries = append(p.entries, e)
	}

	// Deterministic flush order (#392). Map iteration order is randomised per range, so
	// without this the set of partitions already delivered when a sibling fails — and
	// therefore what a retry would duplicate — differed on every run, which is
	// untestable as much as it is unsafe.
	sortResourceKeys(order)

	for _, key := range order {
		p := parts[key]
		for _, e := range p.entries {
			var r otellog.Record
			// ObservedTimestamp is "when the collection system observed the event" in the
			// OTel log data model, and the model expects one value per event — not one per
			// delivery attempt. It therefore comes from Entry.Received, stamped once at queue
			// admission, so a batch retried five times ships five byte-identical records
			// instead of five records that disagree about when we saw them (#394).
			//
			// `now` is only the fallback for an Entry that never went through the pipeline's
			// ingest gate (a sink built directly in a test). Shipping a 1970 observed time
			// would be worse than a slightly late one.
			observed := e.Received
			if observed.IsZero() {
				observed = now
			}
			// Timestamp is the event's OWN time, so it stays the source's value. Its fallback
			// is the observed time rather than `now` for the same retry-stability reason: an
			// undated record must not appear to have happened at a different instant on each
			// attempt.
			ts := e.Record.Timestamp
			if ts.IsZero() {
				ts = observed
			}
			r.SetTimestamp(ts)
			r.SetObservedTimestamp(observed)
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
			p.rl.logger.Emit(ctx, r)
		}

		// One ForceFlush == one Export == one wire request carrying exactly this
		// partition, so the observation the transport hook writes describes THIS
		// partition and nothing else. That one-to-one mapping is what makes a
		// partial-success rejected count attributable to a single (source, subsystem,
		// action) resource — and therefore to a single source's counters.
		obs := &deliveryObservation{}
		err := p.rl.provider.ForceFlush(withDeliveryObservation(ctx, obs))
		classifyPartition(p.entries, obs, err, &res)
	}
	return res
}

// logPartition is one resource stream's share of a batch: the entries destined for a
// single resourceKey, and the logger/provider that ships them.
type logPartition struct {
	rl      *resourceLogger
	entries []Entry
}

// sortResourceKeys orders keys by (source, subsystem, action) so partition flushes
// happen in a stable, reproducible sequence regardless of arrival order.
func sortResourceKeys(keys []resourceKey) {
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.source != b.source {
			return a.source < b.source
		}
		if a.subsystem != b.subsystem {
			return a.subsystem < b.subsystem
		}
		return a.action < b.action
	})
}

// classifyPartition folds one partition's flush outcome into res.
//
// The DECISION comes from the wire observation, not from the error value: the pinned
// exporter reports partial success, permanent rejection and transient failure through
// one opaque `error` whose distinguishing types (partialsuccess, retryableError) are
// all under vendor `internal/`, and matching their message text is explicitly out of
// bounds. The transport hook records the HTTP status / gRPC code — and any populated
// partial-success payload — before the SDK collapses them, so this classifies from the
// protocol rather than from prose.
func classifyPartition(entries []Entry, obs *deliveryObservation, err error, res *SinkResult) {
	if len(entries) == 0 {
		return
	}
	outcome, rejected := obs.result()

	switch outcome {
	case outcomePartial:
		// TERMINAL, always — the OTLP spec forbids resending a request the server
		// answered with a populated partial_success, because it already accepted the
		// records it did not reject. Resending is precisely the duplication bug.
		//
		// The protocol reports a rejected COUNT, never identities, so the split is by
		// count from the tail of the partition. Both halves are terminal and every entry
		// in the partition shares a source, so the per-source counters land exactly
		// right; see the caveat on SinkResult.Rejected for what this must NOT be read as.
		n := int(rejected)
		if n < 0 {
			n = 0
		}
		if n > len(entries) {
			// A server claiming it rejected more records than the request contained is
			// out of contract. Clamp, rather than letting the arithmetic under-run and
			// count a negative number of deliveries.
			n = len(entries)
		}
		split := len(entries) - n
		res.Acked = append(res.Acked, entries[:split]...)
		res.Rejected = append(res.Rejected, entries[split:]...)
		res.Err = errors.Join(res.Err, err)
	case outcomePermanent:
		// HTTP 400, gRPC InvalidArgument/Unauthenticated and friends: one attempt, then
		// counted and dropped. Retrying an identical request against a permanent refusal
		// cannot succeed, and doing so used to burn the whole --logs.ship-max-attempts
		// budget (10 wire requests by default) before reaching the same conclusion.
		res.Rejected = append(res.Rejected, entries...)
		res.Err = errors.Join(res.Err, err)
	case outcomeAccepted:
		res.Acked = append(res.Acked, entries...)
	default:
		// outcomeRetryable, and outcomeUnknown. Unknown means no wire outcome was observed
		// at all — a marshalling failure, a request the SDK refused to send, or a sink
		// built over a bare exporter in a test. err==nil there is a successful export;
		// err!=nil is treated as retryable, because the safer of the two possible mistakes
		// (one bounded extra attempt) beats discarding records we cannot prove were refused.
		if outcome == outcomeUnknown && err == nil {
			res.Acked = append(res.Acked, entries...)
			return
		}
		res.Retry = append(res.Retry, entries...)
		res.Err = errors.Join(res.Err, err)
	}
}

// loggerFor returns the resource-logger bound to key's resource, building it on first
// use, together with the EFFECTIVE key it was filed under. The effective key differs
// from the requested one only when the cardinality cap collapsed it onto the base
// resource; Emit groups by the effective key so two collapsed keys share one partition
// — and therefore one flush — instead of flushing the same provider twice and having
// the second flush observe an already-drained, trivially "successful" buffer.
func (s *otlpSink) loggerFor(ctx context.Context, key resourceKey) (*resourceLogger, resourceKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if rl, ok := s.providers[key]; ok {
		return rl, key, nil
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
			return rl, key, nil
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
		return nil, key, fmt.Errorf("build otlp log resource: %w", err)
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
	return rl, key, nil
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

// ---------------------------------------------------------------------------
// Delivery observation: the supported error-classification seam (#392)
// ---------------------------------------------------------------------------
//
// WHY THIS EXISTS AT ALL. The pinned otlplog exporters (v0.20.0) expose NO public API
// for classifying a delivery outcome. Every distinguishing type is unreachable:
//
//   - vendor/go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp/internal/
//     partialsuccess.go and the otlploggrpc twin are under internal/, so this package
//     cannot import them;
//   - otlploghttp/client.go's retryableError, which marks 429/502/503/504, is
//     unexported;
//   - both Exporter.Export methods return a bare error.
//
// Matching the vendor's error TEXT is explicitly ruled out — it is unversioned prose
// that would silently start misclassifying on any upstream reword, i.e. exactly the
// failure mode that is hardest to notice. So the classification is taken from the
// TRANSPORT instead, one layer below the SDK, using the two injection points the pinned
// exporters do support:
//
//   - HTTP: otlploghttp.WithHTTPClient (config.go:382) accepts an *http.Client, so an
//     http.RoundTripper sees the real status code and the raw partial-success body
//     before the SDK folds them into an error.
//   - gRPC: otlploggrpc.WithDialOption (config.go:318) accepts arbitrary
//     grpc.DialOptions, so a unary client interceptor sees the reply message and the
//     gRPC status code before the SDK converts them.
//
// Each hook writes its finding into a deliveryObservation carried on the export
// context, which classifyPartition then reads. The values are OUR types, derived from
// the protocol, so nothing here depends on vendor internals or vendor wording.

// deliveryOutcome is what the destination did with one export request.
type deliveryOutcome int

const (
	// outcomeUnknown means no wire outcome was observed: the request never reached a
	// transport (marshalling failure, oversize request), or the sink is running over a
	// bare exporter with no transport at all, as in unit tests.
	outcomeUnknown deliveryOutcome = iota
	// outcomeAccepted is a clean success: 2xx with no partial-success payload, or gRPC OK.
	outcomeAccepted
	// outcomePartial is a populated OTLP partial_success. TERMINAL: the spec forbids
	// resending this exact request.
	outcomePartial
	// outcomePermanent is a response that will not change on retry: any non-2xx HTTP
	// status outside the retryable set (400 and friends), or a non-retryable gRPC code
	// such as InvalidArgument or Unauthenticated.
	outcomePermanent
	// outcomeRetryable is a genuinely transient failure: HTTP 429/502/503/504, the
	// retryable gRPC codes, or a transport-level error (refused connection, TLS
	// failure, timeout).
	outcomeRetryable
)

// deliveryObservation is the side channel between the transport hook and
// classifyPartition. It is created per ForceFlush and reachable only through that
// flush's context, so observations from concurrent flushes cannot collide.
//
// The SDK may make SEVERAL round trips inside one Export (it applies its own bounded
// retry to 429/502/503/504). Each is recorded, and the LAST one wins — that is the
// outcome the SDK ultimately acted on, and the one whose verdict the pipeline must
// inherit. A flush that retried 503 three times and gave up therefore reads retryable,
// while one that retried twice and then got a 200 with partial success reads partial.
type deliveryObservation struct {
	mu       sync.Mutex
	outcome  deliveryOutcome
	rejected int64
}

func (o *deliveryObservation) record(outcome deliveryOutcome, rejected int64) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.outcome = outcome
	o.rejected = rejected
}

// result reads the observation back. A nil receiver reports outcomeUnknown so callers
// never need a nil check.
func (o *deliveryObservation) result() (deliveryOutcome, int64) {
	if o == nil {
		return outcomeUnknown, 0
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.outcome, o.rejected
}

// deliveryObservationCtxKey is an unexported struct key, so nothing outside this
// package can set or shadow the observation.
type deliveryObservationCtxKey struct{}

func withDeliveryObservation(ctx context.Context, o *deliveryObservation) context.Context {
	return context.WithValue(ctx, deliveryObservationCtxKey{}, o)
}

// deliveryObservationFrom returns the observation attached to ctx, or nil when the
// caller is not a log export (the same transport could, in principle, carry other
// traffic) — in which case the hooks record nothing at all.
func deliveryObservationFrom(ctx context.Context) *deliveryObservation {
	o, _ := ctx.Value(deliveryObservationCtxKey{}).(*deliveryObservation)
	return o
}

// maxObservedResponseBytes bounds how much of a response body the HTTP hook will buffer
// to look for a partial-success payload. A real OTLP response is a few dozen bytes; the
// cap only stops a hostile or broken endpoint from making us hold an arbitrary body in
// memory. Past it the hook stops parsing and the SDK's own 4 MiB reader deals with the
// rest.
const maxObservedResponseBytes = 1 << 20

// observingTransport is the HTTP arm of the seam. It classifies from the status line —
// the protocol's own statement of what happened — and, on success, from the
// partial-success payload, then passes the response through untouched.
type observingTransport struct{ base http.RoundTripper }

func (t *observingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)

	obs := deliveryObservationFrom(req.Context())
	if obs == nil {
		return resp, err
	}
	if err != nil || resp == nil {
		// No response at all: connection refused, TLS failure, timeout. The endpoint may
		// well come back, so this is transient.
		obs.record(outcomeRetryable, 0)
		return resp, err
	}

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
		obs.record(observeHTTPSuccessBody(resp))
	case resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode == http.StatusBadGateway,
		resp.StatusCode == http.StatusServiceUnavailable,
		resp.StatusCode == http.StatusGatewayTimeout:
		// The exact retryable set named by the OTLP spec, and the same set the pinned
		// exporter retries internally.
		obs.record(outcomeRetryable, 0)
	default:
		// Everything else — 400, 401, 403, 404, 413, 501 … — is permanent. Repeating a
		// byte-identical request cannot change the answer.
		obs.record(outcomePermanent, 0)
	}
	return resp, err
}

// observeHTTPSuccessBody inspects a 2xx body for a populated partial_success, replacing
// resp.Body with an equivalent reader so the SDK still parses it normally. It returns
// outcomeAccepted whenever it cannot prove otherwise: guessing "partial" would strand
// records as terminally rejected on no evidence.
func observeHTTPSuccessBody(resp *http.Response) (deliveryOutcome, int64) {
	if resp.Body == nil {
		return outcomeAccepted, 0
	}
	buf, readErr := io.ReadAll(io.LimitReader(resp.Body, maxObservedResponseBytes))
	// Put the bytes back in front of whatever remains, keeping the original Closer so
	// the SDK's deferred Close still releases the connection.
	resp.Body = &replayBody{
		Reader: io.MultiReader(bytes.NewReader(buf), resp.Body),
		Closer: resp.Body,
	}
	if readErr != nil || len(buf) == 0 || int64(len(buf)) >= maxObservedResponseBytes {
		return outcomeAccepted, 0
	}
	if resp.Header.Get("Content-Type") != "application/x-protobuf" {
		return outcomeAccepted, 0
	}
	var pb collogpb.ExportLogsServiceResponse
	if err := proto.Unmarshal(buf, &pb); err != nil {
		return outcomeAccepted, 0
	}
	ps := pb.GetPartialSuccess()
	if ps == nil {
		return outcomeAccepted, 0
	}
	// An error_message with a zero rejected count is still a partial success per the
	// spec, and the pinned exporter reports it as an error, so it must be terminal here
	// too — otherwise the pipeline would retry a request the server said not to.
	if ps.GetRejectedLogRecords() == 0 && ps.GetErrorMessage() == "" {
		return outcomeAccepted, 0
	}
	return outcomePartial, ps.GetRejectedLogRecords()
}

// replayBody re-serves already-buffered bytes ahead of the untouched remainder of a
// response body while keeping the original Closer.
type replayBody struct {
	io.Reader
	io.Closer
}

// observingUnaryInterceptor is the gRPC arm of the seam. Unlike HTTP there is no body
// to buffer: the reply message is materialised by the invoker, so partial success is
// readable directly, and the status code is available before the SDK converts it.
func observingUnaryInterceptor(
	ctx context.Context,
	method string,
	req, reply any,
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	err := invoker(ctx, method, req, reply, cc, opts...)

	obs := deliveryObservationFrom(ctx)
	if obs == nil {
		return err
	}
	if lr, ok := reply.(*collogpb.ExportLogsServiceResponse); ok {
		if ps := lr.GetPartialSuccess(); ps != nil &&
			(ps.GetRejectedLogRecords() != 0 || ps.GetErrorMessage() != "") {
			obs.record(outcomePartial, ps.GetRejectedLogRecords())
			return err
		}
	}
	switch status.Code(err) {
	case codes.OK:
		obs.record(outcomeAccepted, 0)
	case codes.Canceled,
		codes.DeadlineExceeded,
		codes.Aborted,
		codes.OutOfRange,
		codes.Unavailable,
		codes.DataLoss,
		codes.ResourceExhausted:
		// The OTLP spec's retryable gRPC set. ResourceExhausted is included here even
		// though the SDK only retries it when the server attaches RetryInfo: our retry
		// is bounded by --logs.ship-max-attempts with backoff, so treating a quota
		// signal as transient costs a few attempts, whereas treating it as permanent
		// would discard records the endpoint would have taken a moment later.
		obs.record(outcomeRetryable, 0)
	default:
		// InvalidArgument, Unauthenticated, PermissionDenied, Unimplemented …: the
		// request is wrong or the credentials are, and neither is fixed by repeating it.
		obs.record(outcomePermanent, 0)
	}
	return err
}

// newLogExporter builds an OTLP log exporter for the configured protocol,
// mirroring the metrics exporter's option handling. Empty fields are omitted so
// the SDK falls back to the standard OTEL_EXPORTER_OTLP_* env vars.
//
// Both branches install the delivery-observation hook described above; without it every
// failure would read as generic-and-retryable, which is the pre-#392 behaviour.
func newLogExporter(ctx context.Context, cfg *options.OTLPConfig) (sdklog.Exporter, error) {
	tlsCfg, err := buildLogTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	switch cfg.Protocol {
	case "grpc":
		opts := []otlploggrpc.Option{
			otlploggrpc.WithDialOption(grpc.WithChainUnaryInterceptor(observingUnaryInterceptor)),
		}
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
		// WithHTTPClient takes precedence over WithTLSClientConfig, WithProxy and
		// WithTimeout (and their OTEL_EXPORTER_OTLP_*CERTIFICATE / *TIMEOUT env vars), so
		// supplying a client means owning all of that here. buildLogTLSConfig and
		// logExportTimeout resolve the same env vars the SDK would have, so the only
		// behaviour that changes is that we can now see the response.
		client, err := newObservingHTTPClient(cfg, tlsCfg)
		if err != nil {
			return nil, err
		}
		opts := []otlploghttp.Option{otlploghttp.WithHTTPClient(client)}
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
		return otlploghttp.New(ctx, opts...)
	default:
		return nil, fmt.Errorf("unsupported otlp protocol %q", cfg.Protocol)
	}
}

// newObservingHTTPClient builds the *http.Client handed to otlploghttp: the SDK's own
// default transport settings, plus our TLS config, wrapped in the observing
// RoundTripper.
func newObservingHTTPClient(cfg *options.OTLPConfig, tlsCfg *tls.Config) (*http.Client, error) {
	if cfg.Insecure && tlsCfg != nil {
		// The SDK refuses this combination (errInsecureEndpointWithTLS) and it stops
		// doing that check once we supply the client, so keep the fail-fast here: a
		// plaintext endpoint configured with certificates is a misconfiguration the
		// operator wants to hear about at startup, not a silently ignored setting.
		return nil, fmt.Errorf("otlp logs: an insecure (plaintext) endpoint cannot also use TLS client " +
			"configuration; drop --otlp.insecure or the --otlp.tls-* files")
	}
	// http.DefaultTransport's settings mirror the exporter's own private copy
	// (ProxyFromEnvironment, 30s dial timeout, HTTP/2 attempted); cloning keeps proxy
	// behaviour identical to what the SDK would have used.
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("otlp logs: http.DefaultTransport is not an *http.Transport (%T)", http.DefaultTransport)
	}
	base := tr.Clone()
	if tlsCfg != nil {
		base.TLSClientConfig = tlsCfg
	}
	return &http.Client{
		Transport: &observingTransport{base: base},
		Timeout:   logExportTimeout(),
	}, nil
}

// logExportTimeout reproduces the exporter's own timeout resolution, which
// WithHTTPClient would otherwise bypass: OTEL_EXPORTER_OTLP_LOGS_TIMEOUT, then
// OTEL_EXPORTER_OTLP_TIMEOUT (both in MILLISECONDS), else the SDK's 10s default.
// A malformed or non-positive value falls back to the default rather than disabling the
// timeout, which is what a zero would do.
func logExportTimeout() time.Duration {
	const defaultTimeout = 10 * time.Second
	for _, env := range []string{"OTEL_EXPORTER_OTLP_LOGS_TIMEOUT", "OTEL_EXPORTER_OTLP_TIMEOUT"} {
		raw := strings.TrimSpace(os.Getenv(env))
		if raw == "" {
			continue
		}
		ms, err := strconv.Atoi(raw)
		if err != nil || ms <= 0 {
			continue
		}
		return time.Duration(ms) * time.Millisecond
	}
	return defaultTimeout
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
//
// The flags win; where a flag is unset it falls back to the same OTEL_EXPORTER_OTLP_*
// certificate env vars the SDK consults. That fallback is NOT decoration: the HTTP path
// now supplies its own *http.Client (see newObservingHTTPClient), and WithHTTPClient
// takes precedence over the SDK's env-derived TLS, so without resolving them here an
// operator who configured certificates purely by environment would silently lose them.
func buildLogTLSConfig(cfg *options.OTLPConfig) (*tls.Config, error) {
	caFile := cfg.TLSCAFile
	if caFile == "" {
		caFile = firstEnv("OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE", "OTEL_EXPORTER_OTLP_CERTIFICATE")
	}
	certFile, keyFile := cfg.TLSCertFile, cfg.TLSKeyFile
	if certFile == "" && keyFile == "" {
		certFile = firstEnv("OTEL_EXPORTER_OTLP_LOGS_CLIENT_CERTIFICATE", "OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE")
		keyFile = firstEnv("OTEL_EXPORTER_OTLP_LOGS_CLIENT_KEY", "OTEL_EXPORTER_OTLP_CLIENT_KEY")
	}
	if caFile == "" && certFile == "" && keyFile == "" {
		return nil, nil
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

// firstEnv returns the first non-empty environment variable among names.
func firstEnv(names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return v
		}
	}
	return ""
}
