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

	"github.com/rknightion/opnsense2otel/v4/internal/options"
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
// Every dimension of the resource key is a closed set (see shape_attrs.go), so the
// cap is not a cardinality control — it is a backstop against a future Source that
// put something wire-derived behind one of the keys, which would otherwise leak
// providers here and, once a tenant promotes the attribute, explode Loki's label
// cardinality.
//
// It is NOT set by arithmetic over the vocabularies. The key count is the product of
// five dimensions, but the OBSERVED product is far smaller than the theoretical one,
// because most combinations never occur — a printer does not appear on the WAN, a
// syslog record has no device at all. So the number is anchored to measurement: 79
// distinct keys over an hour on the live box (#473), pinned as
// observedResourceCombos, and the cap is 3x that. The headroom absorbs normal churn
// — a new VLAN, a device category Zenarmor has not classified before — without
// walking into the degrade path.
//
// That degrade path is why overshooting is worse than it sounds. Past the cap we
// fall back to the BASE resource: records still ship, but with no opnsense.*
// attributes at all. So a cap set too low does not merely fail to add the two new
// labels, it destroys the three that already work. Raising this alongside a new key
// is not optional; TestOTLPSink_ResourceKeyBudgetHasHeadroomOverObserved enforces it.
const maxLogResources = 256

// otlpMaxRequestBytes is the serialized-request ceiling we PIN on the HTTP exporter
// rather than inheriting (#506). It is the SDK's own current default
// (vendor/…/otlploghttp/config.go:29), pinned so that it and maxExportBytes below cannot
// drift apart on a dependency bump — the whole point of the pair is the relationship
// between them, and a silently-lowered SDK default would break it with no signal.
//
// The exporter checks this against the UNCOMPRESSED marshalled protobuf
// (vendor/…/otlploghttp/client.go:159-178) and only gzips afterwards, in newRequest — so
// the gzip default does NOT buy headroom here.
const otlpMaxRequestBytes = 64 << 20

// maxExportBytes bounds one drained batch, and therefore every partition split out of it,
// so a request that the exporter would refuse to send is never built (#506).
//
// It is HALF the wire ceiling on purpose. recordBytes (queue.go) estimates the RETAINED
// size of a record — body, source, attributes, plus fixed overhead allowances — which is
// a proxy for the marshalled protobuf size, not a measurement of it. Protobuf adds field
// tags and length prefixes we do not model. A 2x margin absorbs that difference instead
// of betting that the estimate is conservative in every payload shape.
//
// IT IS NOT THE ONLY BATCH BOUND, and since #663 it is not the one that normally binds.
// This constant answers "what will the OTLP exporter agree to SEND"; a Loki tenant's
// ingestion limit is a bytes-per-SECOND budget, which is a different constraint entirely
// — a 7.5 MB push is worth many seconds of that budget and is refused atomically however
// long we wait, while being comfortably under 32 MiB. --logs.max-export-bytes carries the
// ingest-rate bound (default 1 MiB) and pipeline.exportByteBound takes the min of the two,
// so this stays the hard transport backstop and never has to double as a rate bound.
const maxExportBytes = 32 << 20

// otlpRetryPolicy PINS the exporter's own retry loop instead of inheriting it (#663).
// Both branches of newLogExporter install it.
//
// THERE ARE TWO NESTED RETRY LAYERS AND ONLY ONE OF THEM WAS EVER VISIBLE. The SDK
// default is InitialInterval 5s / MaxInterval 30s / MaxElapsedTime 1 MINUTE
// (vendor/…/otlploghttp/internal/retry/retry.go), applied INSIDE one Export call — so a
// single Emit could burn a minute plus a 10s request timeout before returning, and the
// pipeline then counted that as ONE attempt and did it nine more times. Worst case on an
// undeliverable batch was --logs.ship-max-attempts × (SDK max-elapsed + timeout) ≈ 700s,
// which is the ~8 minutes observed on the live box. The pipeline's own 5s-capped backoff
// was irrelevant noise beside it, and nothing in the code related the two.
//
// The SDK layer is KEPT, not removed: riding out a single transient 503 inside one Export
// is genuinely cheaper than handing the batch back for a whole logical delivery round,
// and TestOTLPSink_HTTPTransientThenRecoveryAcknowledgesOnce is the contract that says so.
// What changes is that it is now pinned SMALL — one to two quick in-Export retries, not a
// minute — so that the composition of the two layers is a number that can be written down.
// The bound is derived in full on pipeline.shipBatch.
//
// It also must not swallow the rate-limit signal for long: on a 429 the SDK honours
// Retry-After itself, and with the default minute-long budget an advertised 30s delay
// would be slept INSIDE Export where the pipeline cannot see it, split the batch, or do
// anything else useful.
var otlpRetryPolicy = struct {
	InitialInterval time.Duration
	MaxInterval     time.Duration
	MaxElapsedTime  time.Duration
}{
	InitialInterval: 500 * time.Millisecond,
	MaxInterval:     2 * time.Second,
	MaxElapsedTime:  5 * time.Second,
}

// otlpSink ships records over OTLP logs. It reuses the exporter's --otlp.*
// transport family. Each provider's syncBatchProcessor (#290) exports synchronously and
// returns the real export error, so the pipeline's own bounded queue is the single
// COUNTED backpressure valve and delivery is observable — there is no second, silent SDK
// batch queue in front of the wire. The exporter still applies its own transient
// retry/backoff, but PINNED small (otlpRetryPolicy, #663) so it composes with
// --logs.ship-max-attempts into a bounded worst case instead of multiplying against it;
// a returned error means it gave up, and the pipeline retries the batch.
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
// The providers share ONE HTTP CLIENT, so resource partitioning costs no extra
// connection pool — but NOT one exporter: there is one exporter per concurrent worker,
// because an exporter is not re-entrant. See newLogExporters.
//
// The pre-1.0 otel logs SDK is deliberately confined to this file (pinned +
// Renovate) so the rest of the codebase never imports it.
type otlpSink struct {
	// exporters holds one exporter per concurrent worker — an exporter is not
	// re-entrant, so concurrent flushes must not share one. See newLogExporters.
	// exporter is exporters[0] and is only the fallback for a flush that arrives
	// without a leased exporter on its context (a provider ForceFlushed outside Emit,
	// e.g. at Shutdown, where nothing is concurrent).
	exporters []sdklog.Exporter
	exporter  sdklog.Exporter
	base      []attribute.KeyValue
	log       *slog.Logger
	// concurrency bounds how many of a batch's resource partitions are exported at
	// once. Always >= 1; see newOTLPSink for why the floor is applied there rather
	// than trusted from config.
	concurrency int

	mu        sync.Mutex
	providers map[resourceKey]*resourceLogger
	order     []resourceKey // creation order, so Shutdown is deterministic
	// cappedOnce keeps the cardinality-cap warning to one line per process. The
	// counter carries the ongoing rate; the log line is there so the first
	// occurrence is discoverable without already knowing to look for the metric.
	cappedOnce sync.Once
}

// resourceKey identifies one OTLP resource. Every field is a closed set — see
// AttrSubsystem, AttrAction and shape_attrs.go for what "closed" rests on in each
// case. Adding a field multiplies the key count against maxLogResources.
type resourceKey struct{ source, subsystem, action, deviceCategory, iface string }

type resourceLogger struct {
	provider *sdklog.LoggerProvider
	logger   otellog.Logger
}

// sharedExporter lends a real exporter to many LoggerProviders. Shutdown is
// suppressed: a provider shutting down would otherwise close the exporter out from
// under its siblings, and whichever of them still had records queued would fail to
// flush them. otlpSink.Shutdown closes every real exporter once, after every provider
// has drained.
//
// What a provider holds through this wrapper is only the FALLBACK exporter. A flush
// dispatched by Emit's worker pool carries its own leased exporter on the context and
// uses that instead (see syncBatchProcessor.export), which is what keeps concurrent
// Export calls off a single instance.
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
	// Prefer the exporter leased to this flush. Emit's worker pool leases a distinct one
	// per concurrent worker precisely so no two concurrent Export calls land on the same
	// exporter instance, which the SDK forbids. p.exporter is the fallback for flushes
	// that did not come from the pool, where nothing is concurrent.
	exporter := p.exporter
	if leased := leasedExporterFrom(ctx); leased != nil {
		exporter = leased
	}
	return exporter.Export(ctx, batch)
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
// concurrency is the maximum number of resource partitions exported at once; it is
// floored at 1 HERE rather than trusted from the caller, because a Sink built directly
// in a test (or from a LogsConfig struct literal that never went through Validate)
// leaves it zero-valued, and a zero would size the worker pool at nothing and deadlock.
func newOTLPSink(cfg *options.OTLPConfig, version, instance string, concurrency int, log *slog.Logger) (Sink, error) {
	if !endpointResolvable(cfg.Endpoint) {
		return nil, fmt.Errorf("logs sink=otlp requires an OTLP endpoint: set --otlp.endpoint " +
			"(or --otlp.grafana-cloud-endpoint, or the OTEL_EXPORTER_OTLP_ENDPOINT / " +
			"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT environment variable)")
	}
	if concurrency < 1 {
		concurrency = 1
	}

	exporters, err := newLogExporters(context.Background(), cfg, concurrency)
	if err != nil {
		return nil, fmt.Errorf("build otlp log exporter: %w", err)
	}

	return &otlpSink{
		exporters:   exporters,
		exporter:    exporters[0],
		log:         log,
		concurrency: concurrency,
		base:        baseLogAttributes(cfg.ServiceName, version, instance),
		providers:   make(map[resourceKey]*resourceLogger),
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
			source:         e.Source,
			subsystem:      e.Record.Attributes[AttrSubsystem],
			action:         e.Record.Attributes[AttrAction],
			deviceCategory: e.Record.Attributes[AttrDeviceCategory],
			iface:          e.Record.Attributes[AttrInterface],
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

	// Deterministic MERGE order (#392, revised in #505). Map iteration order is
	// randomised per range, so without this the accounting depended on which range the
	// runtime happened to produce. It used to also fix wire order, because partitions
	// were flushed one after another; they are now flushed concurrently, so wire order
	// is genuinely nondeterministic and no longer something to preserve. What #392
	// actually needs is that an ACKNOWLEDGED partition is never resent, and concurrency
	// strengthens that rather than weakening it: every partition is attempted on every
	// pass, so none is left in an ambiguous "might have reached the wire" state because
	// a sibling failed first. Sorting now orders the result merge below, which is what
	// keeps SinkResult reproducible.
	sortResourceKeys(order)

	// Flush the partitions through a bounded worker pool. Each partition is a separate
	// synchronous wire request, so a sequential loop cost one full round-trip per
	// partition and capped throughput at (batch size / partitions) / latency — measured
	// at ~125 records/sec against a live Grafana Cloud tenant, below the sustained
	// ingest rate, which is what drove the queue into permanent oldest-drop (#505).
	//
	// THE INVARIANT THIS RESTS ON: one provider is never flushed twice concurrently.
	// syncBatchProcessor.export swaps out the whole buffer, so two concurrent flushes of
	// one provider would have each ship the other's records and observe a wire outcome
	// that never described what it sent. Grouping by the EFFECTIVE key above guarantees
	// one partition per provider per Emit — including when the cardinality cap collapses
	// several keys onto the base resource — which is why that grouping is now a
	// correctness invariant and not just an accounting nicety. It is what makes
	// per-partition concurrency safe here and why the QUEUE drain is deliberately not
	// parallelised instead: two concurrent batches would overlap on hot resource keys.
	//
	// Each worker writes its own SinkResult into its own slot, so nothing is shared: the
	// three entry slices and the joined error are merged single-threaded afterwards.
	// deliveryObservation is already per-flush and reachable only through that flush's
	// context, so it needs no change.
	//
	// Floor the pool size here as well as in newOTLPSink. otlpSink is constructed
	// directly in tests, which leaves concurrency zero-valued, and a zero-buffered token
	// channel would block on the first send and deadlock the emitter goroutine for the
	// life of the process. A silent single-partition-at-a-time fallback is the right
	// failure mode for a field nobody set; a hang is not.
	poolSize := s.concurrency
	if poolSize < 1 {
		poolSize = 1
	}
	if poolSize > len(order) {
		poolSize = len(order)
	}
	// Tokens carry an exporter INDEX rather than being empty structs. Holding a token is
	// what grants exclusive use of exporters[idx] for the length of one flush, so at most
	// poolSize flushes run and no two of them share an exporter — which is the whole
	// reason there is more than one. Pre-filled, so a worker takes an index and puts it
	// back rather than deriving one from loop position.
	results := make([]SinkResult, len(order))
	tokens := make(chan int, poolSize)
	for i := range poolSize {
		tokens <- i
	}
	var wg sync.WaitGroup

	for i, key := range order {
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
			// #475 looked at dropping this: Loki renders it as an `observed_timestamp`
			// structured-metadata key, 37 B on every line, distinct-per-line by
			// construction so it never aggregates. It is NOT removable from this side.
			// Loki emits it whenever both timestamps are set (otlplabels/labels.go), and
			// the SDK stamps ObservedTimestamp itself at Emit when the caller leaves it
			// zero — so the only way to suppress it is to stop setting the EVENT time,
			// which would replace every Zenarmor flow's close time with our receive time.
			// The lever for it is tenant-side, not here.
			r.SetObservedTimestamp(observed)
			r.SetBody(attribute.StringValue(e.Record.Body))
			// Severity costs ~33 B/line as Loki's severity_number + severity_text, and it
			// measured single-valued on the sampled Zenarmor streams — but that is the
			// sample, not the field: SeverityWarn is what a blocked Zenarmor record and
			// every syslog error carry, and it is what Loki's level detection reads to
			// populate detected_level. Dropping it would flatten the one severity signal
			// the whole log estate has, to save 0.4% of volume. Kept on purpose (#475).
			r.SetSeverity(otlpSeverity(e.Record.Severity))
			r.SetSeverityText(otlpSeverityText(e.Record.Severity))
			for k, v := range e.Record.Attributes {
				// The hoisted keys live on the resource, not the record: emitting them here
				// as well would duplicate them into structured metadata beside the label.
				// (`source` was stripped from Attributes upstream anyway; the pipeline
				// carries it in Entry.Source.) Each lane's OWN verbatim keys —
				// `device.category`, `interface.name` — are a different key space and are
				// deliberately left alone, so queries against them keep working.
				if k == AttrSubsystem || k == attrSource || k == AttrAction ||
					k == AttrDeviceCategory || k == AttrInterface {
					continue
				}
				r.AddAttributes(attribute.String(k, v))
			}
			p.rl.logger.Emit(ctx, r)
		}

		// One ForceFlush == one Export == one wire request carrying exactly this
		// partition, so the observation the transport hook writes describes THIS
		// partition and nothing else. That one-to-one mapping is what makes a
		// partial-success rejected count attributable to a single (source, subsystem,
		// action) resource — and therefore to a single source's counters.
		//
		// The records are already buffered in this partition's processor by the loop
		// above, so handing the flush to a worker cannot interleave with another
		// partition's Emit calls.
		wg.Add(1)
		expIdx := <-tokens
		go func(slot, expIdx int, p *logPartition) {
			defer wg.Done()
			defer func() { tokens <- expIdx }()
			obs := &deliveryObservation{}
			fctx := withLeasedExporter(withDeliveryObservation(ctx, obs), s.exporterAt(expIdx))
			err := p.rl.provider.ForceFlush(fctx)
			classifyPartition(p.entries, obs, err, &results[slot])
		}(i, expIdx, p)
	}
	wg.Wait()

	// Merge in sorted key order, so SinkResult is byte-for-byte reproducible for a given
	// batch regardless of the order the flushes actually completed in.
	for i := range results {
		res.Acked = append(res.Acked, results[i].Acked...)
		res.Rejected = append(res.Rejected, results[i].Rejected...)
		res.Retry = append(res.Retry, results[i].Retry...)
		res.Err = errors.Join(res.Err, results[i].Err)
	}
	return res
}

// exporterAt returns the exporter for a worker slot, or nil when the sink was built
// without a pool (constructed directly in a test), in which case the processor falls back
// to its own. Tolerating a short pool here rather than indexing blindly keeps a
// directly-constructed sink working instead of panicking on the first Emit.
func (s *otlpSink) exporterAt(i int) sdklog.Exporter {
	if i < 0 || i >= len(s.exporters) {
		return nil
	}
	return s.exporters[i]
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
		if a.action != b.action {
			return a.action < b.action
		}
		if a.deviceCategory != b.deviceCategory {
			return a.deviceCategory < b.deviceCategory
		}
		return a.iface < b.iface
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
	case outcomeRateLimited:
		// Retryable, but NOT by resending this request unchanged — it was refused for
		// its size against a bytes/sec budget. The entries go back for another attempt
		// and the rateLimitError tells the pipeline to split and pace them (#663).
		res.Retry = append(res.Retry, entries...)
		res.Err = errors.Join(res.Err, &rateLimitError{retryAfter: obs.throttle(), err: err})
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

	attrs := make([]attribute.KeyValue, 0, len(s.base)+5)
	attrs = append(attrs, s.base...)
	if key.source != "" {
		attrs = append(attrs, attribute.String(attrSource, key.source))
	}
	if key.subsystem != "" {
		attrs = append(attrs, attribute.String(AttrSubsystem, key.subsystem))
	}
	// Only when set, for all three below: an absent value must stay ABSENT rather
	// than become opnsense.action="" / opnsense.interface="". An empty string reads
	// as a real value in LogQL, so present-and-empty is a lie — an unknown firewall
	// disposition would match {opnsense_action=""} as if it were a classification,
	// and every syslog record (which has no device and no interface at all) would
	// join one enormous empty-valued stream.
	if key.action != "" {
		attrs = append(attrs, attribute.String(AttrAction, key.action))
	}
	if key.deviceCategory != "" {
		attrs = append(attrs, attribute.String(AttrDeviceCategory, key.deviceCategory))
	}
	if key.iface != "" {
		attrs = append(attrs, attribute.String(AttrInterface, key.iface))
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
		// EMPTY SCOPE NAME, DELIBERATELY (#475). Loki's OTLP handler appends the
		// instrumentation scope name as structured metadata on EVERY record, gated only
		// on it being non-empty (pkg/loghttp/push/otlplabels/labels.go: `if scopeName :=
		// scope.Name(); scopeName != ""`), and structured metadata is billed as ingested
		// volume. The old value, this module's import path, measured 57 B/line at exactly
		// one distinct value across every family — ~140 MB/day of the same string on the
		// Zenarmor stream alone, for a distinction that does not exist: this binary ships
		// logs from one scope, and service.name already identifies the producer.
		//
		// Empty is the only value Loki treats as "omit"; shortening it just makes the
		// repetition cheaper. Give it a name again only when a second scope appears and
		// telling them apart is worth the bytes.
		logger: provider.Logger(""),
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
	// Close every exporter in the pool, not just exporters[0]. Each owns its own
	// transport state, and on gRPC its own client connection, so missing one leaks a
	// connection for the life of the process.
	shut := s.exporters
	if len(shut) == 0 && s.exporter != nil {
		shut = []sdklog.Exporter{s.exporter}
	}
	for _, e := range shut {
		if err := e.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
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
	// outcomeRetryable is a genuinely transient failure: HTTP 502/503/504, the
	// retryable gRPC codes, or a transport-level error (refused connection, TLS
	// failure, timeout). A byte-identical resend is the right response.
	outcomeRetryable
	// outcomeRateLimited is a RATE-limit refusal: HTTP 429, or gRPC RESOURCE_EXHAUSTED
	// (#663). Split out of outcomeRetryable because the correct response is materially
	// different. The other retryable outcomes mean "the endpoint could not take this
	// right now"; this one means "this request is too much AT ONCE for a bytes/sec
	// budget", so resending it unchanged is guaranteed to fail again however long we
	// wait. It is still retryable — the records are not refused on their merits — but
	// the pipeline must SPLIT and PACE rather than resend. See rateLimitError.
	outcomeRateLimited
)

// rateLimitError is how the sink tells the pipeline "this was a rate limit, not a
// generic transient failure", and how long the destination asked us to wait.
//
// It travels on SinkResult.Err rather than as a new SinkResult field on purpose: the
// three entry lists already say WHICH entries to retry, and the only extra information
// here is HOW to retry them. errors.As reaches it through the errors.Join chain Emit
// builds, so a batch whose partitions failed for mixed reasons still surfaces the rate
// limit — which is the conservative direction, because pacing a batch that did not need
// it costs one delay, while missing one costs the whole --logs.ship-max-attempts budget.
type rateLimitError struct {
	// retryAfter is the delay the destination advertised (HTTP Retry-After), or zero
	// when it advertised none. Zero is common and is NOT a signal to retry immediately:
	// the pipeline falls back to its own pacing floor.
	retryAfter time.Duration
	err        error
}

func (e *rateLimitError) Error() string {
	msg := "destination rate limit"
	if e.retryAfter > 0 {
		msg += " (retry-after " + e.retryAfter.String() + ")"
	}
	if e.err != nil {
		return msg + ": " + e.err.Error()
	}
	return msg
}

func (e *rateLimitError) Unwrap() error { return e.err }

// rateLimitDelay reports whether err carries a rate-limit refusal, and the delay the
// destination advertised with it (zero when it advertised none).
func rateLimitDelay(err error) (time.Duration, bool) {
	if err == nil {
		return 0, false
	}
	var rl *rateLimitError
	if errors.As(err, &rl) {
		return rl.retryAfter, true
	}
	return 0, false
}

// deliveryObservation is the side channel between the transport hook and
// classifyPartition. It is created per ForceFlush and reachable only through that
// flush's context, so observations from concurrent flushes cannot collide.
//
// The SDK may make SEVERAL round trips inside one Export (it applies its own bounded
// retry to 429/502/503/504, pinned by otlpRetryPolicy). Each is recorded, and the LAST
// one wins — that is the outcome the SDK ultimately acted on, and the one whose verdict
// the pipeline must inherit. A flush that retried 503 twice and gave up therefore reads
// retryable, while one that retried once and then got a 200 with partial success reads
// partial.
type deliveryObservation struct {
	mu         sync.Mutex
	outcome    deliveryOutcome
	rejected   int64
	retryAfter time.Duration
}

func (o *deliveryObservation) record(outcome deliveryOutcome, rejected int64) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.outcome = outcome
	o.rejected = rejected
	o.retryAfter = 0
}

// recordRateLimited records a rate-limit refusal together with any delay the destination
// advertised. Separate from record rather than a third parameter on it: every other call
// site has no delay to report, and a signature that made them all pass a zero would make
// "no advertised delay" and "advertised zero" indistinguishable at the call site.
func (o *deliveryObservation) recordRateLimited(retryAfter time.Duration) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.outcome = outcomeRateLimited
	o.rejected = 0
	o.retryAfter = retryAfter
}

// throttle reads back the advertised delay. Zero means none was advertised.
func (o *deliveryObservation) throttle() time.Duration {
	if o == nil {
		return 0
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.retryAfter
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

// leasedExporterCtxKey carries the exporter one worker has exclusive use of for the
// duration of its flush. The processor is shared per resource, but the EXPORTER must not
// be shared between concurrent flushes, so the choice cannot live on the processor — it
// has to travel with the call. ForceFlush passes its context straight through to
// Processor.ForceFlush and on to export, which is what makes this work.
type leasedExporterCtxKey struct{}

func withLeasedExporter(ctx context.Context, e sdklog.Exporter) context.Context {
	return context.WithValue(ctx, leasedExporterCtxKey{}, e)
}

// leasedExporterFrom returns the exporter leased to this flush, or nil when the flush did
// not come from Emit's worker pool (Shutdown, or a test driving a provider directly).
func leasedExporterFrom(ctx context.Context) sdklog.Exporter {
	e, _ := ctx.Value(leasedExporterCtxKey{}).(sdklog.Exporter)
	return e
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
	case resp.StatusCode == http.StatusTooManyRequests:
		// 429 is a RATE limit, and it is the one retryable status where resending the
		// same bytes cannot work (#663). Classified separately, with the advertised
		// Retry-After, so the pipeline splits and paces instead of resending.
		obs.recordRateLimited(retryAfterDelay(resp.Header.Get("Retry-After"), time.Now()))
	case resp.StatusCode == http.StatusBadGateway,
		resp.StatusCode == http.StatusServiceUnavailable,
		resp.StatusCode == http.StatusGatewayTimeout:
		// The rest of the retryable set named by the OTLP spec. These mean the endpoint
		// could not take the request right now, not that the request was too big for a
		// rate budget, so an identical resend is the right response.
		//
		// A 503 may also carry Retry-After, but it is deliberately NOT honoured here:
		// the pipeline's own backoff already spaces these, and treating a 503 as a rate
		// limit would make an unrelated outage shrink the batch size for the rest of the
		// batch's life.
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

// maxRetryAfter clamps a Retry-After the destination advertised. The header is
// endpoint-controlled and a misconfigured or hostile one can name hours; honouring that
// literally would park the single emitter goroutine for the rest of the day while the
// queue behind it oldest-drops everything. Past the clamp we wait this long, then try
// again with a smaller batch — the split is doing the real work anyway.
const maxRetryAfter = 30 * time.Second

// retryAfterDelay parses an HTTP Retry-After value, which RFC 9110 allows in BOTH of two
// forms: delay-seconds, or an HTTP-date. Loki sends the former, Cloudflare and several
// gateways in front of it send the latter, so parsing only the integer form would
// silently read a real advertised delay as "none advertised".
//
// now is passed in rather than read here so the date form is testable without a clock.
// An unparseable, negative or absent value returns zero, meaning "nothing advertised" —
// the caller falls back to its own pacing floor rather than retrying immediately.
func retryAfterDelay(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			return 0
		}
		return clampRetryAfter(time.Duration(secs) * time.Second)
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return clampRetryAfter(d)
		}
	}
	return 0
}

func clampRetryAfter(d time.Duration) time.Duration {
	if d > maxRetryAfter {
		return maxRetryAfter
	}
	return d
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
	case codes.ResourceExhausted:
		// gRPC's rate/quota code — the transport-level twin of HTTP 429 (#663). Still
		// retryable, never permanent (treating a quota signal as permanent would discard
		// records the endpoint would have taken a moment later), but split out so the
		// pipeline shrinks and paces rather than resending identical bytes.
		//
		// NO ADVERTISED DELAY IS EXTRACTED on this path, and that is a known gap rather
		// than an oversight: the gRPC equivalent of Retry-After is a google.rpc.RetryInfo
		// message in the status details, and reading it needs a direct import of
		// google.golang.org/genproto/googleapis/rpc/errdetails, which is presently an
		// INDIRECT module requirement. Promoting it would change go.mod/vendor for an
		// optional hint. Zero here means "nothing advertised", and the pipeline's own
		// pacing floor covers it — the split is what actually clears the limit.
		obs.recordRateLimited(0)
	case codes.Canceled,
		codes.DeadlineExceeded,
		codes.Aborted,
		codes.OutOfRange,
		codes.Unavailable,
		codes.DataLoss:
		// The rest of the OTLP spec's retryable gRPC set.
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
// gzipByDefault reports whether to request gzip on the logs signal. The policy, the
// spec citation and the reason an unconditional WithCompression would be WRONG all live
// on options.OTLPGzipDefault, which the self-telemetry metrics exporter shares.
func gzipByDefault() bool { return options.OTLPGzipDefault(options.OTLPSignalLogs) }

// newLogExporters builds ONE EXPORTER PER CONCURRENT WORKER, not one shared between them.
//
// The interface is explicit that an exporter is not re-entrant — sdk/log/exporter.go:34,
// "Export should never be called concurrently with other Export calls" — and the logs
// SDK spec says the same (logs/sdk.md L621-622). Since #505 up to --logs.ship-concurrency
// partitions flush at once, so a single shared exporter would breach that contract. Two
// concrete things follow, and only the second is about spec purity:
//
//   - otlploggrpc.Exporter.Export takes a clientMu around the whole upload
//     (vendor/…/otlploggrpc/exporter.go:29-30, :71-73). With one shared exporter every
//     concurrent flush queues behind that mutex and --logs.ship-concurrency buys
//     NOTHING on gRPC — the flag silently means something different per transport. One
//     exporter per worker is what makes the flag mean the same thing on both.
//   - otlploghttp.Exporter.Export holds no such lock, so sharing it happened to work.
//     But that is a fact about the pinned version, not a promise: if a future
//     otlploghttp grows the mutex gRPC already has, a shared exporter would collapse
//     back to sequential SILENTLY — no error, no failing test, just the ~125 rec/s
//     ceiling that cost 451k records. Owning N exporters removes that tripwire entirely
//     rather than documenting it.
//
// The HTTP branch shares ONE *http.Client across all N. The contract being honoured is
// per-Exporter, not per-connection-pool, and N private pools of N connections each would
// be N^2 connections to one host for no benefit. http.Client is explicitly safe for
// concurrent use, and the idle pool is sized to the concurrency (see
// newObservingHTTPClient).
func newLogExporters(ctx context.Context, cfg *options.OTLPConfig, concurrency int) ([]sdklog.Exporter, error) {
	if concurrency < 1 {
		concurrency = 1
	}
	tlsCfg, err := buildLogTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	// Built once and shared by every HTTP exporter; nil on the gRPC path.
	var sharedClient *http.Client
	if cfg.Protocol != "grpc" {
		sharedClient, err = newObservingHTTPClient(cfg, tlsCfg, concurrency)
		if err != nil {
			return nil, err
		}
	}

	exps := make([]sdklog.Exporter, 0, concurrency)
	for range concurrency {
		exp, err := newLogExporter(ctx, cfg, tlsCfg, sharedClient)
		if err != nil {
			// Close the ones already built rather than leaking their connections.
			for _, e := range exps {
				_ = e.Shutdown(ctx)
			}
			return nil, err
		}
		exps = append(exps, exp)
	}
	return exps, nil
}

// newLogExporter builds a single exporter. sharedClient is the HTTP client every HTTP
// exporter shares; it is ignored on the gRPC path.
//
// Both branches install the delivery-observation hook described above; without it every
// failure would read as generic-and-retryable, which is the pre-#392 behaviour.
func newLogExporter(ctx context.Context, cfg *options.OTLPConfig, tlsCfg *tls.Config, sharedClient *http.Client) (sdklog.Exporter, error) {
	switch cfg.Protocol {
	case "grpc":
		opts := []otlploggrpc.Option{
			otlploggrpc.WithDialOption(grpc.WithChainUnaryInterceptor(observingUnaryInterceptor)),
			// Pin the in-Export retry small so it composes with --logs.ship-max-attempts
			// into a stateable worst case. See otlpRetryPolicy.
			otlploggrpc.WithRetry(otlploggrpc.RetryConfig{
				Enabled:         true,
				InitialInterval: otlpRetryPolicy.InitialInterval,
				MaxInterval:     otlpRetryPolicy.MaxInterval,
				MaxElapsedTime:  otlpRetryPolicy.MaxElapsedTime,
			}),
		}
		if gzipByDefault() {
			opts = append(opts, otlploggrpc.WithCompressor("gzip"))
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
		client := sharedClient
		if client == nil {
			var err error
			if client, err = newObservingHTTPClient(cfg, tlsCfg, 1); err != nil {
				return nil, err
			}
		}
		// Pin the request ceiling rather than inheriting the SDK default, so it and
		// maxExportBytes stay a matched pair (#506). See otlpMaxRequestBytes.
		opts := []otlploghttp.Option{
			otlploghttp.WithHTTPClient(client),
			otlploghttp.WithMaxRequestSize(otlpMaxRequestBytes),
			// Pin the in-Export retry small so it composes with --logs.ship-max-attempts
			// into a stateable worst case. See otlpRetryPolicy.
			otlploghttp.WithRetry(otlploghttp.RetryConfig{
				Enabled:         true,
				InitialInterval: otlpRetryPolicy.InitialInterval,
				MaxInterval:     otlpRetryPolicy.MaxInterval,
				MaxElapsedTime:  otlpRetryPolicy.MaxElapsedTime,
			}),
		}
		if gzipByDefault() {
			opts = append(opts, otlploghttp.WithCompression(otlploghttp.GzipCompression))
		}
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
func newObservingHTTPClient(cfg *options.OTLPConfig, tlsCfg *tls.Config, concurrency int) (*http.Client, error) {
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
	// Size the idle pool to the export concurrency. net/http defaults
	// MaxIdleConnsPerHost to 2 (DefaultMaxIdleConnsPerHost) when it is left at zero,
	// and http.DefaultTransport does leave it at zero — it only raises the GLOBAL
	// MaxIdleConns to 100. HTTP/2 would make this moot, since one connection
	// multiplexes every concurrent flush, but the Grafana Cloud OTLP gateway does not
	// negotiate h2: probed live 2026-07-29, `openssl s_client -alpn h2` reports "No
	// ALPN negotiated" and curl --http2 reports http_version=1.1. So each concurrent
	// partition flush needs its own TCP connection, and with a pool of 2 the other
	// N-2 would be dialled and TLS-handshaken fresh on every batch — paying back in
	// handshakes much of what the concurrency just bought.
	if concurrency > base.MaxIdleConnsPerHost {
		base.MaxIdleConnsPerHost = concurrency
	}
	if base.MaxIdleConns < concurrency {
		base.MaxIdleConns = concurrency
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
// deliver zero logs. Append /v1/logs unless the path already targets it.
//
// A PATHLESS endpoint is written out in full here rather than left to the SDK,
// for the reason spelled out on telemetry.metricsEndpointURL: otel v1.45.0 made
// WithEndpointURL set an explicit "/" for an empty path, which suppresses the
// SDK's own /v1/logs default and would silently POST every log to the root.
func logsEndpointURL(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse otlp endpoint %q: %w", endpoint, err)
	}
	trimmed := strings.TrimRight(u.Path, "/")
	if strings.HasSuffix(trimmed, "/v1/logs") {
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
