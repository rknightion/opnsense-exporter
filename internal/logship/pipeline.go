package logship

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/internal/options"
)

// stateFlushInterval bounds how often persisted cursors are rewritten while the
// pipeline runs. Writes are skipped when no cursor changed, and a final flush
// always runs on shutdown, so this only bounds the staleness window of the
// on-disk state — it does not tie persistence to any source's poll cadence.
const stateFlushInterval = 30 * time.Second

// errorLogInterval rate-limits repeated poll/ship error logging so a flapping
// endpoint cannot flood the logs.
const errorLogInterval = 30 * time.Second

// errorLogMaxKeys bounds the pipeline limiter's key set. Its keys are code-defined
// and few ("poll:"+source name, "oversize:"+source name, "ship", "ship_permanent"),
// so this is only a backstop and is never reached in practice.
const errorLogMaxKeys = 64

// pipeline is the running log-shipping loop.
type pipeline struct {
	sink    Sink
	queue   *boundedQueue
	metrics *metrics
	cfg     *options.LogsConfig
	log     *slog.Logger
	selfLog *SelfLogHandler

	sources     []Source
	pushSources []PushSource
	stateful    []StatefulSource
	stateFile   string

	ctx    context.Context
	cancel context.CancelFunc
	// afterSourcesStopped bridges producers outside the source registry into the
	// shutdown order. It runs after pollerWG reaches zero and before queue.close.
	afterSourcesStopped func()

	pollerWG  sync.WaitGroup
	emitterWG sync.WaitGroup

	stateMu       sync.Mutex
	lastPersisted []byte

	limiter *LogLimiter

	// shipChunk is the STICKY, adaptive per-attempt record cap learned from rate-limit
	// refusals (#663). 0 means "no cap, send the whole batch", which is the state a
	// healthy pipeline stays in forever. Only the single emitter goroutine touches it
	// (shipBatch is the sole writer, and runEmitter is the sole caller in production),
	// so it needs no lock.
	//
	// It is deliberately pipeline-scoped rather than batch-scoped. A sustained burst
	// above the tenant's budget produces a NEW oversized batch every drain, so a split
	// that reset each time would re-learn the limit — and pay one refused wire attempt
	// for it — on every single batch. Carrying it forward is what turns "burst above the
	// limit" into steady paced delivery rather than a refusal per batch.
	shipChunk int
}

// Start builds every registered source, the configured sink and the pipeline,
// then launches the poller/emitter/state goroutines. It performs no network I/O:
// the OTLP sink connects lazily on the first export, so a dead endpoint never
// blocks startup. It returns a stop function that drains the pipeline (stop
// pollers -> flush queue -> persist cursors -> flush sink), bounded by the stop
// context. When no source is enabled it logs a warning and returns a no-op stop.
//
// transport is the resolved OTLP transport (may be nil); it is required only when
// cfg.Sink == "otlp". Start fails fast with an actionable error when the OTLP
// sink is selected but no endpoint is resolvable.
func Start(
	ctx context.Context,
	cfg *options.LogsConfig,
	transport *options.OTLPConfig,
	deps Deps,
	version, instance string,
	reg prometheus.Registerer,
	selfLogs ...*SelfLogHandler,
) (func(context.Context) error, error) {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	var selfLog *SelfLogHandler
	for _, candidate := range selfLogs {
		if candidate != nil {
			selfLog = candidate
			break
		}
	}
	if selfLog != nil {
		if cfg.Sink != "otlp" {
			return nil, fmt.Errorf("self-log shipping requires --logs.sink=otlp; stdout cannot carry OTLP resource attributes")
		}
		// Sink/pipeline diagnostics must stay on the wrapped stderr handler. A
		// failing sink otherwise logs an error which re-enters the same queue and
		// creates a feedback loop while the endpoint is down.
		deps.Logger = selfLog.DiagnosticLogger()
	}

	// Stamp instance identity onto EVERY logship self-metric (#395). Both registerers
	// are wrapped here, before any source is built: reg carries the pipeline's own
	// metrics, deps.Registerer is what each push receiver registers its shared
	// parse/reject vecs on. main.go currently passes the same registry for both, but
	// wrapping them independently is what makes a future split safe — a receiver
	// registering through an unwrapped deps.Registerer is the exact regression
	// TestStart_WrapsBothRegisterersWithInstanceLabel guards.
	reg = SelfMetricsRegisterer(reg, instance)
	deps.Registerer = SelfMetricsRegisterer(deps.Registerer, instance)

	sources, err := buildSources(deps)
	if err != nil {
		return nil, fmt.Errorf("build log sources: %w", err)
	}
	pushSources, err := buildPushSources(deps)
	if err != nil {
		return nil, fmt.Errorf("build push log sources: %w", err)
	}
	if len(sources) == 0 && len(pushSources) == 0 && selfLog == nil {
		deps.Logger.Warn("log shipping enabled but no source is enabled; nothing will be shipped " +
			"(enable a source, e.g. --logs.syslog.enabled)")
		return func(context.Context) error { return nil }, nil
	}

	sink, err := buildSink(cfg, transport, version, instance, deps.Logger)
	if err != nil {
		return nil, err
	}

	pctx, cancel := context.WithCancel(context.Background())
	p := &pipeline{
		sink:                sink,
		cfg:                 cfg,
		log:                 deps.Logger,
		selfLog:             selfLog,
		sources:             sources,
		pushSources:         pushSources,
		stateFile:           cfg.StateFile,
		ctx:                 pctx,
		cancel:              cancel,
		afterSourcesStopped: deps.AfterSourcesStopped,
		limiter:             NewLogLimiter(errorLogInterval, errorLogMaxKeys),
	}
	p.queue = newBoundedQueueBytes(cfg.BufferSize, cfg.BufferMaxBytes, p.noteOverflow)
	sourceLabels := collectSourceNames(sources, pushSources)
	if selfLog != nil {
		sourceLabels.all = append(sourceLabels.all, SelfLogSource)
	}
	p.metrics = newMetrics(reg, queueBounds{
		capacity: cfg.BufferSize,
		maxBytes: cfg.BufferMaxBytes,
		length:   func() float64 { return float64(p.queue.length()) },
		bytes:    func() float64 { return float64(p.queue.queuedBytes()) },
	}, sourceLabels)
	if selfLog != nil {
		selfLog.Bind(func(e Entry) bool {
			e.Record.Attributes = sanitizeAttributes(e.Record.Attributes)
			_, ok := p.enqueue(e)
			return ok
		})
	}

	for _, s := range sources {
		if st, ok := s.(StatefulSource); ok {
			p.stateful = append(p.stateful, st)
		}
	}
	p.loadState()

	p.emitterWG.Add(1)
	go p.runEmitter()

	for _, s := range sources {
		interval := p.effectiveInterval(s)
		p.pollerWG.Add(1)
		go p.runPoller(s, interval)
	}

	// Push sources are registered on pollerWG too, so stop() waits for them: each
	// Run must return on ctx cancel (pollerWG.Wait() is unbounded).
	for _, s := range pushSources {
		p.pollerWG.Add(1)
		go func(s PushSource) {
			defer p.pollerWG.Done()
			p.runPushSource(p.ctx, s)
		}(s)
	}

	if p.stateFile != "" && len(p.stateful) > 0 {
		p.pollerWG.Add(1)
		go p.runStateFlusher()
	}

	names := make([]string, 0, len(sources)+len(pushSources))
	for _, s := range sources {
		names = append(names, s.Name())
	}
	for _, s := range pushSources {
		names = append(names, s.Name())
	}
	deps.Logger.Info("log shipping enabled", "sink", cfg.Sink, "sources", names,
		"poll_interval", cfg.PollInterval.String(), "buffer_size", cfg.BufferSize,
		"buffer_max_bytes", cfg.BufferMaxBytes, "max_record_bytes", cfg.MaxRecordBytes,
		"ship_max_attempts", cfg.ShipMaxAttempts)

	return p.stop, nil
}

// collectSourceNames derives the label combinations to pre-initialise (#280) from
// the sources actually built. Push sources are excluded from poll: they never call
// Poll, so a poll-error zero for them would be a permanent lie.
func collectSourceNames(sources []Source, pushSources []PushSource) sourceNames {
	names := sourceNames{}
	for _, s := range sources {
		names.all = append(names.all, s.Name())
		names.poll = append(names.poll, s.Name())
		if _, ok := s.(GapReportingSource); ok {
			names.gap = append(names.gap, s.Name())
		}
	}
	for _, s := range pushSources {
		names.all = append(names.all, s.Name())
		if _, ok := s.(GapReportingSource); ok {
			names.gap = append(names.gap, s.Name())
		}
	}
	for _, s := range sources {
		if es, ok := s.(ExtraSourceNames); ok {
			names.all = append(names.all, es.ExtraSourceNames()...)
		}
	}
	for _, s := range pushSources {
		if es, ok := s.(ExtraSourceNames); ok {
			names.all = append(names.all, es.ExtraSourceNames()...)
		}
	}
	return names
}

// noteOverflow is the bounded queue's eviction callback: it counts the evicted
// record on logs_dropped_total{reason="overflow"} and on the console's raw
// throughput total. It is a method rather than an inline closure so both the
// pipeline and the test harness that mirrors Start count overflow identically.
func (p *pipeline) noteOverflow(e Entry) {
	p.metrics.dropped.WithLabelValues(e.Source, dropReasonOverflow).Inc()
	consoleDropped.Add(1)
}

// enqueue is the single ingest gate every record passes through, whether it came
// from a poll Source or a push receiver. It rejects a record whose estimated
// retained size exceeds --logs.max-record-bytes (0 = no cap), counting it under
// reason="record_too_large" instead of queueing it, and returns whether the record
// was accepted.
//
// Rejecting at INGEST rather than at export is the point (#318/#325a): an
// oversized record that reaches the queue both displaces other records under the
// byte budget AND can become a batch the sink permanently refuses, which before
// the attempt cap wedged the single emitter goroutine outright.
// It is also where the exporter-clock receive time is stamped (#394). Being the single
// gate is what makes that stamp trustworthy: it is taken exactly once per record, after
// the size check (so a rejected record carries none and cannot advance receive
// freshness) and before the record can be retried, so it stays byte-identical across
// every export attempt. The caller gets the stamp back so it can advance its own
// pre-hoisted per-source gauge without a second clock read.
func (p *pipeline) enqueue(e Entry) (time.Time, bool) {
	if maxBytes := p.cfg.MaxRecordBytes; maxBytes > 0 && recordBytes(e.Record) > maxBytes {
		p.metrics.dropped.WithLabelValues(e.Source, dropReasonRecordTooLarge).Inc()
		consoleDropped.Add(1)
		if p.limiter.Allow("oversize:" + e.Source) {
			p.log.Warn("log record exceeds the per-record size cap; rejected at ingest",
				"source", e.Source, "bytes", recordBytes(e.Record), "max_record_bytes", maxBytes)
		}
		return time.Time{}, false
	}
	e.Received = time.Now()
	p.queue.push(e)
	return e.Received, true
}

// unixSeconds renders t for a *_timestamp_seconds gauge, keeping sub-second precision.
// Truncating to whole seconds would quantise the received/exported gap — the very thing
// the two gauges exist to measure — to 1s, which is coarser than a healthy pipeline's
// entire queue-to-acknowledgement latency.
func unixSeconds(t time.Time) float64 {
	return float64(t.UnixNano()) / float64(time.Second)
}

// effectiveInterval is max(global poll interval, source floor).
func (p *pipeline) effectiveInterval(s Source) time.Duration {
	interval := p.cfg.PollInterval
	if is, ok := s.(IntervalSource); ok {
		if m := is.MinInterval(); m > interval {
			interval = m
		}
	}
	return interval
}

// runPoller polls a source immediately, then on every tick, until the pipeline
// context is cancelled.
func (p *pipeline) runPoller(s Source, interval time.Duration) {
	defer p.pollerWG.Done()
	name := s.Name()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		p.pollOnce(s, name)
		select {
		case <-p.ctx.Done():
			return
		case <-t.C:
		}
	}
}

// pollOnce runs one Poll, sanitizes and enqueues the records, and advances the
// source's receive-freshness gauge.
//
// The gauge is set from the last ADMISSION stamp, never from the newest record
// timestamp in the poll (#394). Taking the newest origin timestamp made a poll of old
// or out-of-order data read as a stall, and made the gauge track the data's age rather
// than the source's liveness — which is what an alert on it needs to mean.
func (p *pipeline) pollOnce(s Source, name string) {
	records, err := s.Poll(p.ctx)
	if err != nil {
		p.metrics.pollErrors.WithLabelValues(name).Inc()
		if p.limiter.Allow("poll:" + name) {
			p.log.Warn("log source poll error", "source", name, "err", err)
		}
		return
	}
	var lastAdmitted time.Time
	for _, r := range records {
		r.Attributes = sanitizeAttributes(r.Attributes)
		recv, ok := p.enqueue(Entry{Source: name, Record: r})
		if !ok {
			continue
		}
		lastAdmitted = recv
	}
	if !lastAdmitted.IsZero() {
		p.metrics.lastReceived.WithLabelValues(name).Set(unixSeconds(lastAdmitted))
	}
}

// shipRetryBase and shipRetryMax bound the exponential backoff between failed export
// attempts. The emitter retries a failed batch in memory (records stay queued, never
// re-fetched) rather than dropping it, so a transient endpoint outage is ridden out for
// as long as the bounded queue behind it holds — the at-least-once-within-a-run contract
// (#290), up to the --logs.ship-max-attempts cap. Loss during a run happens only four
// ways, all counted on logs_dropped_total: the queue overflows its count cap or byte
// budget (reason="overflow"), a record is rejected at ingest for exceeding
// --logs.max-record-bytes (reason="record_too_large"), the sink refuses a batch for
// --logs.ship-max-attempts consecutive attempts (reason="ship_failed_permanent"), or
// shutdown abandons a still-failing batch (reason="ship_failed"). It does NOT survive a
// process restart mid-outage — that is the in-memory tier's documented boundary.
const (
	shipRetryBase = 200 * time.Millisecond
	shipRetryMax  = 5 * time.Second
	// shipRateLimitPause is the pacing floor applied after a rate-limit refusal that
	// advertised no Retry-After. It is a real pause rather than the ordinary backoff
	// because a rate limit is a statement about bytes per SECOND: coming straight back
	// with 200ms of backoff is what turns one refusal into ten.
	shipRateLimitPause = 2 * time.Second
	// shipRateLimitMinChunk floors the split. Halving all the way to a single record
	// would trade one rejected request for hundreds of round trips, each paying the
	// fixed per-partition cost, which is a worse failure than the one being fixed. At
	// the measured ~2.7 kB/record on the live box (see the recordBytes block comment in
	// queue.go) 32 records is ~85 kB — small enough that any tenant with a working
	// budget accepts it, large enough that the trip is worth taking.
	shipRateLimitMinChunk = 32
)

// exportByteBound is the byte budget for ONE delivery attempt: the smaller of the
// operator's ingest-rate bound (--logs.max-export-bytes) and the transport backstop
// (maxExportBytes). The two answer different questions and both must hold — see the
// block comment above maxExportBytes. Zero or an out-of-range value falls back to the
// transport backstop, which is the pre-#663 behaviour.
func (p *pipeline) exportByteBound() int {
	n := p.cfg.MaxExportBytes
	if n <= 0 || n > maxExportBytes {
		return maxExportBytes
	}
	return n
}

// runEmitter drains the queue into batches and ships each with bounded in-memory retry.
// It exits when the queue is closed and fully drained.
func (p *pipeline) runEmitter() {
	defer p.emitterWG.Done()
	for {
		batch, ok := p.queue.drainUpTo(p.cfg.BatchMax, p.exportByteBound())
		if !ok {
			return
		}
		p.shipBatch(batch)
	}
}

// shipBatch exports one batch, retrying on failure until it is acknowledged, the
// attempt cap is reached, or the pipeline is shutting down. Each failed attempt counts
// logs_ship_errors_total; a confirmed export counts logs_shipped_total per record. It
// uses a background context for the export itself so records queued at shutdown still
// get a delivery attempt, but the retry backoff is interruptible by pipeline
// cancellation so stop() stays bounded: once shutdown begins, a still-failing batch is
// abandoned and counted logs_dropped_total{reason="ship_failed"} rather than blocking
// the drain — the records could not be delivered, and that loss is made visible rather
// than silently skipped.
//
// Retries are bounded by --logs.ship-max-attempts (#325a). There is exactly ONE emitter
// goroutine, so an unbounded loop on a batch the sink permanently refuses (an oversized
// record, a schema rejection, a bad credential, an exhausted quota) never returns to
// drainUpTo: delivery halts for the life of the process while everything behind it
// silently oldest-drops as the queue fills. On exhaustion the batch is DROPPED and
// counted under reason="ship_failed_permanent" — deliberately trading "never lose a
// deliverable batch" for "never wedge", and keeping the two loss modes distinguishable
// from the shutdown-time ship_failed. 0 attempts restores the old unlimited behaviour.
// Since #392 the retry set SHRINKS as partitions succeed. Only the entries the sink
// reported as retryable are re-Emitted; anything it acknowledged is counted shipped and
// removed from the batch, and anything it reported terminally rejected is counted
// dropped{reason="rejected"} and likewise removed. That is what stops an acknowledged
// resource partition being resent — and therefore duplicated downstream — because a
// SIBLING partition failed.
// A RATE LIMIT IS NOT A GENERIC TRANSIENT FAILURE, and the difference is the whole of
// #663. When the destination answers HTTP 429 / gRPC RESOURCE_EXHAUSTED the request was
// refused for its SIZE against a bytes-per-second budget, so a byte-identical resend is
// guaranteed to fail again — the observed shape was the same 2777-record, 7.5 MB batch
// refused seven times in a row over eight minutes while every unrelated record behind it
// oldest-dropped out of the queue. So a rate limit does two things nothing else does:
// it HALVES the chunk size (down to shipRateLimitMinChunk) and it sets a PACE that is
// honoured before every subsequent chunk, decaying back to full speed as chunks land.
// The batch is delivered in pieces the tenant can actually accept instead of being
// dropped whole.
//
// WORST-CASE TIME ON ONE UNDELIVERABLE BATCH, which #663 also asks to be bounded and
// stated. BOTH retry layers are in the arithmetic, which is the part that was missing
// before: the OTLP SDK runs its own retry loop INSIDE a single Emit, and the pipeline
// counted that whole thing as one attempt. Writing E for the SDK's pinned max-elapsed
// (otlpRetryPolicy, 5s), T for the OTLP export timeout
// (OTEL_EXPORTER_OTLP_LOGS_TIMEOUT, default 10s), N for --logs.ship-max-attempts and W
// for the longest wait the pipeline can insert between attempts —
// max(shipRetryMax 5s, maxRetryAfter 30s) = 30s:
//
//	t_worst  =  N × (E + T)  +  (N-1) × W
//	         =  10 × 15s + 9 × 30s  =  420s (7 min) at the defaults, and only when the
//	            destination advertises the maximum Retry-After on every single attempt.
//	            With no Retry-After advertised the pacing floor is 2s and the ordinary
//	            backoff caps at 5s, giving 10 × 15s + 9 × 5s = 195s (~3¼ min).
//
// Before #663 E was the SDK's own 60s default and nothing in the code knew it existed:
// 10 × 70s = 700s, which is what produced the ~8-minute observation on the live box.
//
// Attempts are counted GLOBALLY across the whole shipBatch call, not per chunk, so
// splitting can never multiply that bound: N caps wire attempts whatever shape they
// take. A chunk that lands cleanly costs no attempt, which is what lets a split batch
// finish delivering inside the same budget.
//
// DROP ACCOUNTING IS UNCHANGED, and must stay that way: the batch that could not be
// delivered is counted reason="ship_failed_permanent" (or reason="ship_failed" when
// shutdown abandons it), while records evicted from the queue because the emitter was
// busy are counted reason="overflow" by noteOverflow. Those answer different operator
// questions — "this payload/destination is broken" versus "we were too slow" — and
// collapsing them would hide exactly the collateral damage this change exists to reduce.
func (p *pipeline) shipBatch(batch []Entry) {
	maxAttempts := p.cfg.ShipMaxAttempts
	pending := batch
	// chunk starts at the learned cap, or at the whole batch when nothing has been
	// learned — so absent any rate limit the behaviour is exactly the pre-#663 one, one
	// Emit per attempt carrying everything still outstanding.
	chunk := p.shipChunk
	if chunk <= 0 || chunk > len(pending) {
		chunk = len(pending)
	}
	var pace time.Duration
	attempt := 0
	limited := false

	for len(pending) > 0 {
		if pace > 0 && !p.waitOrAbandon(pace, pending) {
			return
		}
		n := chunk
		if n < 1 {
			n = 1
		}
		if n > len(pending) {
			n = len(pending)
		}
		head, rest := pending[:n], pending[n:]

		res := p.sink.Emit(context.Background(), head)
		p.noteAcked(res.Acked)
		p.noteRejected(res.Rejected)

		if len(res.Retry) == 0 && len(res.Rejected) == 0 {
			// This chunk landed cleanly. Relax the pace geometrically rather than
			// dropping it outright: a tenant that just rate-limited us is still near its
			// budget, and going straight back to full speed is what produces the
			// refuse/retry oscillation instead of a steady drain.
			pace /= 2
			if pace < 100*time.Millisecond {
				pace = 0
			}
			pending = rest
			continue
		}

		// One increment per attempt that did not deliver everything, whatever the
		// reason. It stays an ATTEMPT counter, not a record counter: the records are
		// accounted for by shipped/dropped, and conflating the two would make the
		// three families impossible to reconcile.
		attempt++
		p.metrics.shipErrors.Inc()

		if len(res.Rejected) > 0 && p.limiter.Allow("ship_rejected") {
			p.log.Error("log endpoint terminally rejected records; they are lost and will NOT be retried "+
				"(a permanent protocol response, or an OTLP partial-success rejection)",
				"count", len(res.Rejected), "err", res.Err)
		}

		// Whatever this chunk did not deliver goes back to the FRONT of the outstanding
		// set, ahead of the chunks not yet attempted, so ordering within the batch is
		// preserved across a split.
		pending = joinPending(res.Retry, rest)
		if len(pending) == 0 {
			return
		}

		if maxAttempts > 0 && attempt >= maxAttempts {
			for _, e := range pending {
				p.metrics.dropped.WithLabelValues(e.Source, dropReasonShipFailedPermanent).Inc()
			}
			consoleDropped.Add(uint64(len(pending)))
			if p.limiter.Allow("ship_permanent") {
				p.log.Error("log sink refused a batch for the maximum number of attempts; dropping it "+
					"so delivery of later batches continues; records lost",
					"attempts", attempt, "count", len(pending), "err", res.Err)
			}
			return
		}

		if delay, isLimited := rateLimitDelay(res.Err); isLimited {
			limited = true
			chunk = splitChunk(n)
			p.shipChunk = chunk
			pace = pacingFor(delay)
			if p.limiter.Allow("ship_rate_limited") {
				p.log.Warn("log destination rate-limited the export; splitting the batch and pacing "+
					"rather than resending it unchanged",
					"attempt", attempt, "refused_records", n, "next_chunk", chunk,
					"pace", pace.String(), "outstanding", len(pending), "err", res.Err)
			}
			// The pace is applied at the top of the loop, so no extra wait here — one
			// delay per attempt, never two stacked.
			continue
		}

		if p.limiter.Allow("ship") {
			p.log.Warn("log sink export failed; retrying", "attempt", attempt, "count", len(pending), "err", res.Err)
		}
		if !p.waitOrAbandon(shipBackoff(attempt), pending) {
			return
		}
	}

	// The whole batch was accounted for. If nothing rate-limited us this time, walk the
	// learned cap back UP — geometrically, and only one step per batch, so recovery is
	// slower than the halving that got us here. An adaptive limit that only ever shrinks
	// would leave the pipeline permanently paying per-chunk round-trips for a burst that
	// ended hours ago.
	if !limited {
		p.relaxShipChunk()
	}
}

// relaxShipChunk doubles the learned per-attempt cap, clearing it entirely once it
// reaches the configured batch size — at which point the cap is doing nothing and
// carrying it would just be state to get wrong.
func (p *pipeline) relaxShipChunk() {
	if p.shipChunk <= 0 {
		return
	}
	next := p.shipChunk * 2
	if p.cfg == nil || p.cfg.BatchMax <= 0 || next >= p.cfg.BatchMax {
		p.shipChunk = 0
		return
	}
	p.shipChunk = next
}

// waitOrAbandon sleeps for d unless the pipeline is shutting down, in which case it
// counts every outstanding record logs_dropped_total{reason="ship_failed"} and reports
// false so the caller returns. Keeping the abandon path in one place is what stops a
// second wait site (the pacing one) inventing a third loss mode.
func (p *pipeline) waitOrAbandon(d time.Duration, pending []Entry) bool {
	select {
	case <-p.ctx.Done():
		for _, e := range pending {
			p.metrics.dropped.WithLabelValues(e.Source, dropReasonShipFailed).Inc()
		}
		consoleDropped.Add(uint64(len(pending)))
		p.log.Error("log batch abandoned during shutdown; records lost", "count", len(pending))
		return false
	case <-time.After(d):
		return true
	}
}

// joinPending concatenates the un-delivered head with the not-yet-attempted tail into a
// fresh slice. It allocates rather than appending in place on purpose: res.Retry is the
// sink's own slice and tail aliases the caller's batch, so appending could write through
// either backing array depending on capacity.
func joinPending(retry, tail []Entry) []Entry {
	if len(retry) == 0 {
		return tail
	}
	if len(tail) == 0 {
		return retry
	}
	out := make([]Entry, 0, len(retry)+len(tail))
	out = append(out, retry...)
	out = append(out, tail...)
	return out
}

// splitChunk halves a refused chunk, floored at shipRateLimitMinChunk — or at 1 when the
// chunk was already at or below that floor, so a rate limit on a single record still
// makes progress rather than looping on an unchanged size.
func splitChunk(n int) int {
	half := n / 2
	if half < shipRateLimitMinChunk {
		if n <= shipRateLimitMinChunk {
			return 1
		}
		return shipRateLimitMinChunk
	}
	return half
}

// pacingFor turns an advertised Retry-After into the delay applied before the next
// chunk. Zero (nothing advertised, the common case) falls back to shipRateLimitPause
// rather than to the ordinary backoff: a bytes/sec budget needs a pause measured in
// seconds, not the 200ms a first-attempt backoff would give.
func pacingFor(advertised time.Duration) time.Duration {
	if advertised < shipRateLimitPause {
		return shipRateLimitPause
	}
	return advertised
}

// noteAcked counts a confirmed delivery and advances export freshness.
//
// One clock read for the whole acknowledgement: every record here was confirmed by the
// same Emit call, so stamping them at different instants would invent a spread that did
// not happen (#394). Export freshness advances HERE and nowhere else — not on enqueue,
// not on a failed attempt, not on a drop, and NOT on a terminal rejection — which is
// what lets a dashboard read a growing received-minus-exported gap as "input is
// arriving but delivery is stuck".
func (p *pipeline) noteAcked(acked []Entry) {
	if len(acked) == 0 {
		return
	}
	ackedAt := unixSeconds(time.Now())
	for _, e := range acked {
		p.metrics.shipped.WithLabelValues(e.Source).Inc()
		p.metrics.lastExported.WithLabelValues(e.Source).Set(ackedAt)
	}
	consoleShipped.Add(uint64(len(acked)))
}

// noteRejected counts records the endpoint terminally refused. They are LOST — counted
// under reason="rejected", never as shipped, and never retried, because a byte-identical
// request would be refused identically. Keeping them distinct from ship_failed_permanent
// matters operationally: that reason means "we gave up after N attempts, the endpoint
// may be sick", while this one means "the endpoint looked at these records and said no",
// which points at the payload or the credentials instead.
func (p *pipeline) noteRejected(rejected []Entry) {
	if len(rejected) == 0 {
		return
	}
	for _, e := range rejected {
		p.metrics.dropped.WithLabelValues(e.Source, dropReasonRejected).Inc()
	}
	consoleDropped.Add(uint64(len(rejected)))
}

// shipBackoff is full-magnitude exponential backoff capped at shipRetryMax, guarded
// against the shift overflowing for a long-running outage.
func shipBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 8 { // 200ms << 7 already exceeds the 5s cap
		return shipRetryMax
	}
	d := shipRetryBase << (attempt - 1)
	if d > shipRetryMax {
		return shipRetryMax
	}
	return d
}

// runStateFlusher periodically persists cursors while running. The final flush
// runs in stop() after pollers have stopped.
func (p *pipeline) runStateFlusher() {
	defer p.pollerWG.Done()
	t := time.NewTicker(stateFlushInterval)
	defer t.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-t.C:
			p.persistState()
		}
	}
}

// stop drains the pipeline in order: stop pollers, flush the queue through the emitter,
// persist final cursors, then flush the sink. The emitter drain is bounded by ctx: if it
// does not finish within the shutdown deadline, stop returns an error rather than
// reporting a clean flush while cursors imply the buffered records were delivered (#290).
// The emitter goroutine still exits shortly after, when its in-flight export returns and
// it observes the cancelled context.
func (p *pipeline) stop(ctx context.Context) error {
	if p.selfLog != nil {
		p.selfLog.Unbind()
	}
	p.cancel()
	p.pollerWG.Wait()
	if p.afterSourcesStopped != nil {
		p.afterSourcesStopped()
	}
	p.queue.close()

	drained := make(chan struct{})
	go func() {
		p.emitterWG.Wait()
		close(drained)
	}()
	var drainErr error
	select {
	case <-drained:
	case <-ctx.Done():
		drainErr = fmt.Errorf("log pipeline drain did not finish before shutdown deadline: %w", ctx.Err())
		p.log.Error("log pipeline shutdown timed out before the queue fully drained; buffered records may be lost")
	}

	p.persistState()
	return errors.Join(drainErr, p.sink.Shutdown(ctx))
}

// loadState reads the state file (if any) and restores each stateful source's
// cursor. A missing or unreadable file is not fatal: sources resume from now.
func (p *pipeline) loadState() {
	if p.stateFile == "" || len(p.stateful) == 0 {
		return
	}
	data, err := os.ReadFile(p.stateFile)
	if err != nil {
		if !os.IsNotExist(err) {
			p.log.Warn("could not read log state file; resuming from now", "path", p.stateFile, "err", err)
		}
		return
	}
	var blobs map[string]string
	if err := json.Unmarshal(data, &blobs); err != nil {
		p.log.Warn("log state file is corrupt; resuming from now", "path", p.stateFile, "err", err)
		return
	}
	for _, st := range p.stateful {
		enc, ok := blobs[st.Name()]
		if !ok {
			continue
		}
		raw, derr := base64.StdEncoding.DecodeString(enc)
		if derr != nil {
			p.log.Warn("log state entry is corrupt; resuming from now", "source", st.Name(), "err", derr)
			continue
		}
		st.LoadState(raw)
	}
	p.lastPersisted = data
}

// persistState snapshots every stateful source's cursor and atomically rewrites
// the state file, but only when the snapshot differs from the last write (so
// idle sources cause no I/O).
func (p *pipeline) persistState() {
	if p.stateFile == "" || len(p.stateful) == 0 {
		return
	}
	p.stateMu.Lock()
	defer p.stateMu.Unlock()

	blobs := make(map[string]string, len(p.stateful))
	for _, st := range p.stateful {
		data, ok := st.SaveState()
		if !ok {
			continue
		}
		blobs[st.Name()] = base64.StdEncoding.EncodeToString(data)
	}
	if len(blobs) == 0 {
		return
	}
	encoded, err := json.Marshal(blobs)
	if err != nil {
		p.log.Warn("could not encode log state", "err", err)
		return
	}
	if p.lastPersisted != nil && string(encoded) == string(p.lastPersisted) {
		return
	}
	if err := atomicWrite(p.stateFile, encoded); err != nil {
		p.log.Warn("could not write log state file", "path", p.stateFile, "err", err)
		return
	}
	p.lastPersisted = encoded
}

// atomicWrite writes data to a sibling temp file and renames it over path, so a
// reader never sees a partial state file.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
