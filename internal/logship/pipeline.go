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
	"github.com/rknightion/opnsense-exporter/internal/options"
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
// and few ("poll:"+source name, "ship"), so this is only a backstop and is never
// reached in practice.
const errorLogMaxKeys = 64

// pipeline is the running log-shipping loop.
type pipeline struct {
	sink    Sink
	queue   *boundedQueue
	metrics *metrics
	cfg     *options.LogsConfig
	log     *slog.Logger

	sources     []Source
	pushSources []PushSource
	stateful    []StatefulSource
	stateFile   string

	ctx    context.Context
	cancel context.CancelFunc

	pollerWG  sync.WaitGroup
	emitterWG sync.WaitGroup

	stateMu       sync.Mutex
	lastPersisted []byte

	limiter *LogLimiter
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
) (func(context.Context) error, error) {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}

	sources, err := buildSources(deps)
	if err != nil {
		return nil, fmt.Errorf("build log sources: %w", err)
	}
	pushSources, err := buildPushSources(deps)
	if err != nil {
		return nil, fmt.Errorf("build push log sources: %w", err)
	}
	if len(sources) == 0 && len(pushSources) == 0 {
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
		sink:        sink,
		cfg:         cfg,
		log:         deps.Logger,
		sources:     sources,
		pushSources: pushSources,
		stateFile:   cfg.StateFile,
		ctx:         pctx,
		cancel:      cancel,
		limiter:     NewLogLimiter(errorLogInterval, errorLogMaxKeys),
	}
	p.queue = newBoundedQueue(cfg.BufferSize, func(e Entry) {
		p.metrics.dropped.WithLabelValues(e.Source, dropReasonOverflow).Inc()
	})
	p.metrics = newMetrics(reg, cfg.BufferSize, func() float64 { return float64(p.queue.length()) },
		collectSourceNames(sources, pushSources))

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
		"poll_interval", cfg.PollInterval.String(), "buffer_size", cfg.BufferSize)

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
	return names
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

// pollOnce runs one Poll, sanitizes and enqueues the records, and updates the
// cursor-lag gauge.
func (p *pipeline) pollOnce(s Source, name string) {
	records, err := s.Poll(p.ctx)
	if err != nil {
		p.metrics.pollErrors.WithLabelValues(name).Inc()
		if p.limiter.Allow("poll:" + name) {
			p.log.Warn("log source poll error", "source", name, "err", err)
		}
		return
	}
	var newest time.Time
	for _, r := range records {
		r.Attributes = sanitizeAttributes(r.Attributes)
		p.queue.push(Entry{Source: name, Record: r})
		if r.Timestamp.After(newest) {
			newest = r.Timestamp
		}
	}
	if !newest.IsZero() {
		p.metrics.lastEventTime.WithLabelValues(name).Set(float64(newest.Unix()))
	}
}

// shipRetryBase and shipRetryMax bound the exponential backoff between failed export
// attempts. The emitter retries a failed batch in memory (records stay queued, never
// re-fetched) rather than dropping it, so a transient endpoint outage is ridden out for
// as long as the bounded queue behind it holds — the at-least-once-within-a-run contract
// (#290). Loss during a run therefore happens only two ways, both counted: the queue
// overflows (logs_dropped_total{reason="overflow"}) or shutdown abandons an
// undeliverable batch (logs_dropped_total{reason="ship_failed"}). It does NOT survive a
// process restart mid-outage — that is the in-memory tier's documented boundary.
const (
	shipRetryBase = 200 * time.Millisecond
	shipRetryMax  = 5 * time.Second
)

// runEmitter drains the queue into batches and ships each with bounded in-memory retry.
// It exits when the queue is closed and fully drained.
func (p *pipeline) runEmitter() {
	defer p.emitterWG.Done()
	for {
		batch, ok := p.queue.drainUpTo(p.cfg.BatchMax)
		if !ok {
			return
		}
		p.shipBatch(batch)
	}
}

// shipBatch exports one batch, retrying on failure until it is acknowledged or the
// pipeline is shutting down. Each failed attempt counts logs_ship_errors_total; a
// confirmed export counts logs_shipped_total per record. It uses a background context
// for the export itself so records queued at shutdown still get a delivery attempt, but
// the retry backoff is interruptible by pipeline cancellation so stop() stays bounded:
// once shutdown begins, a still-failing batch is abandoned and counted
// logs_dropped_total{reason="ship_failed"} rather than blocking the drain — the records
// could not be delivered, and that loss is made visible rather than silently skipped.
func (p *pipeline) shipBatch(batch []Entry) {
	for attempt := 1; ; attempt++ {
		err := p.sink.Emit(context.Background(), batch)
		if err == nil {
			for _, e := range batch {
				p.metrics.shipped.WithLabelValues(e.Source).Inc()
			}
			return
		}
		p.metrics.shipErrors.Inc()
		if p.limiter.Allow("ship") {
			p.log.Warn("log sink export failed; retrying", "attempt", attempt, "count", len(batch), "err", err)
		}
		select {
		case <-p.ctx.Done():
			for _, e := range batch {
				p.metrics.dropped.WithLabelValues(e.Source, dropReasonShipFailed).Inc()
			}
			p.log.Error("log batch abandoned during shutdown; records lost", "count", len(batch))
			return
		case <-time.After(shipBackoff(attempt)):
		}
	}
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
	p.cancel()
	p.pollerWG.Wait()
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
