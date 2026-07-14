package logship

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

	limiter *logLimiter
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
		limiter:     newLogLimiter(errorLogInterval),
	}
	p.queue = newBoundedQueue(cfg.BufferSize, func(e Entry) {
		p.metrics.dropped.WithLabelValues(e.Source, dropReasonOverflow).Inc()
	})
	p.metrics = newMetrics(reg, cfg.BufferSize, func() float64 { return float64(p.queue.length()) })

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
		if p.limiter.allow("poll:" + name) {
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

// runEmitter drains the queue into batches and ships them. It uses a background
// context so entries queued at shutdown are still flushed after the pipeline
// context is cancelled; the OTLP sink's Emit is non-blocking (network I/O
// happens in the sink's own batch processor, flushed by Shutdown).
func (p *pipeline) runEmitter() {
	defer p.emitterWG.Done()
	for {
		batch, ok := p.queue.drainUpTo(p.cfg.BatchMax)
		if !ok {
			return
		}
		if err := p.sink.Emit(context.Background(), batch); err != nil {
			p.metrics.shipErrors.Inc()
			if p.limiter.allow("ship") {
				p.log.Warn("log sink emit error (batch dropped)", "count", len(batch), "err", err)
			}
			continue
		}
		for _, e := range batch {
			p.metrics.shipped.WithLabelValues(e.Source).Inc()
		}
	}
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

// stop drains the pipeline in order: stop pollers, flush the queue through the
// emitter, persist final cursors, then flush the sink (bounded by ctx).
func (p *pipeline) stop(ctx context.Context) error {
	p.cancel()
	p.pollerWG.Wait()
	p.queue.close()
	p.emitterWG.Wait()
	p.persistState()
	return p.sink.Shutdown(ctx)
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

// logLimiter rate-limits repeated log lines keyed by a string.
type logLimiter struct {
	mu       sync.Mutex
	last     map[string]time.Time
	interval time.Duration
}

func newLogLimiter(interval time.Duration) *logLimiter {
	return &logLimiter{last: map[string]time.Time{}, interval: interval}
}

func (l *logLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if t, ok := l.last[key]; ok && now.Sub(t) < l.interval {
		return false
	}
	l.last[key] = now
	return true
}
