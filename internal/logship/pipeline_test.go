package logship

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/internal/options"
)

// --- test doubles ---------------------------------------------------------

type fakeSource struct {
	name    string
	mu      sync.Mutex
	batches [][]Record
	polls   int
	err     error
	// stateful bits
	loaded   []byte
	saveData []byte
	minEvery time.Duration
}

func (f *fakeSource) Name() string { return f.name }

func (f *fakeSource) Poll(context.Context) ([]Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.polls++
	if f.err != nil {
		return nil, f.err
	}
	if len(f.batches) == 0 {
		return nil, nil
	}
	b := f.batches[0]
	f.batches = f.batches[1:]
	return b, nil
}

func (f *fakeSource) pollCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.polls
}

type statefulFakeSource struct{ *fakeSource }

func (s statefulFakeSource) LoadState(data []byte) { s.loaded = data }
func (s statefulFakeSource) SaveState() ([]byte, bool) {
	return s.saveData, s.saveData != nil
}
func (s statefulFakeSource) MinInterval() time.Duration { return s.minEvery }

type fakeSink struct {
	mu       sync.Mutex
	entries  []Entry
	emitErr  error
	shutdown bool
}

func (s *fakeSink) Emit(_ context.Context, batch []Entry) SinkResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.emitErr != nil {
		return retryResult(batch, s.emitErr)
	}
	s.entries = append(s.entries, batch...)
	return ackedResult(batch)
}

func (s *fakeSink) Shutdown(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shutdown = true
	return nil
}

func (s *fakeSink) got() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Entry(nil), s.entries...)
}

// withRegistry swaps the package source registry for the duration of a test.
func withRegistry(t *testing.T, factories ...SourceFactory) {
	t.Helper()
	saved := registeredFactories
	registeredFactories = append([]SourceFactory(nil), factories...)
	t.Cleanup(func() { registeredFactories = saved })
}

// startWithSink is like Start but injects a sink, bypassing sink construction
// (so the pipeline can be tested without a live OTLP endpoint). It mirrors
// Start's wiring.
func startWithSink(t *testing.T, cfg *options.LogsConfig, sink Sink, deps Deps, reg prometheus.Registerer, selfLogs ...*SelfLogHandler) func(context.Context) error {
	t.Helper()
	var selfLog *SelfLogHandler
	for _, candidate := range selfLogs {
		if candidate != nil {
			selfLog = candidate
			break
		}
	}
	// Resolve the logger roles through the same helper Start uses, so this
	// mirror cannot drift from the production split.
	sourceLog, pipelineLog := splitDiagnosticLoggers(deps.Logger, selfLog)
	if selfLog != nil {
		deps.Logger = pipelineLog
	}
	sources, err := buildSources(deps)
	if err != nil {
		t.Fatalf("buildSources: %v", err)
	}
	pctx, cancel := context.WithCancel(context.Background())
	p := &pipeline{
		sink: sink, cfg: cfg, log: deps.Logger, sourceLog: sourceLog, selfLog: selfLog,
		sources: sources, stateFile: cfg.StateFile,
		ctx: pctx, cancel: cancel, limiter: NewLogLimiter(errorLogInterval, errorLogMaxKeys),
	}
	p.queue = newBoundedQueue(cfg.BufferSize, p.noteOverflow)
	p.metrics = newMetrics(reg, queueBounds{capacity: cfg.BufferSize, length: func() float64 { return float64(p.queue.length()) }}, sourceNames{})
	if selfLog != nil {
		selfLog.Bind(func(e Entry) bool {
			e.Record.Attributes = sanitizeAttributes(e.Record.Attributes)
			_, ok := p.enqueue(e)
			return ok
		})
		t.Cleanup(selfLog.Unbind)
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
		p.pollerWG.Add(1)
		go p.runPoller(s, p.effectiveInterval(s))
	}
	if p.stateFile != "" && len(p.stateful) > 0 {
		p.pollerWG.Add(1)
		go p.runStateFlusher()
	}
	return p.stop
}

func testCfg() *options.LogsConfig {
	return &options.LogsConfig{Sink: "otlp", PollInterval: 5 * time.Millisecond, BufferSize: 4096, BatchMax: 1000}
}

func testDeps() Deps { return Deps{Logger: slog.New(slog.NewTextHandler(os.Stderr, nil))} }

// --- tests ----------------------------------------------------------------

func TestPipeline_ShipsAndStampsSource(t *testing.T) {
	src := &fakeSource{name: "firewall", batches: [][]Record{{
		{Body: "line-1", Attributes: map[string]string{"src": "10.0.0.1", "opnsense.source": "forged"}},
	}}}
	withRegistry(t, func(Deps) (Source, error) { return src, nil })
	sink := &fakeSink{}
	stop := startWithSink(t, testCfg(), sink, testDeps(), prometheus.NewRegistry())

	waitFor(t, func() bool { return len(sink.got()) >= 1 })
	_ = stop(context.Background())

	got := sink.got()
	if got[0].Source != "firewall" {
		t.Fatalf("source not stamped: %q", got[0].Source)
	}
	if _, ok := got[0].Record.Attributes["opnsense.source"]; ok {
		t.Fatal("reserved 'opnsense.source' attribute was not stripped from the record")
	}
	if got[0].Record.Attributes["src"] != "10.0.0.1" {
		t.Fatalf("structured metadata lost: %v", got[0].Record.Attributes)
	}
}

func TestPipeline_NoEnabledSourcesIsNoOp(t *testing.T) {
	withRegistry(t) // none
	stop, err := Start(context.Background(), testCfg(), &options.OTLPConfig{}, testDeps(), "v", "inst", prometheus.NewRegistry())
	if err != nil {
		t.Fatalf("Start with no sources should not error: %v", err)
	}
	if err := stop(context.Background()); err != nil {
		t.Fatalf("no-op stop should not error: %v", err)
	}
}

func TestPipeline_DisabledFactorySkipped(t *testing.T) {
	withRegistry(t, func(Deps) (Source, error) { return nil, nil }) // disabled
	stop, err := Start(context.Background(), testCfg(), &options.OTLPConfig{}, testDeps(), "v", "inst", prometheus.NewRegistry())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	_ = stop(context.Background())
}

func TestPipeline_FactoryErrorAborts(t *testing.T) {
	withRegistry(t, func(Deps) (Source, error) { return nil, errors.New("boom") })
	_, err := Start(context.Background(), testCfg(), &options.OTLPConfig{}, testDeps(), "v", "inst", prometheus.NewRegistry())
	if err == nil {
		t.Fatal("expected Start to abort on factory error")
	}
}

func TestPipeline_StopDrainsQueue(t *testing.T) {
	// A slow-emitting sink so entries are still queued at stop; stop must flush.
	src := &fakeSource{name: "s", batches: [][]Record{
		{{Body: "a"}, {Body: "b"}, {Body: "c"}},
	}}
	withRegistry(t, func(Deps) (Source, error) { return src, nil })
	sink := &fakeSink{}
	cfg := testCfg()
	cfg.PollInterval = time.Hour // poll once immediately, never again
	stop := startWithSink(t, cfg, sink, testDeps(), prometheus.NewRegistry())
	waitFor(t, func() bool { return src.pollCount() >= 1 })
	_ = stop(context.Background())
	if len(sink.got()) != 3 {
		t.Fatalf("stop did not drain all queued entries: got %d", len(sink.got()))
	}
	if !sink.shutdown {
		t.Fatal("sink.Shutdown not called")
	}
}

func TestPipeline_StateFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	// First run: source persists cursor "cursor-1".
	base := &fakeSource{name: "firewall", saveData: []byte("cursor-1")}
	withRegistry(t, func(Deps) (Source, error) { return statefulFakeSource{base}, nil })
	cfg := testCfg()
	cfg.Sink = "stdout"
	cfg.StateFile = statePath
	cfg.PollInterval = time.Hour
	stop := startWithSink(t, cfg, &fakeSink{}, testDeps(), prometheus.NewRegistry())
	waitFor(t, func() bool { return base.pollCount() >= 1 })
	_ = stop(context.Background()) // final persistState writes the file

	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("state file not written: %v", err)
	}

	// Second run: a fresh source must receive the persisted blob via LoadState.
	base2 := &fakeSource{name: "firewall"}
	withRegistry(t, func(Deps) (Source, error) { return statefulFakeSource{base2}, nil })
	stop2 := startWithSink(t, cfg, &fakeSink{}, testDeps(), prometheus.NewRegistry())
	waitFor(t, func() bool { return base2.pollCount() >= 1 })
	_ = stop2(context.Background())

	if string(base2.loaded) != "cursor-1" {
		t.Fatalf("LoadState did not restore cursor: got %q", string(base2.loaded))
	}
}

// alwaysFailSink rejects every batch and records the first record body of each
// distinct batch it was handed, so a test can tell "the emitter is still retrying
// batch 1" apart from "the emitter moved on to batch 2".
type alwaysFailSink struct {
	mu       sync.Mutex
	attempts int
	seen     []string
}

func (s *alwaysFailSink) Emit(_ context.Context, batch []Entry) SinkResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	if len(batch) > 0 {
		s.seen = append(s.seen, batch[0].Record.Body)
	}
	return retryResult(batch, errors.New("permanently refused"))
}

func (s *alwaysFailSink) Shutdown(context.Context) error { return nil }

func (s *alwaysFailSink) sawBody(body string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.seen {
		if b == body {
			return true
		}
	}
	return false
}

// #325a: there is exactly ONE emitter goroutine, so an unbounded retry loop on a
// batch the sink permanently refuses never returns to drainUpTo — every later
// record silently oldest-drops behind it. With ShipMaxAttempts set, the emitter
// must abandon the poison batch (counted under reason="ship_failed_permanent")
// and go on to attempt the NEXT batch.
//
// Against the pre-fix code this test times out: the emitter is still retrying
// batch "first" and never drains "second".
func TestPipeline_PermanentShipFailureDoesNotWedgeEmitter(t *testing.T) {
	sink := &alwaysFailSink{}
	reg := prometheus.NewRegistry()
	cfg := testCfg()
	cfg.BatchMax = 1 // one record per batch, so "first" and "second" are separate batches
	cfg.ShipMaxAttempts = 2

	pctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &pipeline{
		sink: sink, cfg: cfg, log: testDeps().Logger,
		ctx: pctx, cancel: cancel,
		limiter: NewLogLimiter(errorLogInterval, errorLogMaxKeys),
	}
	p.queue = newBoundedQueue(cfg.BufferSize, p.noteOverflow)
	p.metrics = newMetrics(reg, queueBounds{capacity: cfg.BufferSize, length: func() float64 { return float64(p.queue.length()) }}, sourceNames{all: []string{"s"}})

	p.emitterWG.Add(1)
	go p.runEmitter()

	p.queue.push(Entry{Source: "s", Record: Record{Body: "first"}})
	p.queue.push(Entry{Source: "s", Record: Record{Body: "second"}})

	deadline := time.Now().Add(5 * time.Second)
	for !sink.sawBody("second") {
		if time.Now().After(deadline) {
			t.Fatal("emitter wedged: the second batch was never attempted " +
				"(the first batch is being retried forever)")
		}
		time.Sleep(2 * time.Millisecond)
	}

	// The abandoned first batch must be visible, and under its own reason so it is
	// distinguishable from the shutdown-time ship_failed drop.
	if got := counterValue(t, p.metrics.dropped.WithLabelValues("s", dropReasonShipFailedPermanent)); got < 1 {
		t.Fatalf("logs_dropped_total{source=s,reason=%s} = %v, want >= 1", dropReasonShipFailedPermanent, got)
	}
	if got := counterValue(t, p.metrics.dropped.WithLabelValues("s", dropReasonShipFailed)); got != 0 {
		t.Fatalf("logs_dropped_total{source=s,reason=%s} = %v, want 0 "+
			"(nothing was abandoned at shutdown; the two reasons must stay distinct)", dropReasonShipFailed, got)
	}

	cancel()
	p.queue.close()
	p.emitterWG.Wait()
}

// ShipMaxAttempts = 0 must preserve the pre-#325 unlimited-retry behaviour: a
// transient failure is ridden out rather than dropped.
func TestPipeline_ShipMaxAttemptsZeroRetriesUnbounded(t *testing.T) {
	reg := prometheus.NewRegistry()
	p, cancel := newDeliveryPipeline(&flakySink{failN: 3}, reg)
	defer cancel()
	p.cfg.ShipMaxAttempts = 0

	p.shipBatch([]Entry{{Source: "firewall", Record: Record{Body: "a"}}})

	if got := counterValue(t, p.metrics.shipped.WithLabelValues("firewall")); got != 1 {
		t.Fatalf("logs_shipped_total{source=firewall} = %v, want 1 (unlimited retries must ride out 3 failures)", got)
	}
	if got := counterValue(t, p.metrics.dropped.WithLabelValues("firewall", dropReasonShipFailedPermanent)); got != 0 {
		t.Fatalf("logs_dropped_total{reason=%s} = %v, want 0 with ShipMaxAttempts=0", dropReasonShipFailedPermanent, got)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}

// TestPipeline_SourcePollErrorReachesTheLogBackend pins the diagnostic that made
// the OPN-0060 delivery proof inconclusive: configstate stopped delivering, its
// logs_poll_errors_total moved, and the reason existed only on the exporter's
// stderr because Start routed EVERY pipeline diagnostic to the non-forwarding
// handler.
//
// The recursion guard that motivated that routing covers sink, retry and
// shutdown diagnostics - all of which describe the delivery path and would
// manufacture another record per failed attempt. A source poll error describes
// the firewall side and cannot recur as a consequence of being shipped, so it
// belongs on the forwarding handler.
func TestPipeline_SourcePollErrorReachesTheLogBackend(t *testing.T) {
	src := &fakeSource{name: "configstate", err: errors.New("snapshot fetch failed")}
	withRegistry(t, func(Deps) (Source, error) { return src, nil })

	selfLog := NewSelfLogHandler(slog.NewTextHandler(io.Discard, nil))
	deps := Deps{Logger: slog.New(selfLog)}
	sink := &fakeSink{}
	stop := startWithSink(t, testCfg(), sink, deps, prometheus.NewRegistry(), selfLog)

	waitFor(t, func() bool {
		for _, e := range sink.got() {
			if e.Source == SelfLogSource && strings.Contains(e.Record.Body, "log source poll error") {
				return true
			}
		}
		return false
	})
	_ = stop(context.Background())

	var shipped *Entry
	for i, e := range sink.got() {
		if e.Source == SelfLogSource && strings.Contains(e.Record.Body, "log source poll error") {
			shipped = &sink.got()[i]
			break
		}
	}
	if shipped == nil {
		t.Fatal("poll-error diagnostic never reached the sink")
	}
	if got := shipped.Record.Attributes["source"]; got != "configstate" {
		t.Errorf("shipped poll error source = %q, want %q", got, "configstate")
	}
	if got := shipped.Record.Attributes["err"]; got != "snapshot fetch failed" {
		t.Errorf("shipped poll error reason = %q, want the underlying error", got)
	}
}

// TestPipeline_SinkDiagnosticsStayOffTheWire is the other half of the split: a
// sink diagnostic must never re-enter the queue it is complaining about.
func TestPipeline_SinkDiagnosticsStayOffTheWire(t *testing.T) {
	selfLog := NewSelfLogHandler(slog.NewTextHandler(io.Discard, nil))
	var forwarded int
	selfLog.Bind(func(Entry) bool { forwarded++; return true })
	t.Cleanup(selfLog.Unbind)

	_, pipelineLog := splitDiagnosticLoggers(slog.New(selfLog), selfLog)
	pipelineLog.Error("log sink export failed; retrying", "attempt", 3)

	if forwarded != 0 {
		t.Fatalf("sink diagnostic entered the self-log queue %d times, want 0", forwarded)
	}
}
