package logship

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/internal/options"
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

func (s *fakeSink) Emit(_ context.Context, batch []Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.emitErr != nil {
		return s.emitErr
	}
	s.entries = append(s.entries, batch...)
	return nil
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
func startWithSink(t *testing.T, cfg *options.LogsConfig, sink Sink, deps Deps, reg prometheus.Registerer) func(context.Context) error {
	t.Helper()
	sources, err := buildSources(deps)
	if err != nil {
		t.Fatalf("buildSources: %v", err)
	}
	pctx, cancel := context.WithCancel(context.Background())
	p := &pipeline{
		sink: sink, cfg: cfg, log: deps.Logger,
		sources: sources, stateFile: cfg.StateFile,
		ctx: pctx, cancel: cancel, limiter: NewLogLimiter(errorLogInterval, errorLogMaxKeys),
	}
	p.queue = newBoundedQueue(cfg.BufferSize, p.noteOverflow)
	p.metrics = newMetrics(reg, cfg.BufferSize, func() float64 { return float64(p.queue.length()) }, sourceNames{})
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
