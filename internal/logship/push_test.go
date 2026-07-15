package logship

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/internal/options"
)

// newTestPipeline builds a minimal pipeline (queue + metrics + limiter) with no
// sink or goroutines, for exercising the push-source path in isolation.
func newTestPipeline(t *testing.T, capacity int) *pipeline {
	t.Helper()
	p := &pipeline{
		cfg:     &options.LogsConfig{BufferSize: capacity, BatchMax: capacity},
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		limiter: newLogLimiter(time.Second),
	}
	p.queue = newBoundedQueue(capacity, func(Entry) {})
	p.metrics = newMetrics(prometheus.NewRegistry(), capacity, func() float64 { return float64(p.queue.length()) })
	return p
}

// drainN collects exactly n entries. It CLOSES the queue on a timeout, because
// boundedQueue.drainUpTo BLOCKS until an entry arrives or the queue is closed
// (queue.go:57-64) — a naive deadline loop would hang forever instead of failing.
func drainN(t *testing.T, p *pipeline, n int, d time.Duration) []Entry {
	t.Helper()
	done := make(chan []Entry, 1)
	go func() {
		var out []Entry
		for len(out) < n {
			batch, ok := p.queue.drainUpTo(n - len(out))
			if !ok {
				break
			}
			out = append(out, batch...)
		}
		done <- out
	}()
	select {
	case out := <-done:
		if len(out) != n {
			t.Fatalf("drained %d entries, want %d", len(out), n)
		}
		return out
	case <-time.After(d):
		p.queue.close() // unblock the drainer so the test FAILS rather than hangs
		t.Fatalf("timed out waiting for %d records", n)
		return nil
	}
}

type fakePush struct {
	n     int
	attrs map[string]string
	err   error
}

func (f *fakePush) Name() string { return "fake" }

func (f *fakePush) Run(ctx context.Context, emit func(Record)) error {
	for i := 0; i < f.n; i++ {
		emit(Record{Body: "line", Timestamp: time.Unix(1700000000, 0), Attributes: f.attrs})
	}
	if f.err != nil {
		return f.err
	}
	<-ctx.Done()
	return nil
}

func TestPushSourceEmitsIntoQueue(t *testing.T) {
	p := newTestPipeline(t, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.runPushSource(ctx, &fakePush{n: 3})

	batch := drainN(t, p, 3, 2*time.Second)
	for _, e := range batch {
		if e.Source != "fake" {
			t.Errorf("Source = %q, want fake", e.Source)
		}
		if e.Record.Body != "line" {
			t.Errorf("Body = %q, want line", e.Record.Body)
		}
	}
}

// A push source must not be able to forge the resource identity.
func TestPushSourceReservedAttributesStripped(t *testing.T) {
	p := newTestPipeline(t, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.runPushSource(ctx, &fakePush{n: 1, attrs: map[string]string{"opnsense.source": "forged", "keep": "yes"}})

	got := drainN(t, p, 1, 2*time.Second)[0].Record.Attributes
	if _, ok := got["opnsense.source"]; ok {
		t.Error(`reserved key "opnsense.source" must be stripped`)
	}
	if got["keep"] != "yes" {
		t.Error("non-reserved attributes must survive")
	}
}

// A Run error (with ctx still live) is counted and does not restart the source.
func TestPushSourceRunErrorCounted(t *testing.T) {
	p := newTestPipeline(t, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		p.runPushSource(ctx, &fakePush{n: 0, err: io.ErrUnexpectedEOF})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runPushSource did not return after Run errored")
	}
	if got := counterValue(t, p.metrics.pollErrors.WithLabelValues("fake")); got != 1 {
		t.Errorf("logs_poll_errors_total{source=fake} = %v, want 1", got)
	}
}

// stop() waits on pollerWG with NO timeout, so a push source that ignores ctx
// would hang the exporter forever on SIGTERM. This proves the contract: a push
// source registered on the pipeline does not prevent stop() from returning.
func TestPushSourceDoesNotBlockStop(t *testing.T) {
	p := newTestPipeline(t, 8)
	sink := &fakeSink{}
	p.sink = sink
	pctx, cancel := context.WithCancel(context.Background())
	p.ctx, p.cancel = pctx, cancel

	p.emitterWG.Add(1)
	go p.runEmitter()

	s := &fakePush{n: 2}
	p.pushSources = []PushSource{s}
	p.pollerWG.Add(1)
	go func() {
		defer p.pollerWG.Done()
		p.runPushSource(p.ctx, s)
	}()

	done := make(chan error, 1)
	go func() { done <- p.stop(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stop: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stop() did not return: a push source blocked pollerWG.Wait()")
	}
	if got := len(sink.got()); got != 2 {
		t.Errorf("sink got %d entries, want 2 (queue must drain on stop)", got)
	}
}
