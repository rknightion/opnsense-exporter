package logship

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/rknightion/opnsense2otel/v4/internal/options"
)

// gaugeValue reads the current value of a prometheus.Gauge, mirroring
// counterValue in metrics_test.go (a Gauge writes into dto.Metric.Gauge, not
// .Counter, so the two helpers cannot share an implementation).
func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var d dto.Metric
	if err := g.Write(&d); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	return d.GetGauge().GetValue()
}

// newTestPipeline builds a minimal pipeline (queue + metrics + limiter) with no
// sink or goroutines, for exercising the push-source path in isolation.
func newTestPipeline(t *testing.T, capacity int) *pipeline {
	t.Helper()
	p := &pipeline{
		cfg:     &options.LogsConfig{BufferSize: capacity, BatchMax: capacity},
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		limiter: NewLogLimiter(time.Second, errorLogMaxKeys),
	}
	p.queue = newBoundedQueue(capacity, func(Entry) {})
	p.metrics = newMetrics(prometheus.NewRegistry(), queueBounds{capacity: capacity, length: func() float64 { return float64(p.queue.length()) }}, sourceNames{})
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
			batch, ok := p.queue.drainUpTo(n-len(out), 0)
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

// fakePushOverride is a PushSource that also implements ExtraSourceNames, mirroring
// the syslog receiver delegating Zenarmor records to a different logical source
// (Task S). It emits one record with a Source override and one plain record.
type fakePushOverride struct{}

func (f *fakePushOverride) Name() string { return "fake" }

func (f *fakePushOverride) ExtraSourceNames() []string { return []string{"zenarmor"} }

func (f *fakePushOverride) Run(ctx context.Context, emit func(Record)) error {
	emit(Record{Body: "override", Source: "zenarmor", Timestamp: time.Unix(1700000001, 0)})
	emit(Record{Body: "plain", Timestamp: time.Unix(1700000002, 0)})
	<-ctx.Done()
	return nil
}

// A record with Record.Source set ships under that source, not the emitter's own
// Name(); a record with no Source set is byte-identical to today (src stays
// Name(), lastEvent stays the default hoisted gauge).
func TestPushSourceRecordSourceOverride(t *testing.T) {
	p := newTestPipeline(t, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.runPushSource(ctx, &fakePushOverride{})

	batch := drainN(t, p, 2, 2*time.Second)
	bySource := map[string]Entry{}
	for _, e := range batch {
		bySource[e.Record.Body] = e
	}

	override, ok := bySource["override"]
	if !ok {
		t.Fatal("override record never reached the sink")
	}
	if override.Source != "zenarmor" {
		t.Errorf("override record Entry.Source = %q, want zenarmor", override.Source)
	}

	plain, ok := bySource["plain"]
	if !ok {
		t.Fatal("plain record never reached the sink")
	}
	if plain.Source != "fake" {
		t.Errorf("plain record Entry.Source = %q, want the emitter's own Name() (fake)", plain.Source)
	}

	// The override source's own receive gauge is set from the pre-hoisted
	// extraLastReceived map, and the default gauge is advanced only by the plain record.
	// Both read the EXPORTER's clock, not the records' 2023 origin timestamps (#394) —
	// asserting they are NOT those values is the whole point: an origin timestamp must
	// never be able to set source-liveness, in either direction.
	for _, src := range []string{"zenarmor", "fake"} {
		got := gaugeValue(t, p.metrics.lastReceived.WithLabelValues(src))
		if got == 1700000001 || got == 1700000002 {
			t.Errorf("lastReceived{source=%s} = %v, which is the record's origin timestamp; it must be the exporter clock", src, got)
		}
		if got < float64(time.Now().Add(-time.Minute).Unix()) {
			t.Errorf("lastReceived{source=%s} = %v, want a recent exporter-clock stamp", src, got)
		}
	}
}

// #394: a record's own timestamp — future-dated, stale or zero — must not move the
// receive-freshness gauge in either direction. With the syslog receiver enabled, UDP
// listens on all interfaces and an empty peer allowlist accepts any sender, so before
// this an admitted line claiming a timestamp a decade out pinned the gauge into the
// future and `time() - gauge` went negative, silently suppressing the stalled-source
// alert for as long as the sender kept it there.
func TestPushSourceReceiveFreshnessIgnoresOriginTimestamp(t *testing.T) {
	p := newTestPipeline(t, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	future := time.Now().Add(10 * 365 * 24 * time.Hour)
	go p.runPushSource(ctx, &timestampAbusingPush{stamps: []time.Time{
		future,          // a sender-controlled timestamp far in the future
		time.Unix(1, 0), // then an ancient one, out of order
		{},              // then no timestamp at all
	}})
	drainN(t, p, 3, 2*time.Second)

	got := gaugeValue(t, p.metrics.lastReceived.WithLabelValues("stamps"))
	now := float64(time.Now().Unix())
	if got > now+60 {
		t.Errorf("lastReceived = %v, which is in the future; a sender pushed process freshness forward", got)
	}
	if got < now-60 {
		t.Errorf("lastReceived = %v, far behind now; an out-of-order or zero origin timestamp regressed it", got)
	}
}

// timestampAbusingPush emits one record per supplied origin timestamp, including a
// zero one (which the old code skipped entirely, so a source that never dated its
// records advanced nothing and read as permanently stalled).
type timestampAbusingPush struct{ stamps []time.Time }

func (f *timestampAbusingPush) Name() string { return "stamps" }

func (f *timestampAbusingPush) Run(ctx context.Context, emit func(Record)) error {
	for _, ts := range f.stamps {
		emit(Record{Body: "line", Timestamp: ts})
	}
	<-ctx.Done()
	return nil
}

// #318: a record larger than --logs.max-record-bytes must be rejected BEFORE it
// enters the queue, and counted under its own reason. Rejecting at ingest is what
// stops one oversized record from later becoming a batch the sink permanently
// refuses (#325a).
func TestPushSourceRejectsOversizedRecord(t *testing.T) {
	p := newTestPipeline(t, 16)
	p.cfg.MaxRecordBytes = 256
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go p.runPushSource(ctx, &fakePushBodies{bodies: []string{string(make([]byte, 4096)), "small"}})

	got := drainN(t, p, 1, 2*time.Second)
	if got[0].Record.Body != "small" {
		t.Fatalf("oversized record reached the queue: body len %d", len(got[0].Record.Body))
	}
	if v := counterValue(t, p.metrics.dropped.WithLabelValues("fake", dropReasonRecordTooLarge)); v != 1 {
		t.Errorf("logs_dropped_total{source=fake,reason=%s} = %v, want 1", dropReasonRecordTooLarge, v)
	}
}

// MaxRecordBytes = 0 disables the per-record cap.
func TestPushSourceOversizedAllowedWhenCapDisabled(t *testing.T) {
	p := newTestPipeline(t, 16)
	p.cfg.MaxRecordBytes = 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go p.runPushSource(ctx, &fakePushBodies{bodies: []string{string(make([]byte, 4096))}})

	got := drainN(t, p, 1, 2*time.Second)
	if len(got[0].Record.Body) != 4096 {
		t.Fatalf("record rejected with the per-record cap disabled: body len %d", len(got[0].Record.Body))
	}
}

// fakePushBodies emits one record per body, then blocks on ctx.
type fakePushBodies struct{ bodies []string }

func (f *fakePushBodies) Name() string { return "fake" }

func (f *fakePushBodies) Run(ctx context.Context, emit func(Record)) error {
	for _, b := range f.bodies {
		emit(Record{Body: b, Timestamp: time.Unix(1700000000, 0)})
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
