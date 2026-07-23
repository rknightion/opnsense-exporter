package logship

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/rknightion/opnsense-exporter/internal/options"
)

// flakySink fails its first failN Emit calls (or every call, when always is set) then
// succeeds. Emit is driven serially by the single emitter; the mutex only guards the
// call counter for a test goroutine that reads it.
type flakySink struct {
	mu     sync.Mutex
	calls  int
	failN  int
	always bool
}

func (s *flakySink) Emit(context.Context, []Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.always || s.calls <= s.failN {
		return errors.New("export refused")
	}
	return nil
}
func (s *flakySink) Shutdown(context.Context) error { return nil }
func (s *flakySink) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// blockingSink blocks inside Emit until release is closed, signalling started once.
type blockingSink struct {
	started chan struct{}
	release chan struct{}
}

func (s *blockingSink) Emit(context.Context, []Entry) error {
	select {
	case s.started <- struct{}{}:
	default:
	}
	<-s.release
	return nil
}
func (s *blockingSink) Shutdown(context.Context) error { return nil }

// erroringExporter fails every Export, to prove the sink surfaces the failure as a
// returned error rather than swallowing it.
type erroringExporter struct{}

func (erroringExporter) Export(context.Context, []sdklog.Record) error {
	return errors.New("endpoint unavailable")
}
func (erroringExporter) Shutdown(context.Context) error   { return nil }
func (erroringExporter) ForceFlush(context.Context) error { return nil }

func newDeliveryPipeline(sink Sink, reg prometheus.Registerer) (*pipeline, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &pipeline{
		sink:    sink,
		cfg:     &options.LogsConfig{BatchMax: 100, BufferSize: 100},
		log:     slog.New(slog.NewTextHandler(os.Stderr, nil)),
		ctx:     ctx,
		cancel:  cancel,
		limiter: NewLogLimiter(errorLogInterval, errorLogMaxKeys),
	}
	p.queue = newBoundedQueue(100, func(Entry) {})
	p.metrics = newMetrics(reg, queueBounds{capacity: 100, length: func() float64 { return 0 }}, sourceNames{all: []string{"firewall"}})
	return p, cancel
}

// A transient export failure must NOT lose records or count them as shipped: the batch
// is retried in memory until the endpoint recovers, then shipped exactly once (#290).
func TestShipBatch_RetriesTransientFailureThenShips(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink := &flakySink{failN: 2}
	p, cancel := newDeliveryPipeline(sink, reg)
	defer cancel()

	p.shipBatch([]Entry{
		{Source: "firewall", Record: Record{Body: "a"}},
		{Source: "firewall", Record: Record{Body: "b"}},
	})

	s := gatherSeries(t, reg)
	if got := s[`opnsense_exporter_logs_shipped_total{source="firewall"}`]; got != 2 {
		t.Fatalf("shipped=%v, want 2 (both records delivered after retry)", got)
	}
	if got := s[`opnsense_exporter_logs_ship_errors_total`]; got != 2 {
		t.Fatalf("ship_errors=%v, want 2 (two transient failures observed)", got)
	}
	if got := s[`opnsense_exporter_logs_dropped_total{reason="ship_failed",source="firewall"}`]; got != 0 {
		t.Fatalf("ship_failed=%v, want 0 (nothing permanently lost)", got)
	}
	if c := sink.callCount(); c != 3 {
		t.Fatalf("sink Emit called %d times, want 3 (2 fail + 1 success)", c)
	}
}

// When the pipeline is shutting down and the endpoint is still failing, an undeliverable
// batch is abandoned and every record counted logs_dropped_total{reason="ship_failed"} —
// never silently skipped and never counted as shipped (#290).
func TestShipBatch_AbandonsUndeliverableBatchOnShutdown(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink := &flakySink{always: true}
	p, cancel := newDeliveryPipeline(sink, reg)
	cancel() // shutdown already in progress

	done := make(chan struct{})
	go func() {
		p.shipBatch([]Entry{{Source: "firewall", Record: Record{Body: "a"}}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shipBatch did not return promptly after shutdown; the drain would hang")
	}

	s := gatherSeries(t, reg)
	if got := s[`opnsense_exporter_logs_dropped_total{reason="ship_failed",source="firewall"}`]; got != 1 {
		t.Fatalf("ship_failed=%v, want 1 (the abandoned record is counted)", got)
	}
	if got := s[`opnsense_exporter_logs_shipped_total{source="firewall"}`]; got != 0 {
		t.Fatalf("shipped=%v, want 0 (it was never delivered)", got)
	}
	if got := s[`opnsense_exporter_logs_ship_errors_total`]; got < 1 {
		t.Fatalf("ship_errors=%v, want >=1", got)
	}
}

// stop must not report a clean flush when the emitter cannot finish before the shutdown
// deadline: it returns an error rather than letting cursors imply delivery (#290).
func TestStop_ReturnsErrorWhenDrainExceedsDeadline(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink := &blockingSink{started: make(chan struct{}, 1), release: make(chan struct{})}
	p, _ := newDeliveryPipeline(sink, reg)

	p.emitterWG.Add(1)
	go p.runEmitter()
	p.queue.push(Entry{Source: "firewall", Record: Record{Body: "a"}})
	<-sink.started // the emitter is now blocked inside Emit

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := p.stop(ctx)
	if err == nil {
		t.Fatal("stop reported a clean shutdown while the drain was still blocked")
	}

	close(sink.release) // let the emitter finish so the goroutine does not leak
}

// The OTLP sink must surface a failed export as a returned error from Emit, not swallow
// it the way the old fire-and-forget Logger.Emit path did (#290) — that error is what
// lets the pipeline retry instead of counting an undelivered batch as shipped.
func TestOTLPSink_EmitReturnsErrorWhenExportFails(t *testing.T) {
	s := newTestSink(erroringExporter{})
	batch := []Entry{{Source: "syslog", Record: Record{
		Body:       "denied",
		Attributes: map[string]string{AttrSubsystem: "firewall"},
	}}}
	if err := s.Emit(context.Background(), batch); err == nil {
		t.Fatal("Emit returned nil despite the exporter failing every Export")
	}
	_ = s.Shutdown(context.Background())
}
