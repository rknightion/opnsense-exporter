package logship

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/rknightion/opnsense2otel/v4/internal/options"
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

func (s *flakySink) Emit(_ context.Context, batch []Entry) SinkResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.always || s.calls <= s.failN {
		return retryResult(batch, errors.New("export refused"))
	}
	return ackedResult(batch)
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

func (s *blockingSink) Emit(_ context.Context, batch []Entry) SinkResult {
	select {
	case s.started <- struct{}{}:
	default:
	}
	<-s.release
	return ackedResult(batch)
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

// --- #394: stage-correct freshness ----------------------------------------
//
// The old logs_last_event_timestamp_seconds was advanced right after queue ADMISSION
// using the record's SOURCE-ORIGIN timestamp, but documented and alerted as "the last
// event shipped". Three ways that lied: it moved before the sink acknowledged
// anything, it regressed on out-of-order input, and — because an enabled syslog
// receiver listens on all interfaces with an empty peer allowlist by default — any
// admitted sender could push it years into the future and silently suppress the
// stalled-source alert. It is REPLACED (not deprecated) by two exporter-clock gauges.

// Export freshness must advance ONLY when the sink acknowledges. A batch retried twice
// then delivered advances it exactly once, at acknowledgement.
func TestShipBatch_ExportFreshnessAdvancesOnlyOnAcknowledgement(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink := &flakySink{failN: 2}
	p, cancel := newDeliveryPipeline(sink, reg)
	defer cancel()

	before := float64(time.Now().Unix())
	p.shipBatch([]Entry{{Source: "firewall", Record: Record{Body: "a"}}})

	s := gatherSeries(t, reg)
	got, ok := s[`opnsense_exporter_logs_last_exported_timestamp_seconds{source="firewall"}`]
	if !ok {
		t.Fatal("logs_last_exported_timestamp_seconds is absent after an acknowledged delivery")
	}
	if got < before {
		t.Fatalf("export freshness = %v, want >= %v (the acknowledgement time)", got, before)
	}
}

// A batch the sink never acknowledges must NOT advance export freshness — that is the
// whole point of splitting the gauge. Before #394 the single gauge had already moved at
// admission, so a wedged sink looked healthy.
func TestShipBatch_ExportFreshnessNeverAdvancesForAbandonedBatch(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink := &flakySink{always: true}
	p, cancel := newDeliveryPipeline(sink, reg)
	cancel() // shutdown already in progress

	p.shipBatch([]Entry{{Source: "firewall", Record: Record{Body: "a"}}})

	s := gatherSeries(t, reg)
	if v, ok := s[`opnsense_exporter_logs_last_exported_timestamp_seconds{source="firewall"}`]; ok {
		t.Fatalf("export freshness = %v for a batch that was never delivered; want the series absent", v)
	}
}

// The ambiguous gauge is REMOVED outright (owner decision on #449): no alias, no
// deprecation window. A rebuilt alias would leave the dashboards ambiguous for another
// release cycle, and the run is cutting a major anyway.
func TestMetrics_LastEventTimestampGaugeIsGone(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink := &flakySink{}
	p, cancel := newDeliveryPipeline(sink, reg)
	defer cancel()
	p.shipBatch([]Entry{{Source: "firewall", Record: Record{Body: "a", Timestamp: time.Now()}}})

	for key := range gatherSeries(t, reg) {
		if strings.HasPrefix(key, "opnsense_exporter_logs_last_event_timestamp_seconds") {
			t.Fatalf("%s still exists; it was removed in favour of the last_received/last_exported pair", key)
		}
	}
}

// The OTLP sink must surface a failed export from Emit, not swallow it the way the old
// fire-and-forget Logger.Emit path did (#290) — that signal is what lets the pipeline
// retry instead of counting an undelivered batch as shipped. Since #392 it surfaces as
// the batch coming back in Retry rather than as a bare error.
func TestOTLPSink_EmitReturnsErrorWhenExportFails(t *testing.T) {
	s := newTestSink(erroringExporter{})
	batch := []Entry{{Source: "syslog", Record: Record{
		Body:       "denied",
		Attributes: map[string]string{AttrSubsystem: "firewall"},
	}}}
	res := s.Emit(context.Background(), batch)
	if len(res.Acked) != 0 {
		t.Fatal("Emit acknowledged records despite the exporter failing every Export")
	}
	if len(res.Retry) != 1 || res.Err == nil {
		t.Fatalf("Emit returned %+v; want the batch back for retry with the underlying error", res)
	}
	_ = s.Shutdown(context.Background())
}

// --- #392: the pipeline's side of the resource-aware contract ---------------

// partitionedSink acknowledges some entries, terminally rejects others and asks for the
// rest back, in one call — the shape a real OTLP sink produces when one resource
// partition succeeds, a second is refused and a third fails transiently.
type partitionedSink struct {
	mu     sync.Mutex
	calls  int
	result func(batch []Entry) SinkResult
	seen   [][]string
}

func (s *partitionedSink) Emit(_ context.Context, batch []Entry) SinkResult {
	s.mu.Lock()
	s.calls++
	got := make([]string, 0, len(batch))
	for _, e := range batch {
		got = append(got, e.Record.Body)
	}
	s.seen = append(s.seen, got)
	fn := s.result
	s.mu.Unlock()
	return fn(batch)
}

func (s *partitionedSink) Shutdown(context.Context) error { return nil }

func (s *partitionedSink) attempts() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]string(nil), s.seen...)
}

// The pipeline must count each record exactly once and re-send only what came back in
// Retry. An acknowledged record being resent is the duplication bug; an acknowledged
// record counted as dropped is the undercounting bug the issue warns against trading
// it for.
func TestShipBatch_RetriesOnlyTheUnacknowledgedRemainder(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink := &partitionedSink{}
	sink.result = func(batch []Entry) SinkResult {
		sink.mu.Lock()
		first := sink.calls == 1
		sink.mu.Unlock()
		if !first {
			return ackedResult(batch)
		}
		// a=acked, b=terminally rejected, c=retryable
		return SinkResult{
			Acked:    []Entry{batch[0]},
			Rejected: []Entry{batch[1]},
			Retry:    []Entry{batch[2]},
			Err:      errors.New("mixed partition outcome"),
		}
	}
	p, cancel := newDeliveryPipeline(sink, reg)
	defer cancel()

	p.shipBatch([]Entry{
		{Source: "firewall", Record: Record{Body: "a"}},
		{Source: "firewall", Record: Record{Body: "b"}},
		{Source: "firewall", Record: Record{Body: "c"}},
	})

	got := sink.attempts()
	if len(got) != 2 {
		t.Fatalf("sink called %d times, want 2 (initial + one retry): %v", len(got), got)
	}
	if !slices.Equal(got[1], []string{"c"}) {
		t.Fatalf("retry carried %v, want only the unacknowledged remainder [c]", got[1])
	}

	s := gatherSeries(t, reg)
	if v := s[`opnsense_exporter_logs_shipped_total{source="firewall"}`]; v != 2 {
		t.Fatalf("shipped=%v, want 2 (a acknowledged on attempt 1, c on attempt 2)", v)
	}
	if v := s[`opnsense_exporter_logs_dropped_total{reason="rejected",source="firewall"}`]; v != 1 {
		t.Fatalf("dropped{rejected}=%v, want 1 (b was terminally refused)", v)
	}
	// The three families must reconcile: every record is either shipped or dropped,
	// exactly once, and an acknowledged record is never counted as dropped.
	var droppedTotal float64
	for _, reason := range []string{"overflow", "record_too_large", "rejected", "ship_failed", "ship_failed_permanent"} {
		droppedTotal += s[`opnsense_exporter_logs_dropped_total{reason="`+reason+`",source="firewall"}`]
	}
	if total := s[`opnsense_exporter_logs_shipped_total{source="firewall"}`] + droppedTotal; total != 3 {
		t.Fatalf("shipped+dropped=%v, want exactly 3 — the logical batch must reconcile", total)
	}
	if v := s[`opnsense_exporter_logs_ship_errors_total`]; v != 1 {
		t.Fatalf("ship_errors=%v, want 1 (attempt 1 did not fully deliver; attempt 2 did)", v)
	}
}

// A terminal rejection must cost ONE wire attempt, not --logs.ship-max-attempts of
// them, and must be counted under its own reason so an operator can tell "the endpoint
// refuses this payload" from "the endpoint is down".
func TestShipBatch_TerminalRejectionIsNotRetried(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink := &partitionedSink{result: func(batch []Entry) SinkResult {
		return SinkResult{Rejected: batch, Err: errors.New("400 bad request")}
	}}
	p, cancel := newDeliveryPipeline(sink, reg)
	defer cancel()
	p.cfg.ShipMaxAttempts = 10

	p.shipBatch([]Entry{{Source: "firewall", Record: Record{Body: "a"}}})

	if n := len(sink.attempts()); n != 1 {
		t.Fatalf("sink called %d times for a permanent refusal, want exactly 1", n)
	}
	s := gatherSeries(t, reg)
	if v := s[`opnsense_exporter_logs_dropped_total{reason="rejected",source="firewall"}`]; v != 1 {
		t.Fatalf("dropped{rejected}=%v, want 1", v)
	}
	if v := s[`opnsense_exporter_logs_dropped_total{reason="ship_failed_permanent",source="firewall"}`]; v != 0 {
		t.Fatalf("dropped{ship_failed_permanent}=%v, want 0 — this was a refusal, not exhausted retries", v)
	}
	if v := s[`opnsense_exporter_logs_shipped_total{source="firewall"}`]; v != 0 {
		t.Fatalf("shipped=%v, want 0 — a refused record was never delivered", v)
	}
	if _, ok := s[`opnsense_exporter_logs_last_exported_timestamp_seconds{source="firewall"}`]; ok {
		t.Fatal("export freshness advanced for a terminally rejected batch; it must track acknowledgement only")
	}
}

// A batch that is fully acknowledged in one call must not touch the error counter — the
// mixed-outcome bookkeeping must not start counting successes as failures.
func TestShipBatch_CleanDeliveryCountsNoShipError(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink := &partitionedSink{result: ackedResult}
	p, cancel := newDeliveryPipeline(sink, reg)
	defer cancel()

	p.shipBatch([]Entry{{Source: "firewall", Record: Record{Body: "a"}}})

	s := gatherSeries(t, reg)
	if v := s[`opnsense_exporter_logs_ship_errors_total`]; v != 0 {
		t.Fatalf("ship_errors=%v, want 0 for a clean delivery", v)
	}
	if v := s[`opnsense_exporter_logs_shipped_total{source="firewall"}`]; v != 1 {
		t.Fatalf("shipped=%v, want 1", v)
	}
}
