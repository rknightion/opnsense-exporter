package logship

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rknightion/opnsense2otel/v5/internal/options"
)

// rateLimitingSink refuses the first refuseCalls Emit calls with a rate-limit verdict,
// recording the size of every batch it was handed, then accepts everything. It is the
// pipeline-side stand-in for a tenant whose bytes/sec budget rejects a large push and
// accepts a small one.
type rateLimitingSink struct {
	mu          sync.Mutex
	sizes       []int
	refuseAbove int // refuse any batch larger than this; 0 means refuse everything
	retryAfter  time.Duration
}

func (s *rateLimitingSink) Emit(_ context.Context, batch []Entry) SinkResult {
	s.mu.Lock()
	s.sizes = append(s.sizes, len(batch))
	refuse := len(batch) > s.refuseAbove
	ra := s.retryAfter
	s.mu.Unlock()
	if refuse {
		return SinkResult{
			Retry: batch,
			Err: &rateLimitError{
				retryAfter: ra,
				err:        errors.New("ingestion rate limit exceeded for user X"),
			},
		}
	}
	return ackedResult(batch)
}

func (s *rateLimitingSink) Shutdown(context.Context) error { return nil }

func (s *rateLimitingSink) batchSizes() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int(nil), s.sizes...)
}

func ratePipeline(t *testing.T, reg prometheus.Registerer, sink Sink) (*pipeline, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	p := &pipeline{
		sink:    sink,
		cfg:     &options.LogsConfig{BatchMax: 1024, BufferSize: 1024, ShipMaxAttempts: 10},
		log:     slog.New(slog.NewTextHandler(os.Stderr, nil)),
		ctx:     ctx,
		cancel:  cancel,
		limiter: NewLogLimiter(errorLogInterval, errorLogMaxKeys),
	}
	p.queue = newBoundedQueue(1024, p.noteOverflow)
	p.metrics = newMetrics(reg, queueBounds{capacity: 1024, length: func() float64 { return 0 }},
		sourceNames{all: []string{"syslog"}})
	return p, cancel
}

func rateEntries(n int) []Entry {
	out := make([]Entry, n)
	for i := range out {
		out[i] = Entry{Source: "syslog", Record: Record{Body: "line"}}
	}
	return out
}

// THE HEADLINE ACCEPTANCE CRITERION OF #663. A rate-limit refusal must cause a SPLIT,
// not an identical resend. The observed failure was the same 2777-record batch sent
// seven times unchanged; the sink here refuses anything above 128 records, so a pipeline
// that resends unchanged never delivers and a pipeline that splits does.
func TestShipBatch_RateLimitSplitsInsteadOfResending(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink := &rateLimitingSink{refuseAbove: 128, retryAfter: 0}
	p, cancel := ratePipeline(t, reg, sink)
	defer cancel()
	// Keep the test's wall clock sane: the pacing floor is what production uses, but
	// what is under test is the split, not the exact number of seconds slept.
	p.cfg.ShipMaxAttempts = 10

	batch := rateEntries(256)
	done := make(chan struct{})
	go func() { p.shipBatch(batch); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("shipBatch did not finish; a rate limit must not wedge the emitter")
	}

	sizes := sink.batchSizes()
	if len(sizes) < 2 {
		t.Fatalf("sink called %d times, want at least 2 (a refusal then a split retry): %v", len(sizes), sizes)
	}
	if sizes[0] != 256 {
		t.Fatalf("first attempt carried %d records, want the whole batch (256)", sizes[0])
	}
	// The core assertion: the SECOND attempt must not be the same request again.
	if sizes[1] >= sizes[0] {
		t.Fatalf("second attempt carried %d records after a rate limit, want fewer than %d — "+
			"an identical resend is refused identically forever: %v", sizes[1], sizes[0], sizes)
	}

	s := gatherSeries(t, reg)
	if got := s[`opnsense_exporter_logs_shipped_total{source="syslog"}`]; got != 256 {
		t.Fatalf("shipped=%v, want all 256 delivered by splitting: %v", got, sizes)
	}
	if got := s[`opnsense_exporter_logs_dropped_total{reason="ship_failed_permanent",source="syslog"}`]; got != 0 {
		t.Fatalf("ship_failed_permanent=%v, want 0 — splitting must deliver the batch, not drop it", got)
	}
}

// A rate limit must be PACED by the advertised Retry-After, not retried on the ordinary
// 200ms backoff. Measured as elapsed wall time on a single refusal, which is the only
// externally visible statement the pipeline makes about honouring the header.
func TestShipBatch_RateLimitHonoursAdvertisedRetryAfter(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink := &rateLimitingSink{refuseAbove: 1, retryAfter: 1500 * time.Millisecond}
	p, cancel := ratePipeline(t, reg, sink)
	defer cancel()

	start := time.Now()
	p.shipBatch(rateEntries(2))
	elapsed := time.Since(start)

	if elapsed < 1500*time.Millisecond {
		t.Fatalf("shipBatch took %s, want at least the advertised 1.5s Retry-After — "+
			"an unpaced retry is what turns one refusal into ten", elapsed)
	}
	if got := gatherSeries(t, reg)[`opnsense_exporter_logs_shipped_total{source="syslog"}`]; got != 2 {
		t.Fatalf("shipped=%v, want 2", got)
	}
}

// DROP ACCOUNTING MUST SURVIVE THE CHANGE (#663's last acceptance criterion). A batch
// that stays undeliverable through the whole attempt budget is counted
// ship_failed_permanent — the STUCK BATCH — and never under overflow, which means
// something else entirely: records evicted from the queue because the emitter was busy.
func TestShipBatch_RateLimitExhaustionKeepsDropReasonsDistinct(t *testing.T) {
	reg := prometheus.NewRegistry()
	// refuseAbove 0 => every batch is refused, however small the split gets.
	sink := &rateLimitingSink{refuseAbove: 0}
	p, cancel := ratePipeline(t, reg, sink)
	defer cancel()
	p.cfg.ShipMaxAttempts = 3

	// A record evicted from the queue by pressure is the OTHER loss mode; count one so
	// the two reasons are asserted side by side rather than in isolation.
	p.noteOverflow(Entry{Source: "syslog", Record: Record{Body: "evicted"}})

	p.shipBatch(rateEntries(4))

	s := gatherSeries(t, reg)
	if got := s[`opnsense_exporter_logs_dropped_total{reason="ship_failed_permanent",source="syslog"}`]; got != 4 {
		t.Fatalf("ship_failed_permanent=%v, want 4 (the whole undeliverable batch)", got)
	}
	if got := s[`opnsense_exporter_logs_dropped_total{reason="overflow",source="syslog"}`]; got != 1 {
		t.Fatalf("overflow=%v, want 1 — collateral queue eviction must stay a separate reason "+
			"from the stuck batch", got)
	}
	if got := s[`opnsense_exporter_logs_shipped_total{source="syslog"}`]; got != 0 {
		t.Fatalf("shipped=%v, want 0", got)
	}
	// The attempt cap still binds: splitting must not multiply the wire attempts.
	if n := len(sink.batchSizes()); n != 3 {
		t.Fatalf("sink called %d times with ShipMaxAttempts=3, want exactly 3 — splitting must "+
			"never buy extra attempts: %v", n, sink.batchSizes())
	}
}

// The learned split is STICKY across batches, which is what turns a sustained burst into
// steady paced delivery instead of one refused wire attempt per batch. The second batch
// must start at the size the first one learned, not back at full size.
func TestShipBatch_LearnedChunkCarriesToTheNextBatch(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink := &rateLimitingSink{refuseAbove: 128}
	p, cancel := ratePipeline(t, reg, sink)
	defer cancel()

	p.shipBatch(rateEntries(256))
	learned := p.shipChunk
	if learned <= 0 || learned >= 256 {
		t.Fatalf("shipChunk = %d after a rate limit, want a reduced positive cap", learned)
	}

	before := len(sink.batchSizes())
	p.shipBatch(rateEntries(256))
	sizes := sink.batchSizes()[before:]
	if sizes[0] != learned {
		t.Fatalf("second batch's first attempt carried %d records, want the learned %d — "+
			"re-learning the limit costs a refused wire attempt on every batch", sizes[0], learned)
	}
}

// A clean run must walk the learned cap back up, or a burst that ended hours ago leaves
// the pipeline paying per-chunk round-trips forever.
func TestShipBatch_LearnedChunkRelaxesOnCleanDelivery(t *testing.T) {
	reg := prometheus.NewRegistry()
	p, cancel := ratePipeline(t, reg, &partitionedSink{result: ackedResult})
	defer cancel()

	p.shipChunk = 64
	p.shipBatch(rateEntries(4))
	if p.shipChunk != 128 {
		t.Fatalf("shipChunk = %d after a clean batch, want 128 (one doubling)", p.shipChunk)
	}

	p.shipChunk = 600 // one doubling puts it past BatchMax=1024's half, clearing the cap
	p.shipBatch(rateEntries(4))
	if p.shipChunk != 0 {
		t.Fatalf("shipChunk = %d, want 0 — a cap at or above --logs.batch-max is doing nothing "+
			"and should be cleared rather than carried", p.shipChunk)
	}
}

// The classification must come from the PROTOCOL — an HTTP 429 with a Retry-After — and
// not from matching the endpoint's error prose, which is unversioned and Loki-specific.
// This drives the real exporter over a real socket.
func TestOTLPSink_HTTP429IsClassifiedAsRateLimitedWithRetryAfter(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	s := newSinkOverEndpoint(t, "http/protobuf", srv.URL)
	batch := []Entry{entry("syslog", "dns", "rate-limited")}
	res := s.Emit(context.Background(), batch)
	assertResultCoversBatch(t, res, batch)

	if len(res.Retry) != 1 {
		t.Fatalf("acked=%d rejected=%d retry=%d, want the batch handed back for a paced retry",
			len(res.Acked), len(res.Rejected), len(res.Retry))
	}
	delay, limited := rateLimitDelay(res.Err)
	if !limited {
		t.Fatalf("SinkResult.Err = %v, want a rate-limit verdict reachable via errors.As", res.Err)
	}
	if delay != 3*time.Second {
		t.Fatalf("advertised delay = %s, want 3s from the Retry-After header", delay)
	}
}

// An ordinary transient failure must NOT be classified as a rate limit: shrinking the
// batch for the rest of its life because one 503 arrived is a real cost, and 503 is by
// far the more common status.
func TestOTLPSink_ServiceUnavailableIsNotARateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	s := newSinkOverEndpoint(t, "http/protobuf", srv.URL)
	batch := []Entry{entry("syslog", "dns", "transient")}
	res := s.Emit(context.Background(), batch)
	assertResultCoversBatch(t, res, batch)

	if len(res.Retry) != 1 {
		t.Fatalf("retry=%d, want 1 (a 503 is retryable)", len(res.Retry))
	}
	if _, limited := rateLimitDelay(res.Err); limited {
		t.Fatal("a 503 was classified as a rate limit; only 429 / RESOURCE_EXHAUSTED may be")
	}
}

// RFC 9110 allows Retry-After in two forms and real gateways send both. Parsing only the
// integer form would silently read a real advertised delay as "none advertised".
func TestRetryAfterDelay(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		in   string
		want time.Duration
	}{
		{"delay seconds", "5", 5 * time.Second},
		{"http date", now.Add(7 * time.Second).UTC().Format(http.TimeFormat), 7 * time.Second},
		{"absent", "", 0},
		{"garbage", "soon", 0},
		{"past date", now.Add(-time.Hour).UTC().Format(http.TimeFormat), 0},
		{"negative seconds", "-5", 0},
		// An endpoint-controlled header must not be able to park the single emitter
		// goroutine for an hour while the queue behind it oldest-drops.
		{"clamped", "3600", maxRetryAfter},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := retryAfterDelay(tc.in, now); got != tc.want {
				t.Fatalf("retryAfterDelay(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

// The split must converge and must stop somewhere: halving to a single record trades one
// rejected request for hundreds of round-trips.
func TestSplitChunk(t *testing.T) {
	cases := []struct{ in, want int }{
		{2777, 1388},
		{128, 64},
		{64, 32},
		{48, shipRateLimitMinChunk},
		{32, 1},
		{1, 1},
	}
	for _, tc := range cases {
		if got := splitChunk(tc.in); got != tc.want {
			t.Fatalf("splitChunk(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// Nothing advertised must fall back to a pause measured in SECONDS. Falling back to the
// ordinary 200ms first-attempt backoff is what turns one rate-limit refusal into ten.
func TestPacingFor(t *testing.T) {
	if got := pacingFor(0); got != shipRateLimitPause {
		t.Fatalf("pacingFor(0) = %s, want the %s floor", got, shipRateLimitPause)
	}
	if got := pacingFor(50 * time.Millisecond); got != shipRateLimitPause {
		t.Fatalf("pacingFor(50ms) = %s, want the %s floor", got, shipRateLimitPause)
	}
	if got := pacingFor(9 * time.Second); got != 9*time.Second {
		t.Fatalf("pacingFor(9s) = %s, want the advertised 9s", got)
	}
}

// The ingest-rate bound and the transport backstop are different constraints and BOTH
// must hold. The transport one is a ceiling the operator cannot raise past.
func TestExportByteBound(t *testing.T) {
	cases := []struct {
		name string
		cfg  int
		want int
	}{
		{"default 1MiB ingest bound binds", 1 << 20, 1 << 20},
		{"zero falls back to the transport backstop", 0, maxExportBytes},
		{"negative falls back", -1, maxExportBytes},
		{"cannot be raised past the transport backstop", maxExportBytes * 4, maxExportBytes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &pipeline{cfg: &options.LogsConfig{MaxExportBytes: tc.cfg}}
			if got := p.exportByteBound(); got != tc.want {
				t.Fatalf("exportByteBound() = %d, want %d", got, tc.want)
			}
		})
	}
}
