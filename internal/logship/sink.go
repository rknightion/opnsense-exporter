package logship

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/rknightion/opnsense-exporter/internal/options"
)

// SinkResult is the outcome of ONE Sink.Emit call. It replaces the old
// all-or-nothing `error` return (#392), which forced the pipeline to resend a whole
// logical batch whenever any part of it failed.
//
// The three entry lists PARTITION the batch handed to Emit: every entry appears in
// exactly one of them, and Acked+Rejected+Retry always sums to len(batch). The
// pipeline relies on that — it counts Acked as shipped, Rejected as dropped, and
// re-Emits only Retry — so a Sink that loses or duplicates an entry across the three
// silently miscounts delivery. sinkResultCoversBatch asserts the invariant in tests.
//
// WHY THREE LISTS AND NOT AN ERROR. The OTLP logs exporter reports three materially
// different things through one opaque `error`, and treating them alike is what made
// the old seam lose data both ways: a transient 503 must be retried, an HTTP 400 or a
// gRPC InvalidArgument must NOT be (retrying a permanent rejection burns the whole
// --logs.ship-max-attempts budget for nothing), and a populated OTLP partial-success
// response must not be resent AT ALL — the spec forbids it, and resending duplicates
// every record the server already accepted.
type SinkResult struct {
	// Acked are the entries the destination CONFIRMED it accepted. They are counted
	// logs_shipped_total and never sent again.
	Acked []Entry
	// Rejected are the entries the destination TERMINALLY refused: a permanent
	// protocol response (HTTP 400, gRPC InvalidArgument/Unauthenticated), or the
	// rejected share of an OTLP partial success. They are counted
	// logs_dropped_total{reason="rejected"} and never sent again, because another
	// attempt would be refused identically.
	//
	// CAVEAT ON IDENTITY, and it is the whole reason this is a count and not a set:
	// OTLP partial success reports HOW MANY records the server rejected, never WHICH.
	// For that case the sink moves an arbitrary N entries of the affected partition
	// here. That is count-exact per source — a partition is one (source, subsystem,
	// action) resource, so every entry in it shares a source — but it is NOT a claim
	// that these specific records are the ones the server dropped. Nothing downstream
	// may treat membership of this list as per-record knowledge; both this list and
	// Acked are terminal, so the distinction only ever moves a counter.
	Rejected []Entry
	// Retry are the entries that were NOT delivered but may succeed on another
	// attempt: a transient protocol response (HTTP 429/502/503/504, retryable gRPC
	// codes), a transport failure, or any outcome the sink could not classify. The
	// pipeline re-Emits exactly these, bounded by --logs.ship-max-attempts.
	Retry []Entry
	// Err carries the underlying failure(s) for logging. It is diagnostic only: the
	// pipeline decides what to do from the three lists, never by inspecting this.
	Err error
}

// ackedResult reports a fully acknowledged batch.
func ackedResult(batch []Entry) SinkResult { return SinkResult{Acked: batch} }

// retryResult reports a batch that was not delivered and should be retried whole.
// It is the honest answer for any failure a sink cannot attribute more precisely.
func retryResult(batch []Entry, err error) SinkResult {
	return SinkResult{Retry: batch, Err: err}
}

// Sink is the delivery target for shipped log entries. Implementations: the OTLP
// logs sink (sink_otlp.go) and the stdout JSON sink (sink_stdout.go).
type Sink interface {
	// Emit ships a batch of entries and reports, per entry, what the destination did
	// with it. It must account for every entry it was handed (see SinkResult).
	Emit(ctx context.Context, batch []Entry) SinkResult
	// Shutdown flushes any buffered data and releases resources, bounded by ctx.
	Shutdown(ctx context.Context) error
}

// buildSink constructs the configured sink. For the OTLP sink it fails fast with
// an actionable error when no endpoint is resolvable.
func buildSink(cfg *options.LogsConfig, transport *options.OTLPConfig, version, instance string, log *slog.Logger) (Sink, error) {
	switch cfg.Sink {
	case "stdout":
		return newStdoutSink(), nil
	case "otlp":
		if transport == nil {
			return nil, fmt.Errorf("logs sink=otlp requires an OTLP transport; set the --otlp.* flags (e.g. --otlp.endpoint)")
		}
		return newOTLPSink(transport, version, instance, cfg.ShipConcurrency, log)
	default:
		return nil, fmt.Errorf("unknown logs sink %q", cfg.Sink)
	}
}
