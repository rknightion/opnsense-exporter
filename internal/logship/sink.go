package logship

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/rknightion/opnsense-exporter/internal/options"
)

// Sink is the delivery target for shipped log entries. Implementations: the OTLP
// logs sink (sink_otlp.go) and the stdout JSON sink (sink_stdout.go).
type Sink interface {
	// Emit ships a batch of entries. A returned error is counted
	// (logs_ship_errors_total) and the batch is dropped; the pipeline continues.
	Emit(ctx context.Context, batch []Entry) error
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
		return newOTLPSink(transport, version, instance, log)
	default:
		return nil, fmt.Errorf("unknown logs sink %q", cfg.Sink)
	}
}
