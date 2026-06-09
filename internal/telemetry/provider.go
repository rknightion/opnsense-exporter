package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/internal/options"
	prometheusbridge "go.opentelemetry.io/contrib/bridges/prometheus"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// errorLogInterval bounds how often OTLP/SDK internal errors are logged, so a
// flapping endpoint cannot flood the logs. Suppressed errors are counted and the
// count is surfaced with the next emitted log line.
const errorLogInterval = 30 * time.Second

// Start builds and installs an OTLP-exporting MeterProvider backed by a Prometheus
// bridge producer over the supplied gatherer (the exporter's existing registry).
// It returns the provider's Shutdown function, which flushes a final export and
// releases resources; callers invoke it during graceful shutdown. Start performs no
// network I/O: the OTLP exporter connects lazily on the first export tick, so a
// transient endpoint outage does not block startup.
func Start(
	ctx context.Context,
	gatherer prometheus.Gatherer,
	cfg *options.OTLPConfig,
	version, instance string,
	log *slog.Logger,
) (func(context.Context) error, error) {
	exporter, err := newExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("build otlp exporter: %w", err)
	}

	producer := prometheusbridge.NewMetricProducer(prometheusbridge.WithGatherer(gatherer))
	reader := sdkmetric.NewPeriodicReader(
		exporter,
		sdkmetric.WithInterval(cfg.ExportInterval),
		sdkmetric.WithProducer(producer),
	)

	res, rerr := buildResource(ctx, cfg, version, instance)
	if rerr != nil {
		// resource.New can return a usable resource alongside a partial/schema
		// warning. Treat a nil resource as fatal; otherwise log and proceed. The
		// reader has already started its background goroutine, so shut it down
		// before bailing to avoid leaking it.
		if res == nil {
			_ = reader.Shutdown(context.Background())
			return nil, fmt.Errorf("build otlp resource: %w", rerr)
		}
		log.Warn("otlp resource built with warnings", "err", rerr)
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(reader),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(mp)
	otel.SetErrorHandler(&slogErrorHandler{log: log, interval: errorLogInterval})

	return mp.Shutdown, nil
}

// slogErrorHandler routes OTEL SDK internal errors (e.g. failed exports) to slog,
// rate-limited to one line per interval with a suppressed-count rollup.
type slogErrorHandler struct {
	log      *slog.Logger
	interval time.Duration

	mu      sync.Mutex
	last    time.Time
	dropped int
}

func (h *slogErrorHandler) Handle(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if !h.last.IsZero() && now.Sub(h.last) < h.interval {
		h.dropped++
		return
	}
	if h.dropped > 0 {
		h.log.Warn("otlp export errors suppressed", "count", h.dropped, "window", h.interval.String())
		h.dropped = 0
	}
	h.last = now
	h.log.Warn("otlp export error", "err", err)
}
