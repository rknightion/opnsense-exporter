package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
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
// bridge producer over the supplied gatherers (typically the exporter self-metrics
// registry and the collector registry). Each gatherer is registered independently and
// wrapped in continue-on-error semantics so a metric-consistency error in one (e.g.
// duplicate label values from duplicated OPNsense config) cannot black out the whole
// export tick — the healthy families and the other registries still export (#101).
// It returns the provider's Shutdown function, which flushes a final export and
// releases resources; callers invoke it during graceful shutdown. Start performs no
// network I/O: the OTLP exporter connects lazily on the first export tick, so a
// transient endpoint outage does not block startup.
func Start(
	ctx context.Context,
	gatherers []prometheus.Gatherer,
	cfg *options.OTLPConfig,
	version, instance string,
	log *slog.Logger,
) (func(context.Context) error, error) {
	exporter, err := newExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("build otlp exporter: %w", err)
	}

	// One WithGatherer per registry so the bridge's per-gatherer error handling keeps
	// them isolated; each is wrapped so a partial-gather error yields the successfully
	// gathered families (mirroring promhttp.ContinueOnError) instead of nothing.
	opts := make([]prometheusbridge.Option, 0, len(gatherers))
	for _, g := range gatherers {
		opts = append(opts, prometheusbridge.WithGatherer(
			&continueOnErrorGatherer{inner: g, log: log, interval: errorLogInterval}))
	}
	producer := prometheusbridge.NewMetricProducer(opts...)
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

// continueOnErrorGatherer wraps a prometheus.Gatherer so a partial-gather
// inconsistency (e.g. duplicate label values from duplicated OPNsense config) does not
// black out the OTLP export tick. Registry/Gatherers.Gather returns the successfully
// collected families together with a MultiError, but the OTel bridge producer discards
// the partial families on any non-nil error. Mirroring promhttp.ContinueOnError, this
// returns the partial families with a nil error and logs the underlying error
// (rate-limited, so a persistent duplicate cannot flood the logs) so the
// misconfiguration is still visible (#101).
type continueOnErrorGatherer struct {
	inner    prometheus.Gatherer
	log      *slog.Logger
	interval time.Duration

	mu      sync.Mutex
	last    time.Time
	dropped int
}

func (g *continueOnErrorGatherer) Gather() ([]*dto.MetricFamily, error) {
	mfs, err := g.inner.Gather()
	if err != nil {
		g.logRateLimited(err)
	}
	return mfs, nil
}

func (g *continueOnErrorGatherer) logRateLimited(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if !g.last.IsZero() && now.Sub(g.last) < g.interval {
		g.dropped++
		return
	}
	if g.dropped > 0 {
		g.log.Warn("otlp gather errors suppressed", "count", g.dropped, "window", g.interval.String())
		g.dropped = 0
	}
	g.last = now
	g.log.Warn("otlp gather error (partial metrics still exported)", "err", err)
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
