package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/rknightion/opnsense2otel/v5/internal/options"
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
//
// reg is the exporter's self-metrics registry. When non-nil, the OTLP delivery-health
// series (opnsense_exporter_otlp_*, see delivery.go) are registered on it and every
// export call is booked there — which is the only local evidence that push is
// actually reaching the backend, since a successful Start proves nothing. reg may be
// nil, in which case nothing is registered and delivery accounting is skipped.
//
// A non-nil error means nothing is running: callers treat construction failure while
// OTLP is requested as fatal rather than starting a silently dead push pipeline.
func Start(
	ctx context.Context,
	gatherers []prometheus.Gatherer,
	cfg *options.OTLPConfig,
	version, instance string,
	reg prometheus.Registerer,
	log *slog.Logger,
	fastGatherers ...prometheus.Gatherer,
) (func(context.Context) error, error) {
	rawExporter, err := newExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("build otlp exporter: %w", err)
	}

	// Wrap the exporter BEFORE the reader owns it, so every export call the SDK
	// makes is booked in the self-metrics registry (#388). The decorator observes
	// only: it returns the exporter's error unchanged, so the rate-limited
	// slogErrorHandler installed below still logs it. A nil reg yields nil metrics
	// and the raw exporter is used undecorated.
	delivery := newDeliveryMetrics(reg)
	exporter := observeExports(rawExporter, delivery)

	// Append a synthetic `up = 1` gatherer scoped to the OTLP stream only. It
	// reinstates the target-up series that a Prometheus scraper would generate for
	// free but that push mode has no source for, so `up`-based liveness alerts keep
	// working over OTLP. It is intentionally NOT part of the /metrics registries
	// (where a literal `up` would collide with the scraper's own).
	upGatherer, err := newSyntheticUpGatherer(instance)
	if err != nil {
		return nil, fmt.Errorf("build synthetic up gatherer: %w", err)
	}
	gatherers = append(gatherers, upGatherer)

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
	readers := []sdkmetric.Reader{reader}

	// Optional second lane (#390): fast-tier collectors export at their own, shorter
	// interval while everything else stays on the base interval. Off unless BOTH a
	// fast interval and a disjoint fast gatherer set are supplied, so the default
	// configuration builds exactly one reader as before.
	//
	// Disjointness is the caller's contract and is enforced upstream by the collector
	// lane views: the base lane carries every non-fast collector plus the health/self
	// block, the fast lane carries fast collectors only. Two readers emitting the same
	// series identity would double-report it to the backend.
	//
	// A SECOND exporter is constructed rather than sharing one: the MeterProvider
	// shuts down each reader, and each reader shuts down its exporter, so sharing one
	// would Shutdown it twice. Both are wrapped by the same delivery metrics, so
	// exports_total counts real export calls across both lanes.
	if cfg.FastExportInterval > 0 && len(fastGatherers) > 0 {
		fastRawExporter, ferr := newExporter(ctx, cfg)
		if ferr != nil {
			_ = reader.Shutdown(context.Background())
			return nil, fmt.Errorf("build fast-lane otlp exporter: %w", ferr)
		}
		fastOpts := make([]prometheusbridge.Option, 0, len(fastGatherers))
		for _, g := range fastGatherers {
			fastOpts = append(fastOpts, prometheusbridge.WithGatherer(
				&continueOnErrorGatherer{inner: g, log: log, interval: errorLogInterval}))
		}
		readers = append(readers, sdkmetric.NewPeriodicReader(
			observeExports(fastRawExporter, delivery),
			sdkmetric.WithInterval(cfg.FastExportInterval),
			sdkmetric.WithProducer(prometheusbridge.NewMetricProducer(fastOpts...)),
		))
	}

	res, rerr := buildResource(ctx, cfg, version, instance, metricsResourceIncludesServiceVersion)
	if rerr != nil {
		// resource.New can return a usable resource alongside a partial/schema
		// warning. Treat a nil resource as fatal; otherwise log and proceed. The
		// reader has already started its background goroutine, so shut it down
		// before bailing to avoid leaking it.
		if res == nil {
			for _, r := range readers {
				_ = r.Shutdown(context.Background())
			}
			return nil, fmt.Errorf("build otlp resource: %w", rerr)
		}
		log.Warn("otlp resource built with warnings", "err", rerr)
	}

	// Both readers hang off ONE MeterProvider, so the single Shutdown returned below
	// flushes and stops both within the caller's existing bounded shutdown contract.
	mpOpts := make([]sdkmetric.Option, 0, len(readers)+1)
	for _, r := range readers {
		mpOpts = append(mpOpts, sdkmetric.WithReader(r))
	}
	mpOpts = append(mpOpts, sdkmetric.WithResource(res))
	mp := sdkmetric.NewMeterProvider(mpOpts...)
	otel.SetMeterProvider(mp)
	otel.SetErrorHandler(&slogErrorHandler{log: log, interval: errorLogInterval})

	// Construction failure is fatal at the call site, so a returned Start is always
	// an actually-running pipeline: there is no configured-but-inactive state to
	// model. This says "export is running", NOT "export is working" — that is what
	// otlp_last_success_timestamp_seconds and otlp_consecutive_failures are for.
	delivery.markEnabled()

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
