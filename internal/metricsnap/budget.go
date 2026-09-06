package metricsnap

import (
	"log/slog"
	"sync"
	"time"

	dto "github.com/prometheus/client_model/go"
)

// budgetRepeatInterval bounds how often the over-budget warning repeats while
// the condition persists. See SeriesBudget's doc comment for the full policy.
const budgetRepeatInterval = time.Hour

// SeriesBudget configures the optional soft total-series budget check (#494)
// performed on every real capture that flows through Recorder.Tee / TeeLane.
// It is reporting only: nothing is ever dropped, capped or refused when the
// budget is exceeded.
//
// The check runs where the Recorder already sees every real scrape's family
// set — inside the Tee/TeeLane Gather it already wraps — rather than on a
// separate timer or poller, so it needs no Gather() of its own and naturally
// goes silent when nothing is scraping.
type SeriesBudget struct {
	// Total is the soft budget, in total series across every lane the Recorder
	// merges. Total <= 0 disables the check entirely: no log is ever emitted,
	// regardless of the observed series count.
	//
	// This counts COLLECTOR registry series only — the same set /metrics and
	// the OTLP bridge serve, and what Capture/Snapshot already report. It does
	// NOT include the separate self-metrics registry (process_*/go_*,
	// opnsense_exporter_otlp_* delivery-health), so it will always read lower
	// than a scrape's full response. See --exporter.series-budget's flag help
	// for the same caveat stated to operators.
	Total int
	// Logger receives the rate-limited warning/info lines. A nil Logger makes
	// the check a no-op even when Total > 0 (nothing to log to).
	Logger *slog.Logger
	// Now returns the current time; defaults to time.Now when nil. Overridable
	// so tests can drive the hourly repeat window without a wall-clock sleep.
	Now func() time.Time
	// Observed, when non-nil, is called with the current total collector
	// series count on every real Gather — independent of whether Total is
	// configured — so a caller (the opnsense_exporter_series
	// self-metric) can stay current without this package depending on the
	// collector package.
	Observed func(total int)
}

// budgetState is the Recorder's rate-limiting state for the over-budget log.
// Guarded by its own mutex, separate from Recorder.mu, since it is read/written
// after the lane-capture lock has already been released.
type budgetState struct {
	mu         sync.Mutex
	overBudget bool
	lastLogAt  time.Time
}

// ConfigureSeriesBudget wires the soft total-series budget check into every
// subsequent Tee/TeeLane Gather. Call once at startup, before serving —
// concurrent calls to ConfigureSeriesBudget itself are not supported (there is
// no use case for reconfiguring at runtime today), but it is safe to read
// concurrently with Gather once set.
func (r *Recorder) ConfigureSeriesBudget(cfg SeriesBudget) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	r.mu.Lock()
	r.budget = cfg
	r.mu.Unlock()
}

// totalSeriesOf sums the series (individual metric/label-tuple entries) across
// every family, the same count buildCardinality/webui report as TotalSeries.
func totalSeriesOf(mfs []*dto.MetricFamily) int {
	total := 0
	for _, mf := range mfs {
		total += len(mf.GetMetric())
	}
	return total
}

// observeSeries runs the configured budget's Observed callback and the
// rate-limited over/under-budget log transitions for one just-completed
// Gather's resulting total.
func (r *Recorder) observeSeries(total int, cfg SeriesBudget) {
	if cfg.Observed != nil {
		cfg.Observed(total)
	}
	if cfg.Total <= 0 || cfg.Logger == nil {
		return
	}

	now := time.Now()
	if cfg.Now != nil {
		now = cfg.Now()
	}

	r.budgetState.mu.Lock()
	defer r.budgetState.mu.Unlock()

	over := total >= cfg.Total
	switch {
	case over && !r.budgetState.overBudget:
		cfg.Logger.Warn("total collector series exceeded configured budget",
			"series_total", total, "series_budget", cfg.Total)
		r.budgetState.overBudget = true
		r.budgetState.lastLogAt = now
	case over && r.budgetState.overBudget:
		if now.Sub(r.budgetState.lastLogAt) >= budgetRepeatInterval {
			cfg.Logger.Warn("total collector series still exceeds configured budget",
				"series_total", total, "series_budget", cfg.Total)
			r.budgetState.lastLogAt = now
		}
	case !over && r.budgetState.overBudget:
		cfg.Logger.Info("total collector series back under configured budget",
			"series_total", total, "series_budget", cfg.Total)
		r.budgetState.overBudget = false
		r.budgetState.lastLogAt = time.Time{}
	}
}
