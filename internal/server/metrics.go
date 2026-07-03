package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// scrapeTimeoutHeader is set by Prometheus on every scrape to the configured
// scrape timeout in (possibly fractional) seconds.
const scrapeTimeoutHeader = "X-Prometheus-Scrape-Timeout-Seconds"

// ScrapeViews is the slice of *collector.Collector the metrics handler needs:
// per-request filtered, deadline-bound views plus the valid collector names.
type ScrapeViews interface {
	ScrapeView(ctx context.Context, include map[string]bool) prometheus.Collector
	EnabledCollectorNames() []string
}

type metricsHandler struct {
	views         ScrapeViews
	self          prometheus.Gatherer
	timeoutOffset time.Duration
	log           *slog.Logger
}

// NewMetricsHandler returns the /metrics handler. Per request it parses
// node_exporter-style collect[]/exclude[] filters and the Prometheus scrape
// timeout header, registers a single-request ScrapeView into a fresh registry
// (descriptors are never re-registered globally — the view subsets the shared
// collector's fan-out), and serves it merged with the static self gatherer
// (process_*/go_* metrics).
func NewMetricsHandler(views ScrapeViews, self prometheus.Gatherer, timeoutOffset time.Duration, log *slog.Logger) http.Handler {
	return &metricsHandler{views: views, self: self, timeoutOffset: timeoutOffset, log: log}
}

func (h *metricsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	include, err := parseCollectorFilters(query["collect[]"], query["exclude[]"], h.views.EnabledCollectorNames())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// The request context is the base, so an aborted scrape cancels in-flight
	// API calls even without the timeout header.
	ctx := r.Context()
	if timeout, ok := scrapeTimeout(r.Header.Get(scrapeTimeoutHeader), h.timeoutOffset); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	reg := prometheus.NewRegistry()
	if err := reg.Register(h.views.ScrapeView(ctx, include)); err != nil {
		h.log.Error("failed to register scrape view", "err", err)
		http.Error(w, "failed to build metrics handler", http.StatusInternalServerError)
		return
	}

	promhttp.HandlerFor(
		prometheus.Gatherers{h.self, reg},
		// ContinueOnError (not the zero-value HTTPErrorOnError) so a single
		// collector emitting a duplicate label tuple degrades to a logged
		// warning plus a partial scrape, instead of a blanket HTTP 500 that
		// drops every collector's series and the self/process metrics too (#81).
		promhttp.HandlerOpts{
			ErrorHandling: promhttp.ContinueOnError,
			ErrorLog:      promErrorLogger{log: h.log},
		},
	).ServeHTTP(w, r)
}

// promErrorLogger adapts a *slog.Logger to promhttp.Logger so Gather errors
// (e.g. duplicate label tuples) are surfaced in structured logs rather than
// silently swallowed by the default nil ErrorLog.
type promErrorLogger struct{ log *slog.Logger }

func (l promErrorLogger) Println(v ...any) {
	l.log.Warn("error gathering metrics for scrape", "err", strings.TrimSuffix(fmt.Sprintln(v...), "\n"))
}

// parseCollectorFilters turns collect[]/exclude[] query parameters into an
// include set. nil means "all enabled collectors"; a non-nil (possibly empty)
// map means "exactly these".
func parseCollectorFilters(collect, exclude, valid []string) (map[string]bool, error) {
	if len(collect) > 0 && len(exclude) > 0 {
		return nil, fmt.Errorf("collect[] and exclude[] parameters are mutually exclusive")
	}
	if len(collect) == 0 && len(exclude) == 0 {
		return nil, nil
	}

	validSet := make(map[string]bool, len(valid))
	for _, name := range valid {
		validSet[name] = true
	}
	requested := collect
	if len(exclude) > 0 {
		requested = exclude
	}
	for _, name := range requested {
		if !validSet[name] {
			// valid is sorted by EnabledCollectorNames.
			return nil, fmt.Errorf("unknown collector %q; valid collectors: %s", name, strings.Join(valid, ", "))
		}
	}

	include := make(map[string]bool)
	if len(collect) > 0 {
		for _, name := range collect {
			include[name] = true
		}
		return include, nil
	}

	excluded := make(map[string]bool, len(exclude))
	for _, name := range exclude {
		excluded[name] = true
	}
	for _, name := range valid {
		if !excluded[name] {
			include[name] = true
		}
	}
	return include, nil
}

// scrapeTimeout derives the collection budget from Prometheus' scrape-timeout
// header. The offset is subtracted so the exporter serializes its response
// before Prometheus gives up; if the offset would consume the entire budget,
// the raw header value is used. Missing, malformed or non-positive headers
// yield ok=false (no deadline beyond the request context).
func scrapeTimeout(header string, offset time.Duration) (time.Duration, bool) {
	if header == "" {
		return 0, false
	}
	seconds, err := strconv.ParseFloat(header, 64)
	if err != nil || seconds <= 0 {
		return 0, false
	}
	timeout := time.Duration(seconds * float64(time.Second))
	if timeout > offset {
		return timeout - offset, true
	}
	return timeout, true
}
