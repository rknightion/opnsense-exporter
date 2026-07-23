package server

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rknightion/opnsense-exporter/internal/metricsnap"
)

// maxScrapeTimeoutSeconds bounds an accepted scrape-timeout header. Any real
// Prometheus scrape budget is far below 24h; a larger (client-controlled) value is
// rejected so it cannot overflow time.Duration or effectively disable the budget.
const maxScrapeTimeoutSeconds = 86400

// scrapeTimeoutHeader is set by Prometheus on every scrape to the configured
// scrape timeout in (possibly fractional) seconds.
const scrapeTimeoutHeader = "X-Prometheus-Scrape-Timeout-Seconds"

// maxMetricsInFlight bounds concurrent /metrics scrapes; overflow is answered
// 503 (the same degradation promhttp's own MaxRequestsInFlight applies). The
// exporter's listener has no authentication by default, so without a bound any
// reachable client can force an unbounded number of simultaneous gathers, each
// of which materializes a full copy of the metric set in memory.
//
// Post-#336 a scrape replays the in-memory snapshot and never calls the
// firewall, so this bounds in-process CPU/memory only — nothing upstream. That
// makes a generous value cheap: 40 leaves headroom for the primary scraper, a
// handful of federating scrapers, ad-hoc curls and a slow-reader backlog all at
// once, while still capping the worst case at a bounded multiple of one
// response. Legitimate traffic should never reach it.
const maxMetricsInFlight = 40

// metricsWriteDeadline bounds how long one scrape response may take to write.
// promhttp gathers the entire metric set into memory before writing a byte, so a
// client that reads its response slowly — or opens a connection and never reads
// at all — pins that gathered set plus a goroutine for as long as it likes.
// Server.IdleTimeout does not help: it covers idle keep-alive connections, not
// one that is actively dribbling. The server's Server.WriteTimeout is
// deliberately unset (a large scrape must never be truncated on other routes),
// so the cap is applied per-request here instead, scoped to /metrics only.
//
// Two minutes is far beyond any real scrape budget (Prometheus defaults to 10s
// and caps at the scrape interval), so it can only ever fire on a stuck or
// malicious reader.
const metricsWriteDeadline = 2 * time.Minute

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
	// recorder, when non-nil, passively captures the collector family set of each
	// UNFILTERED scrape so the web UI can read a last-scrape snapshot without ever
	// gathering (and thus re-scraping the firewall) itself. Filtered scrapes
	// (collect[]/exclude[]) are not recorded, so a partial view can't clobber it.
	recorder *metricsnap.Recorder
	// inFlight is the concurrency semaphore for this handler, capacity
	// maxMetricsInFlight. It lives on the handler rather than in the
	// promhttp.HandlerOpts below because promhttp builds its semaphore inside
	// HandlerFor, and HandlerFor is called once PER REQUEST here (each scrape
	// needs its own filtered, deadline-bound registry). Setting
	// HandlerOpts.MaxRequestsInFlight would therefore hand every request a
	// private semaphore that can never fill — a silent no-op. This one is
	// created once in NewMetricsHandler and shared, so it actually bounds.
	inFlight chan struct{}
}

// NewMetricsHandler returns the /metrics handler. Per request it parses
// node_exporter-style collect[]/exclude[] filters and the Prometheus scrape
// timeout header, registers a single-request ScrapeView into a fresh registry
// (descriptors are never re-registered globally — the view subsets the shared
// collector's fan-out), and serves it merged with the static self gatherer
// (process_*/go_* metrics).
func NewMetricsHandler(views ScrapeViews, self prometheus.Gatherer, timeoutOffset time.Duration, log *slog.Logger, recorder *metricsnap.Recorder) http.Handler {
	return &metricsHandler{
		views:         views,
		self:          self,
		timeoutOffset: timeoutOffset,
		log:           log,
		recorder:      recorder,
		inFlight:      make(chan struct{}, maxMetricsInFlight),
	}
}

func (h *metricsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Bound concurrent scrapes before doing any work. Overflow gets 503 with the
	// same wording promhttp uses, so operators reading exporter docs recognise it.
	select {
	case h.inFlight <- struct{}{}:
		defer func() { <-h.inFlight }()
	default:
		http.Error(w, fmt.Sprintf(
			"Limit of concurrent requests reached (%d), try again later.", maxMetricsInFlight,
		), http.StatusServiceUnavailable)
		return
	}

	// Bound how long this response may take to write, so a slow or non-reading
	// client cannot pin a fully-gathered metric set and a goroutine indefinitely.
	// The deadline is cleared on the way out: net/http only resets write deadlines
	// per request when Server.WriteTimeout is set, and it deliberately is not — an
	// uncleared deadline would leak onto the next request on a kept-alive
	// connection (including requests to other routes) and fail it instantly.
	// ErrNotSupported (any ResponseWriter wrapper without Unwrap, and every
	// httptest.ResponseRecorder) is expected and ignored: this is best-effort
	// hardening, never a correctness requirement.
	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Now().Add(metricsWriteDeadline)); err == nil {
		defer func() { _ = rc.SetWriteDeadline(time.Time{}) }()
	}

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

	// On an unfiltered scrape, tee the collector view through the recorder so the
	// web UI's last-scrape snapshot stays fresh — without the UI ever gathering.
	collectorGatherer := prometheus.Gatherer(reg)
	if h.recorder != nil && include == nil {
		collectorGatherer = h.recorder.Tee(reg)
	}

	promhttp.HandlerFor(
		prometheus.Gatherers{h.self, collectorGatherer},
		// ContinueOnError (not the zero-value HTTPErrorOnError) so a single
		// collector emitting a duplicate label tuple degrades to a logged
		// warning plus a partial scrape, instead of a blanket HTTP 500 that
		// drops every collector's series and the self/process metrics too (#81).
		//
		// MaxRequestsInFlight is deliberately NOT set here: HandlerFor allocates
		// its semaphore at construction time, and this construction is
		// per-request, so the field would hand every request its own empty
		// semaphore and bound nothing. The real bound is h.inFlight, taken at the
		// top of ServeHTTP.
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
	// strconv.ParseFloat parses "NaN"/"±Inf"/"1e300" without error, and every NaN
	// comparison is false (so NaN would slip past a bare `seconds <= 0`). Reject
	// non-finite and absurdly large values explicitly: the header is client-controlled
	// and real Prometheus never sends these (#124).
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds <= 0 || seconds > maxScrapeTimeoutSeconds {
		return 0, false
	}
	timeout := time.Duration(seconds * float64(time.Second))
	if timeout > offset {
		return timeout - offset, true
	}
	return timeout, true
}
