package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rknightion/opnsense2otel/v4/internal/metricsnap"
)

// Self-observability for the /metrics handler itself (#426). Before this, a
// stuck admission cap or a persistently duplicate-labelled collector was
// visible only in logs — an operator scraping the exporter had no queryable
// signal that scrapes were being rejected or served partial. Every name below
// is a literal constant so the self-metric inventory's source scan
// (scripts/docgen/selfmetrics.go) can see it; see that file's header for why an
// unresolvable name is a hard build failure rather than a skip.
//
// Label vocabularies are closed by construction, never derived from a request:
// requestStatus* and the reject/gather-error reasons are the only values these
// metrics can ever carry, so cardinality is bounded regardless of client
// behaviour (no path, no client IP, no header value ever becomes a label).
const (
	metricNameRequestsInFlight      = "opnsense_exporter_server_metrics_requests_in_flight"
	metricNameRequestsTotal         = "opnsense_exporter_server_metrics_requests_total"
	metricNameRequestDuration       = "opnsense_exporter_server_metrics_request_duration_seconds"
	metricNameRequestsRejectedTotal = "opnsense_exporter_server_metrics_requests_rejected_total"
	metricNameGatherErrorsTotal     = "opnsense_exporter_server_metrics_gather_errors_total"
)

// requestStatus* is the closed vocabulary for metricNameRequestsTotal and
// metricNameRequestDuration. Only a request the admission cap actually let
// through gets a status: a rejected request never reaches this label set (see
// rejectReasonInFlightLimit below), so the two counters are never
// double-counting the same event.
const (
	requestStatusOK         = "ok"          // served, however the gather itself went (see gather-error counter)
	requestStatusBadRequest = "bad_request" // rejected by parseCollectorFilters (unknown/conflicting collect[]/exclude[])
)

// requestStatusInternalError is the third and last requestStatus* value: the
// scrape view itself failed to register into the fresh per-request registry
// (distinct from a downstream Gather() error, which is a partial 200 tracked
// by metricNameGatherErrorsTotal instead — this is the request that never got
// as far as gathering anything at all).
const requestStatusInternalError = "internal_error"

// rejectReasonInFlightLimit is the sole admission-rejection reason today. It is
// still a label (not a bare Counter) because the admission path is the one
// place a second reason could plausibly join it later (e.g. a future
// per-client throttle); a bare Counter would have to become a CounterVec at
// that point and break every existing query.
const rejectReasonInFlightLimit = "in_flight_limit"

// gatherErrorReasonCollectorError is the sole reason value for
// metricNameGatherErrorsTotal. promhttp's ContinueOnError reports Gather()
// failures (duplicate label tuples, inconsistent HELP/TYPE, and similar
// collector-programming errors) as a single opaque error value with no
// stable, closed sub-classification available to this handler — see
// promErrorLogger.Println below. A label is kept anyway, for the same
// forward-compatibility reason as rejectReasonInFlightLimit.
const gatherErrorReasonCollectorError = "collector_error"

// handlerMetrics is the /metrics handler's OWN self-observability, as distinct
// from h.self (process_*/go_*, forwarded not owned) and the per-request scrape
// view (firewall data). Constructed once per handler and always non-nil so
// every code path can record unconditionally; registration onto a real
// registerer is what actually makes the series visible; a nil registerer (as
// in most unit tests) leaves the same Inc()/Observe() calls as harmless no-ops
// on unregistered collectors.
//
// SELF-REFERENTIAL BY CONSTRUCTION, DOCUMENTED RATHER THAN FOUGHT (#426): these
// metrics are gathered from the SAME registry the /metrics handler serves, so
// requestsInFlight is incremented before promhttp.HandlerFor runs and is
// therefore always >= 1 (never 0) in the very response that reports it — the
// scrape collecting the gauge is itself one of the in-flight requests it
// counts. Do not "fix" this with a snapshot-before-increment trick: it would
// only relocate the same fencepost by one request, and the collection path
// must never itself register a new label combination (a metric whose own
// Collect() mutates cardinality is worse than an off-by-one gauge).
type handlerMetrics struct {
	requestsInFlight prometheus.Gauge
	requestsTotal    *prometheus.CounterVec
	requestDuration  *prometheus.HistogramVec
	requestsRejected *prometheus.CounterVec
	gatherErrors     *prometheus.CounterVec
}

func newHandlerMetrics(reg prometheus.Registerer) *handlerMetrics {
	m := &handlerMetrics{
		requestsInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: metricNameRequestsInFlight,
			Help: "Current number of /metrics requests admitted and being served, bounded by " +
				"maxMetricsInFlight. Self-referential by construction: the request that gathers this " +
				"series is itself one of the requests it counts, so it never reads 0 in its own " +
				"response.",
		}),
		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricNameRequestsTotal,
			Help: "Total /metrics requests admitted and completed, by outcome status " +
				"(ok = served, however the underlying gather went; bad_request = rejected " +
				"collect[]/exclude[] parameters; internal_error = the scrape view itself failed to " +
				"register). A request the admission cap rejected is never counted here; see " +
				metricNameRequestsRejectedTotal + ".",
		}, []string{"status"}),
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: metricNameRequestDuration,
			Help: "Duration in seconds of an admitted /metrics request, from the point it passed " +
				"the in-flight admission check to the point its response finished writing, by " +
				"outcome status. Excludes requests the admission cap rejected outright — those never " +
				"do enough work to be worth timing and would otherwise dilute the distribution with " +
				"near-zero samples.",
			Buckets: prometheus.DefBuckets,
		}, []string{"status"}),
		requestsRejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricNameRequestsRejectedTotal,
			Help: "Total /metrics requests rejected before admission, by reason " +
				"(in_flight_limit = maxMetricsInFlight concurrent requests were already being served).",
		}, []string{"reason"}),
		gatherErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricNameGatherErrorsTotal,
			Help: "Total Gather() errors promhttp's ContinueOnError handling caught and logged " +
				"rather than turning into a 500 (#81) — most commonly a collector emitting a " +
				"duplicate label tuple. The response for that request still returns 200 with " +
				"whatever the gather DID collect; this counter is the only queryable evidence that " +
				"the response was partial. By reason (collector_error is the only value today: " +
				"ContinueOnError does not expose a stable finer-grained cause).",
		}, []string{"reason"}),
	}
	// Pre-initialise the closed vocabularies to zero (rather than leaving them
	// absent until first occurrence) so a dashboard/alert querying a specific
	// reason/status never has to distinguish "never happened" from "this
	// exporter build predates the label" via NO DATA.
	m.requestsTotal.WithLabelValues(requestStatusOK)
	m.requestsTotal.WithLabelValues(requestStatusBadRequest)
	m.requestsTotal.WithLabelValues(requestStatusInternalError)
	m.requestDuration.WithLabelValues(requestStatusOK)
	m.requestDuration.WithLabelValues(requestStatusBadRequest)
	m.requestDuration.WithLabelValues(requestStatusInternalError)
	m.requestsRejected.WithLabelValues(rejectReasonInFlightLimit)
	m.gatherErrors.WithLabelValues(gatherErrorReasonCollectorError)

	if reg != nil {
		reg.MustRegister(m.requestsInFlight, m.requestsTotal, m.requestDuration, m.requestsRejected, m.gatherErrors)
	}
	return m
}

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
// per-request filtered views plus the valid collector names. The context is the
// request's own — it carries no exporter-derived deadline (#439) and the replay
// ignores it, but it keeps the standard cancellation seam at the boundary.
type ScrapeViews interface {
	ScrapeView(ctx context.Context, include map[string]bool) prometheus.Collector
	EnabledCollectorNames() []string
}

type metricsHandler struct {
	views ScrapeViews
	self  prometheus.Gatherer
	log   *slog.Logger
	// recorder, when non-nil, passively captures the collector family set of each
	// UNFILTERED scrape so the web UI can read a last-scrape snapshot without ever
	// gathering (and thus re-scraping the firewall) itself. Filtered scrapes
	// (collect[]/exclude[]) are not recorded, so a partial view can't clobber it.
	recorder *metricsnap.Recorder
	// inFlight is the concurrency semaphore for this handler, capacity
	// maxMetricsInFlight. It lives on the handler rather than in the
	// promhttp.HandlerOpts below because promhttp builds its semaphore inside
	// HandlerFor, and HandlerFor is called once PER REQUEST here (each scrape
	// needs its own filtered registry). Setting
	// HandlerOpts.MaxRequestsInFlight would therefore hand every request a
	// private semaphore that can never fill — a silent no-op. This one is
	// created once in NewMetricsHandler and shared, so it actually bounds.
	inFlight chan struct{}
	// metrics is this handler's own self-observability (#426), always non-nil
	// regardless of whether selfObs was nil — see newHandlerMetrics.
	metrics *handlerMetrics
}

// NewMetricsHandler returns the /metrics handler. Per request it parses
// node_exporter-style collect[]/exclude[] filters, registers a single-request
// ScrapeView into a fresh registry (descriptors are never re-registered globally —
// the view subsets the shared collector's fan-out), and serves it merged with the
// static self gatherer (process_*/go_* metrics).
//
// #439: it deliberately does NOT read Prometheus' X-Prometheus-Scrape-Timeout-Seconds
// header. That header used to derive a collection deadline, minus a configurable
// offset. Since #336 a scrape replays the in-memory poll snapshot and makes no
// OPNsense API call, so the derived deadline bounded no work and the collector
// discarded it. Nothing a scraping client sends can reach or curtail OPNsense
// polling; poll deadlines come from --exporter.max-scrape-duration and the poll
// intervals. Response-side bounds that DO apply live here: maxMetricsInFlight and
// metricsWriteDeadline.
//
// selfObs is where this handler's OWN request/duration/rejection/gather-error
// metrics (#426) register — deliberately a caller-supplied registerer rather
// than the bare self gatherer above, so the caller can stamp instance identity
// onto it the same way logship and the annotation writer do (via
// logship.SelfMetricsRegisterer), instead of these series repeating the
// opnsense_exporter_otlp_* mistake (#466) of carrying no opnsense_instance
// label at all. nil is accepted (most unit tests pass it) and simply leaves
// these metrics unregistered — Inc()/Observe() calls still happen but produce
// no visible series.
func NewMetricsHandler(views ScrapeViews, self prometheus.Gatherer, log *slog.Logger, recorder *metricsnap.Recorder, selfObs prometheus.Registerer) http.Handler {
	return &metricsHandler{
		views:    views,
		self:     self,
		log:      log,
		recorder: recorder,
		inFlight: make(chan struct{}, maxMetricsInFlight),
		metrics:  newHandlerMetrics(selfObs),
	}
}

func (h *metricsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Bound concurrent scrapes before doing any work. Overflow gets 503 with the
	// same wording promhttp uses, so operators reading exporter docs recognise it.
	select {
	case h.inFlight <- struct{}{}:
		defer func() { <-h.inFlight }()
	default:
		h.metrics.requestsRejected.WithLabelValues(rejectReasonInFlightLimit).Inc()
		http.Error(w, fmt.Sprintf(
			"Limit of concurrent requests reached (%d), try again later.", maxMetricsInFlight,
		), http.StatusServiceUnavailable)
		return
	}

	// Admission succeeded: this request now counts toward requestsInFlight and
	// will be tallied exactly once, under whichever requestStatus* it finally
	// resolves to, by the deferred recorder below. status is mutated by every
	// return path between here and the end of the function; the zero value is
	// never observed because every path sets it before returning.
	h.metrics.requestsInFlight.Inc()
	defer h.metrics.requestsInFlight.Dec()
	start := time.Now()
	var status string
	defer func() {
		h.metrics.requestsTotal.WithLabelValues(status).Inc()
		h.metrics.requestDuration.WithLabelValues(status).Observe(time.Since(start).Seconds())
	}()

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
		status = requestStatusBadRequest
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// The request context is the whole story: an aborted scrape cancels the request,
	// and nothing else bounds the replay. No client-supplied budget is layered on top
	// (#439) — see NewMetricsHandler.
	ctx := r.Context()

	reg := prometheus.NewRegistry()
	if err := reg.Register(h.views.ScrapeView(ctx, include)); err != nil {
		status = requestStatusInternalError
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

	status = requestStatusOK
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
			ErrorLog:      promErrorLogger{log: h.log, metrics: h.metrics},
		},
	).ServeHTTP(w, r)
	// status is "ok" even when ErrorLog above fired: ContinueOnError means this
	// response still carries a genuine (if partial) body, which is a completed
	// request from the admission cap's point of view. The partial-gather
	// condition itself is metricNameGatherErrorsTotal's job, not this counter's.
}

// promErrorLogger adapts a *slog.Logger to promhttp.Logger so Gather errors
// (e.g. duplicate label tuples) are surfaced in structured logs rather than
// silently swallowed by the default nil ErrorLog, and counted (#426) so a
// sustained partial-gather condition is queryable rather than only
// discoverable by grepping logs.
type promErrorLogger struct {
	log     *slog.Logger
	metrics *handlerMetrics
}

func (l promErrorLogger) Println(v ...any) {
	l.log.Warn("error gathering metrics for scrape", "err", strings.TrimSuffix(fmt.Sprintln(v...), "\n"))
	l.metrics.gatherErrors.WithLabelValues(gatherErrorReasonCollectorError).Inc()
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
