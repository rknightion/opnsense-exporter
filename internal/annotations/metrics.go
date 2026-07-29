package annotations

import "github.com/prometheus/client_golang/prometheus"

// selfMetrics are the only local evidence that pushing actually works. A
// successful start proves nothing — nothing is written until an event occurs — so
// without these an operator cannot distinguish "correctly quiet" from "the token
// expired three weeks ago".
type selfMetrics struct {
	posted prometheus.Counter
	failed prometheus.Counter
	// rateLimited and undeliverable are BREAKDOWNS of failed, not additions to it:
	// both also increment failed, so failed stays the single "writes that did not
	// land" series and the two below say which of the three fates a failure met.
	// Without them a rate-limit storm and an expired token are the same climbing
	// line, which is exactly how #519 read on the dashboard.
	rateLimited   prometheus.Counter
	undeliverable prometheus.Counter
	skipped       prometheus.Counter
	lastSuccess   prometheus.Gauge
}

func newSelfMetrics(registerer prometheus.Registerer) *selfMetrics {
	m := &selfMetrics{
		posted: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "opnsense_exporter_annotations_written_total",
			Help: "Total annotations successfully written to Grafana.",
		}),
		failed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "opnsense_exporter_annotations_failed_total",
			Help: "Total annotation writes that failed. A failed write is retried on the " +
				"next detection pass — the event is not marked as seen.",
		}),
		rateLimited: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "opnsense_exporter_annotations_rate_limited_total",
			Help: "Total annotation writes Grafana rejected with HTTP 429. Also counted in " +
				"opnsense_exporter_annotations_failed_total. The writer then backs off and " +
				"posts nothing until the wait expires, honouring Retry-After when the server " +
				"sends one. A whole Grafana org shares one annotation rate limit, so this can " +
				"be caused by another writer entirely.",
		}),
		undeliverable: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "opnsense_exporter_annotations_undeliverable_total",
			Help: "Total annotations abandoned because Grafana rejected them with a client " +
				"error that can never succeed (a 4xx other than 429 and 408 — a malformed " +
				"body, or a token without the annotation write permission). Also counted in " +
				"opnsense_exporter_annotations_failed_total. Unlike a failed write these are " +
				"NOT retried; a sustained rate means annotations are being lost and the " +
				"exporter log names the status.",
		}),
		skipped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "opnsense_exporter_annotations_skipped_total",
			Help: "Total annotations dropped because a detection pass hit its per-cycle cap.",
		}),
		lastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "opnsense_exporter_annotations_last_success_timestamp_seconds",
			Help: "Unix timestamp of the last successful annotation write. Stays absent " +
				"until the first write, which on a quiet firewall may be days.",
		}),
	}
	if registerer != nil {
		registerer.MustRegister(m.posted, m.failed, m.rateLimited, m.undeliverable,
			m.skipped, m.lastSuccess)
	}
	return m
}
