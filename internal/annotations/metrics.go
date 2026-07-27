package annotations

import "github.com/prometheus/client_golang/prometheus"

// selfMetrics are the only local evidence that pushing actually works. A
// successful start proves nothing — nothing is written until an event occurs — so
// without these an operator cannot distinguish "correctly quiet" from "the token
// expired three weeks ago".
type selfMetrics struct {
	posted      prometheus.Counter
	failed      prometheus.Counter
	skipped     prometheus.Counter
	lastSuccess prometheus.Gauge
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
		registerer.MustRegister(m.posted, m.failed, m.skipped, m.lastSuccess)
	}
	return m
}
