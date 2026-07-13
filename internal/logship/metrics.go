package logship

import "github.com/prometheus/client_golang/prometheus"

// Drop reasons for logs_dropped_total.
const (
	dropReasonOverflow = "overflow" // queue full, oldest evicted
)

// metrics holds the pipeline self-metrics. They register into the exporter's
// self-metrics registry (so they appear at /metrics and via the OTLP metrics
// bridge). Every metric here is mirrored by a panel on the Logs dashboard tab —
// the grafana coverage gate enforces that.
type metrics struct {
	shipped       *prometheus.CounterVec // logs_shipped_total{source}
	dropped       *prometheus.CounterVec // logs_dropped_total{source,reason}
	shipErrors    prometheus.Counter     // logs_ship_errors_total
	pollErrors    *prometheus.CounterVec // logs_poll_errors_total{source}
	lastEventTime *prometheus.GaugeVec   // logs_last_event_timestamp_seconds{source}
	queueLength   prometheus.GaugeFunc   // logs_queue_length
	queueCapacity prometheus.Gauge       // logs_queue_capacity
}

// newMetrics constructs and registers the pipeline self-metrics on reg. queueLen
// is sampled lazily by the queue_length GaugeFunc.
func newMetrics(reg prometheus.Registerer, capacity int, queueLen func() float64) *metrics {
	const ns = "opnsense_exporter"
	m := &metrics{
		shipped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_shipped_total",
			Help: "Total log records successfully handed to the sink, by source.",
		}, []string{"source"}),
		dropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_dropped_total",
			Help: "Total log records dropped before delivery, by source and reason.",
		}, []string{"source", "reason"}),
		shipErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_ship_errors_total",
			Help: "Total sink Emit errors (a failed batch is dropped and counted).",
		}),
		pollErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_poll_errors_total",
			Help: "Total source Poll errors, by source.",
		}, []string{"source"}),
		lastEventTime: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns, Name: "logs_last_event_timestamp_seconds",
			Help: "Unix timestamp of the most recent event shipped, by source (cursor lag).",
		}, []string{"source"}),
		queueCapacity: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: ns, Name: "logs_queue_capacity",
			Help: "Configured capacity of the log-shipping backpressure queue.",
		}),
	}
	m.queueLength = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: ns, Name: "logs_queue_length",
		Help: "Current depth of the log-shipping backpressure queue.",
	}, queueLen)

	m.queueCapacity.Set(float64(capacity))
	reg.MustRegister(
		m.shipped, m.dropped, m.shipErrors, m.pollErrors,
		m.lastEventTime, m.queueLength, m.queueCapacity,
	)
	return m
}
