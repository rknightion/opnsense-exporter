package zenarmor

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/internal/logship"
)

// metrics are the receiver's self-metrics. recv carries the two shared,
// source-labelled counters every push receiver reports; the bulk pair is specific
// to this receiver's transport.
//
// A nil *metrics is a no-op throughout, so tests can construct a server without a
// registry.
type metrics struct {
	recv      *logship.ReceiverMetrics
	bulkReqs  prometheus.Counter
	bulkBytes prometheus.Counter
}

func newMetrics(reg prometheus.Registerer) *metrics {
	const ns = "opnsense_exporter"
	m := &metrics{
		recv: logship.NewReceiverMetrics(reg, sourceName),
		bulkReqs: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_zenarmor_bulk_requests_total",
			Help: "Total Elasticsearch _bulk requests accepted from Zenarmor.",
		}),
		bulkBytes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_zenarmor_bulk_bytes_total",
			Help: "Total _bulk request body bytes accepted from Zenarmor, measured after " +
				"decompression so the figure reflects parsed volume rather than what the " +
				"socket carried.",
		}),
	}
	if reg != nil {
		// MustRegister, not the get-or-register dance ReceiverMetrics needs: these two
		// names are private to this receiver and only its single factory ever registers
		// them, so a duplicate here is a programming error and should be loud.
		reg.MustRegister(m.bulkReqs, m.bulkBytes)
	}
	return m
}

// reject counts one unit of input dropped before parsing.
func (m *metrics) reject(reason string) {
	if m == nil {
		return
	}
	m.recv.Reject(reason)
}

// parseError counts one record that failed to parse. The record still ships.
func (m *metrics) parseError(stage string) {
	if m == nil {
		return
	}
	m.recv.ParseError(stage)
}

// observeBulk counts one accepted _bulk request of n decompressed body bytes.
func (m *metrics) observeBulk(n int) {
	if m == nil {
		return
	}
	m.bulkReqs.Inc()
	m.bulkBytes.Add(float64(n))
}
