package syslog

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	udpAcceptedMetricName      = "opnsense_exporter_syslog_udp_accepted_total"
	udpReceiveBufferMetricName = "opnsense_exporter_syslog_udp_receive_buffer_bytes"
)

// udpMetrics contains the listener's UDP ingress observations. The concrete
// wrappers make an AlreadyRegisteredError type-safe: prometheus.Counter and
// prometheus.Gauge are structural interfaces, so accepting an existing
// collector through either interface could turn a same-name, wrong-type
// collision into a metric that silently reports the wrong thing.
type udpMetrics struct {
	accepted      *udpCounter
	receiveBuffer *udpGauge
}

type udpCounter struct{ prometheus.Counter }
type udpGauge struct{ prometheus.Gauge }

// newUDPMetrics registers the UDP counter whenever self-metrics are enabled.
// The counter is intentionally present even when UDP itself is disabled: its
// pre-initialised zero is an honest, stable observation that no UDP datagram
// has been admitted by this listener. The receive-buffer gauge is transport
// specific, so it is only registered for a configured UDP socket and remains
// at its zero value until Start has read the effective kernel value back.
func newUDPMetrics(reg prometheus.Registerer, udpEnabled bool) *udpMetrics {
	if reg == nil {
		return nil
	}
	m := &udpMetrics{
		accepted: &udpCounter{prometheus.NewCounter(prometheus.CounterOpts{
			Name: udpAcceptedMetricName,
			Help: "Total UDP syslog datagrams admitted to the bounded worker queue. This is an ingress " +
				"acceptance counter: disallowed peers, empty datagrams, and queue-full drops are excluded; " +
				"parsing and OTLP delivery happen after admission.",
		})},
	}
	m.accepted = registerUDPCounterOrExisting(reg, m.accepted)
	if udpEnabled {
		m.receiveBuffer = registerUDPGaugeOrExisting(reg, &udpGauge{prometheus.NewGauge(prometheus.GaugeOpts{
			Name: udpReceiveBufferMetricName,
			Help: "Effective UDP syslog socket receive buffer in bytes, read back from SO_RCVBUF after " +
				"the requested buffer is applied. On Linux the kernel commonly reports roughly double the " +
				"requested value; this gauge reports the returned value unchanged.",
		})})
	}
	return m
}

func registerUDPCounterOrExisting(reg prometheus.Registerer, c *udpCounter) *udpCounter {
	if err := reg.Register(c); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(*udpCounter); ok {
				return existing
			}
		}
		panic(err)
	}
	return c
}

func registerUDPGaugeOrExisting(reg prometheus.Registerer, g *udpGauge) *udpGauge {
	if err := reg.Register(g); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(*udpGauge); ok {
				return existing
			}
		}
		panic(err)
	}
	return g
}

func (m *udpMetrics) observeAccepted() {
	if m == nil || m.accepted == nil {
		return
	}
	m.accepted.Inc()
}

func (m *udpMetrics) observeReceiveBuffer(effective int) {
	if m == nil || m.receiveBuffer == nil || effective <= 0 {
		return
	}
	m.receiveBuffer.Set(float64(effective))
}
