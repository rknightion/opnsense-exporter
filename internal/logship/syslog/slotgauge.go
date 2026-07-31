package syslog

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Connection-slot self-metrics (#592 item 4).
//
// Before these, pressure on the listener's per-transport connection budget was
// observable only through logs_rejected_total{reason="conn_limit"} — a WALL-HIT
// counter. It tells an operator they have already run out of slots, never that they
// are about to, so there is no way to see a budget filling up and raise MaxConns
// before senders start being refused. Headroom needs the occupancy and the ceiling.
//
// The names carry `syslog` because the budget is this receiver's, not a pipeline-wide
// resource: the zenarmor HTTP receiver has its own, differently-shaped limits. A
// `source` label would be a constant here and would invite the two to be summed.
//
// Full names rather than Namespace+Name so there is exactly one spelling of each,
// shared with the tests. scripts/docgen/selfmetrics.go resolves a constant Name and
// errors loudly (never silently skips) on one it cannot, so this stays visible to the
// self-metric inventory and therefore to the Grafana coverage gate.
const (
	connSlotsInUseName = "opnsense_exporter_logs_syslog_conn_slots_in_use"
	connSlotsLimitName = "opnsense_exporter_logs_syslog_conn_slots_limit"
)

// slotGauges reports per-transport connection-slot occupancy against its ceiling.
// A nil *slotGauges is a no-op, so a listener built with no registerer (self-metrics
// off, or any test that does not care) behaves exactly as it did before.
type slotGauges struct {
	inUse *prometheus.GaugeVec
	limit *prometheus.GaugeVec
}

// newSlotGauges registers the pair and seeds one series per transport in transports,
// which must be the transports actually LISTENING — not every transport the listener
// has a semaphore for.
//
// That distinction is the whole reason this takes a list. NewListener allocates both
// tcpSem and tlsSem unconditionally, so seeding off semaphore capacity would publish a
// TLS budget on a listener with no TLS socket: a series pinned at zero for the life of
// the process, claiming we are watching something that cannot happen. Same rule the
// pipeline's sourceNames split exists for (#280) — pre-initialise a zero only where
// the zero is honest and the series can actually move.
//
// reg may be nil, giving a nil *slotGauges.
func newSlotGauges(reg prometheus.Registerer, maxConns int, transports []string) *slotGauges {
	if reg == nil || len(transports) == 0 {
		return nil
	}
	g := &slotGauges{
		inUse: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: connSlotsInUseName,
			Help: "Syslog receiver connection slots currently held, by transport. Each accepted " +
				"connection holds one slot for as long as it is served; a TLS connection holds one " +
				"from accept, BEFORE it has authenticated, which is why the pre-handshake deadline " +
				"exists. Read against logs_syslog_conn_slots_limit for headroom: this reaching the " +
				"limit is the point at which new senders start being refused and " +
				"logs_rejected_total{reason=\"conn_limit\"} begins to climb.",
		}, []string{"transport"}),
		limit: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: connSlotsLimitName,
			Help: "Syslog receiver connection-slot ceiling, by transport (--logs.syslog.max-conns). " +
				"The budget is PER TRANSPORT, not a shared pool: plain TCP and TLS hold separate " +
				"budgets of this size, so an unauthenticated plaintext flood cannot starve the mTLS " +
				"senders an operator trusts.",
		}, []string{"transport"}),
	}
	reg.MustRegister(g.inUse, g.limit)
	for _, transport := range transports {
		g.limit.WithLabelValues(transport).Set(float64(maxConns))
		g.inUse.WithLabelValues(transport).Set(0)
	}
	return g
}

// observe records the transport's current occupancy. Callers pass len(sem), which is a
// SAMPLE of the semaphore's true depth rather than an accumulator this type maintains.
// That is deliberate: an Inc/Dec pair can be unbalanced by any future early return and
// then reads wrong forever, whereas a sample can at worst be momentarily stale — and
// since every acquire and every release samples, it is exact at rest and self-correcting
// under load.
func (g *slotGauges) observe(transport string, inUse int) {
	if g == nil {
		return
	}
	g.inUse.WithLabelValues(transport).Set(float64(inUse))
}
