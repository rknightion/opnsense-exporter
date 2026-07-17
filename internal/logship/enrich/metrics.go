package enrich

import "github.com/prometheus/client_golang/prometheus"

// Metrics are the enrichment self-metrics. They are constructed in main.go
// against the exporter's self-metrics registry and INJECTED (this package cannot
// reach logship's unexported metrics struct).
type Metrics struct {
	// Misses counts enrichment lookups that found nothing, by table. A rising
	// Misses with a flat LastRefresh means the refresher is wedged.
	Misses *prometheus.CounterVec
	// RefreshErrors counts failed table rebuilds, by table. A failed rebuild
	// keeps the previous snapshot — enrichment degrades, it never drops a record.
	RefreshErrors *prometheus.CounterVec
	// LastRefresh is the unix timestamp of the last SUCCESSFUL rebuild, by table.
	// It is deliberately a timestamp, not a self-reported "age": an age gauge set
	// to 0 at refresh and never touched again reports 0 forever and could never
	// reveal a stale cache. time() - LastRefresh gives the real age at query time.
	LastRefresh *prometheus.GaugeVec
}

// Tables is the closed set of enrichment tables the Refresher owns — every value
// the table label can take on logs_enrich_refresh_errors_total and
// logs_enrich_last_refresh_timestamp_seconds. Enforced against Run's tick() call
// sites by TestTablesMatchTickCallSites.
var Tables = []string{"rules", "interfaces", "leases", "tunnels"}

// MissTables is the subset of Tables that can report a LOOKUP miss, and it is
// deliberately much smaller than Tables (#280).
//
// Only filterlog's rule-description lookup signals a miss, because only there does
// a miss mean the snapshot is stale. Every other lookup — hostname, MAC, scope,
// interface name — misses routinely and legitimately (an address we have never
// seen is the normal case for internet traffic), so those never call Miss at all.
// Pre-initialising the other tables here would publish zeroes that nothing can ever
// increment.
var MissTables = []string{"rules"}

// NewMetrics constructs and registers the enrichment self-metrics on reg, then
// pre-initialises the counters' known label values to zero (#280) so a healthy
// exporter reports a flat 0 rather than an absent series.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	const ns = "opnsense_exporter"
	m := &Metrics{
		Misses: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_enrich_misses_total",
			Help: "Total enrichment lookups that missed the cached snapshot, by table.",
		}, []string{"table"}),
		RefreshErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_enrich_refresh_errors_total",
			Help: "Total failed enrichment table refreshes, by table. The previous snapshot is retained.",
		}, []string{"table"}),
		LastRefresh: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns, Name: "logs_enrich_last_refresh_timestamp_seconds",
			Help: "Unix timestamp of the last successful enrichment table refresh, by table.",
		}, []string{"table"}),
	}
	if reg != nil {
		reg.MustRegister(m.Misses, m.RefreshErrors, m.LastRefresh)
	}
	for _, t := range MissTables {
		m.Misses.WithLabelValues(t)
	}
	for _, t := range Tables {
		m.RefreshErrors.WithLabelValues(t)
	}
	// LastRefresh is deliberately NOT pre-initialised: it is a unix timestamp, and a
	// zero would read as 1970 — a query computing time() - LastRefresh would report a
	// 56-year-old cache rather than "not refreshed yet". Run stamps every table on its
	// first tick anyway, so the gap is one startup, not indefinite.
	return m
}
