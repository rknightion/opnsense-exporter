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

// NewMetrics constructs and registers the enrichment self-metrics on reg.
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
	return m
}
