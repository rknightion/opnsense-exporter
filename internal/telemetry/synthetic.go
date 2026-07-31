package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
)

// syntheticInstanceLabel is the instance label applied to the synthetic `up`
// series. It must stay in lockstep with the collector package's
// instanceLabelName ("opnsense_instance") so the synthetic `up` carries the same
// instance identity as every other exported series. It is duplicated rather than
// imported to keep this package from pulling in the collector package (whose
// init() functions register ~60 sub-collectors as a side effect).
const syntheticInstanceLabel = "opnsense_instance"

// newSyntheticUpGatherer builds a standalone gatherer exposing a single `up`
// gauge fixed at 1, labelled with the exporter instance.
//
// Why this exists: in a Prometheus pull setup the server synthesizes an `up`
// series per target for free (1 when the scrape succeeded, 0 when the exporter
// was unreachable), and users routinely alert on it. In OTLP push mode there is
// no scraper and therefore no synthetic `up`, so those alerts silently stop
// working. This reinstates a push-mode equivalent: while the exporter is running
// it exports `up = 1` on every tick; when it stops the series goes stale/absent,
// which is exactly the signal an `up == 0` / `absent(up)` alert keys off.
//
// The value is a constant 1 (never OPNsense reachability — that is
// opnsense_up's job) to mirror Prometheus target-up semantics: `up` reports
// whether the exporter itself is alive, not whether the firewall behind it is
// healthy.
//
// This gatherer is deliberately wired ONLY into the OTLP export path and is
// never registered with the /metrics handler. A literal `up` exposed at
// /metrics would collide with the `up` Prometheus generates for the scrape
// target, so it must exist in the pushed stream alone.
func newSyntheticUpGatherer(instance string) (prometheus.Gatherer, error) {
	reg := prometheus.NewRegistry()
	up := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "up",
		Help: "Whether the opnsense2otel is alive (always 1 while it is exporting). " +
			"Push-mode equivalent of the target `up` series a Prometheus server synthesizes on scrape; " +
			"exported only over OTLP. Absence/staleness signals the exporter is down. " +
			"Firewall reachability is reported separately by opnsense_up.",
		ConstLabels: prometheus.Labels{syntheticInstanceLabel: instance},
	})
	up.Set(1)
	if err := reg.Register(up); err != nil {
		return nil, err
	}
	return reg, nil
}
