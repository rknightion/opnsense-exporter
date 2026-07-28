package options

import "github.com/alecthomas/kingpin/v2"

// DefaultSeriesBudget is the --exporter.series-budget flag default (#494): the
// soft total-series budget the exporter design targets, with today's real usage
// sitting at roughly 7.5% of it (~7,530 of 100,000 on a fully-enabled instance).
const DefaultSeriesBudget = 100000

// SeriesBudget is the soft total-series budget flag (#494). It is reporting and
// logging only: exceeding it never drops, caps or refuses a series. 0 disables
// the check entirely (no log, ever, regardless of series count).
var SeriesBudget = kingpin.Flag(
	"exporter.series-budget",
	"Soft budget for the total number of Prometheus series produced by the COLLECTOR "+
		"registry (the same set /metrics and the OTLP bridge serve, and what metricsnap "+
		"replays to the web UI's /cardinality report) — this is NOT the exporter "+
		"process's full series count: process_*/go_* self-metrics and the "+
		"opnsense_exporter_otlp_* delivery-health family live on a separate self "+
		"registry and are never counted here, so this number will read lower than what "+
		"your Prometheus tenant ultimately stores for this job. Nothing is ever dropped, "+
		"capped or refused when it is exceeded (#494) — exceeding it only logs a "+
		"rate-limited warning (once on the transition into the over-budget state, then "+
		"at most hourly while it persists, and once more on the transition back under "+
		"budget) and is reported on /cardinality alongside the existing per-metric "+
		"warn/crit thresholds, which are a different, unrelated dimension. Set to 0 to "+
		"disable the check entirely.",
).Envar("OPNSENSE_EXPORTER_SERIES_BUDGET").Default("100000").Int()
