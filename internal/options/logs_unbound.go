package options

import (
	"time"

	"github.com/alecthomas/kingpin/v2"
)

// unboundLogsMinInterval is the poll floor for the unbound query-log source
// (#233). Each call to api/unbound/overview/search_queries spawns
// python+pandas+DuckDB on the box (~1s CPU), so polling faster than this wastes
// resolver CPU for no benefit — mirroring the (higher) floor other heavy
// sources reserve via IntervalSource.
const unboundLogsMinInterval = 15 * time.Second

var logsUnboundEnabled = kingpin.Flag(
	"logs.unbound.enabled",
	"Enable the opt-in Unbound per-query DNS log source (pi-hole-style query log to Loki: "+
		"domain, client, action, resolution source, blocklist and dnssec_status per query). "+
		"Off by default; requires --logs.enabled. CAVEAT: without a per-client filter, "+
		"Unbound's query-log backend (DuckDB) only ever exposes the newest 1000 rows across "+
		"the WHOLE resolver - on a firewall sustaining more than roughly 1000 queries between "+
		"polls, older rows silently fall out of that window before this exporter ever sees "+
		"them. This is accepted, honestly-counted sampling loss, not a bug: it is tracked via "+
		"opnsense_exporter_logs_possible_gap_total{source=\"unbound\"}, never silently dropped. "+
		"Homelab/SMB query volumes are fine; a busy enterprise resolver should not enable this. "+
		"Also requires Unbound reporting/statistics enabled on the firewall. Poll floor 15s "+
		"regardless of --logs.poll-interval.",
).Envar("OPNSENSE_EXPORTER_LOGS_UNBOUND_ENABLED").Default("false").Bool()

// LogsUnboundEnabled reports whether the unbound per-query DNS log source is
// enabled.
func LogsUnboundEnabled() bool {
	return *logsUnboundEnabled
}

// LogsUnboundMinInterval is the hard poll floor for the unbound log source,
// used by its IntervalSource.MinInterval().
func LogsUnboundMinInterval() time.Duration {
	return unboundLogsMinInterval
}
