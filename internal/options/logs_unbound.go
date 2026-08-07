package options

import (
	"fmt"
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
).Envar("OPN2OTEL_LOGS_UNBOUND_ENABLED").Default("false").Bool()

// LogsUnboundEnabled reports whether the unbound per-query DNS log source is
// enabled.
func LogsUnboundEnabled() bool {
	return *logsUnboundEnabled
}

// The SECOND per-query DNS route (#659). Unbound's own log-queries/log-replies
// output arrives over syslog, so unlike the poll lane above this exporter does not
// fetch it — the firewall either sends those lines or it does not. This flag gates
// whether we STRUCTURE and SHIP them, which is the part that costs money: measured
// on a live box, the two settings together emit 2.05 log lines per DNS query,
// forever (~1.14M lines/day at 6.5 qps, 41% of all syslog on that box).
//
// It is deliberately a separate opt-in rather than "parse whatever arrives",
// because the firewall-side setting and the exporter-side bill are set by different
// people at different times: an admin flipping log-queries on the firewall to debug
// something should not silently double a Loki bill.
var logsSyslogUnboundPerQuery = kingpin.Flag(
	"logs.syslog.unbound-per-query.enabled",
	"Enable the opt-in second per-query DNS log route: structure Unbound's own "+
		"log-queries/log-replies syslog output (raw client IP, resolve time, cache-hit flag, "+
		"rcode) and ship it to Loki. Off by default; requires --logs.enabled and the syslog "+
		"receiver. FIREWALL PREREQUISITES: Unbound needs log-replies (and optionally "+
		"log-queries) AND log-tag-queryreply enabled - without log-tag-queryreply the lines are "+
		"tagged 'info:' instead of 'query:'/'reply:' and this parser will not match them; "+
		"upstream defaults it OFF. COST: roughly 2 log lines per DNS query, forever - prefer "+
		"log-replies ALONE, which carries every field log-queries does plus four more, halving "+
		"ingest for strictly more data. Upstream warns log-queries 'makes the server "+
		"(significantly) slower'; measured on a homelab resolver up to ~60x its baseline rate "+
		"there was no detectable effect, but that does not clear a busy resolver. MUTUALLY "+
		"EXCLUSIVE with --logs.unbound.enabled: both routes log the same queries, so running "+
		"both ships two Loki records per query.",
).Envar("OPN2OTEL_LOGS_SYSLOG_UNBOUND_PER_QUERY_ENABLED").Default("false").Bool()

// LogsSyslogUnboundPerQueryEnabled reports whether the syslog per-query DNS route
// (#659) is enabled.
func LogsSyslogUnboundPerQueryEnabled() bool {
	return *logsSyslogUnboundPerQuery
}

// ValidateUnboundPerQueryRoutes refuses the both-lanes-enabled configuration (#659).
//
// The two routes carry the SAME queries by different transports, so enabling both
// ships two Loki records per DNS query under different opnsense_source values. Every
// per-query panel would then depend on which lane the operator enabled, and a
// dispositions-per-second panel silently doubles — a wrong number that reads as a
// real one, which is worse than an obviously broken panel.
//
// This REFUSES rather than warns because both inputs are the operator's own flags,
// known before anything is constructed, and the fix is to drop one of them. The case
// this cannot catch is the firewall sending query:/reply: lines while only the POLL
// lane is enabled here: that is invisible until a record parses, so the pipeline
// warns repeatedly at runtime instead (see internal/logship/syslog/unbound.go).
func ValidateUnboundPerQueryRoutes() error {
	if *logsUnboundEnabled && *logsSyslogUnboundPerQuery {
		return fmt.Errorf(
			"--logs.unbound.enabled and --logs.syslog.unbound-per-query.enabled are mutually " +
				"exclusive: both ship one Loki record per DNS query, so running both doubles " +
				"per-query volume and every per-query panel. Pick one - the poll lane for DNSBL " +
				"action/blocklist attribution, the syslog lane for the raw client IP, complete " +
				"coverage and resolve latency")
	}
	return nil
}

// LogsUnboundMinInterval is the hard poll floor for the unbound log source,
// used by its IntervalSource.MinInterval().
func LogsUnboundMinInterval() time.Duration {
	return unboundLogsMinInterval
}
