package options

import "github.com/alecthomas/kingpin/v2"

// logsIDSEnabled gates the IDS (Suricata EVE alert) log-shipping source. Off
// by default like every log source (see logs.go): --logs.enabled only starts
// the pipeline, a source must also opt in before anything ships.
var logsIDSEnabled = kingpin.Flag(
	"logs.ids.enabled",
	"Enable the IDS (Suricata EVE alert) log source: ships full Suricata alert records "+
		"polled via ids/service/query_alerts. Off by default. Requires --logs.enabled. "+
		"If the box already forwards EVE JSON via syslog (ids.general.syslog_eve), prefer "+
		"that native path instead of also enabling this source - do not ship the same alerts twice.",
).Envar("OPN2OTEL_LOGS_IDS_ENABLED").Default("false").Bool()

// LogsIDSEnabled reports whether the IDS log source is enabled.
func LogsIDSEnabled() bool {
	return *logsIDSEnabled
}
