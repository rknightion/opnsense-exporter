package options

import "github.com/alecthomas/kingpin/v2"

var logsConfigChangeEnabled = kingpin.Flag(
	"logs.configchange.enabled",
	"Enable config-revision diff events from OPNsense configuration history. Off by default; requires --logs.enabled and works independently of the syslog receiver.",
).Envar("OPN2OTEL_LOGS_CONFIGCHANGE_ENABLED").Default("false").Bool()

// LogsConfigChangeEnabled reports whether the config-revision diff source is enabled.
func LogsConfigChangeEnabled() bool { return *logsConfigChangeEnabled }
