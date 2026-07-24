package options

import "github.com/alecthomas/kingpin/v2"

// logsCrowdSecEnabled gates the crowdsec log source. It is meaningless unless
// --logs.enabled is also set (see logs.go) — buildSources skips a disabled
// source's factory regardless, and Start logs a warning if no source ends up
// enabled at all.
var logsCrowdSecEnabled = kingpin.Flag(
	"logs.crowdsec.enabled",
	"Enable the crowdsec log source: ships CrowdSec alert and decision records to Loki "+
		"(there is no native syslog path for these - the plugin registers no syslog scope; "+
		"alerts live only in the LAPI). Requires --logs.enabled. Polls at a 60s floor "+
		"regardless of --logs.poll-interval. Silent when the os-crowdsec plugin is absent. "+
		"Off by default.",
).Envar("OPNSENSE_EXPORTER_LOGS_CROWDSEC_ENABLED").Default("false").Bool()

// LogsCrowdSecEnabled reports whether the crowdsec log source is enabled.
func LogsCrowdSecEnabled() bool {
	return *logsCrowdSecEnabled
}
