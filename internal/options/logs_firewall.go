package options

import "github.com/alecthomas/kingpin/v2"

// LogsFirewallEnabled gates the firewall log source of the log-shipping pipeline
// (--logs.enabled). It is a package-level kingpin flag so it self-registers at
// init and is picked up by docgen and by the source's RegisterSource factory in
// internal/logship/firewall.go, which reads it to report itself enabled/disabled
// without main.go having to wire the source explicitly.
//
// Off by default: enabling --logs.enabled starts the pipeline but ships nothing
// until at least one source flag like this is also set.
var LogsFirewallEnabled = kingpin.Flag(
	"logs.firewall.enabled",
	"Ship OPNsense firewall filter-log events (rule-label-enriched, digest-cursor tailed) through the "+
		"log pipeline. Requires --logs.enabled. Off by default. Targets homelab/SMB event volumes — a box "+
		"logging pass rules at hundreds of events/s should use native syslog + Alloy instead.",
).Envar("OPNSENSE_EXPORTER_LOGS_FIREWALL_ENABLED").Default("false").Bool()
