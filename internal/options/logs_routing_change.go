package options

import "github.com/alecthomas/kingpin/v2"

// logsConfigSnapshotRoutingChangesEnabled gates the routing snapshot-diff source.
// It is deliberately separate from --logs.config-snapshot.firewall.enabled: a
// route transition is an event stream, not a full firewall configuration dump,
// and operators may want one without exporting policy rows.
var logsConfigSnapshotRoutingChangesEnabled = kingpin.Flag(
	"logs.config-snapshot.routing-changes.enabled",
	"Enable default-route movement events from routingTable and gatewaysStatus. Off by default; requires --logs.enabled. "+
		"The source emits one before/after event per observed route movement, coalesces flapping transitions, and ignores "+
		"dpinger-only gateway health changes.",
).Envar("OPN2OTEL_LOGS_CONFIG_SNAPSHOT_ROUTING_CHANGES_ENABLED").Default("false").Bool()

// LogsConfigSnapshotRoutingChangesEnabled reports whether the routing snapshot
// diff source is enabled.
func LogsConfigSnapshotRoutingChangesEnabled() bool {
	return *logsConfigSnapshotRoutingChangesEnabled
}
