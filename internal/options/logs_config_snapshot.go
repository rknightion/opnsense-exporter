package options

import "github.com/alecthomas/kingpin/v2"

// Config snapshots are deliberately enabled family-by-family. These records can
// contain topology and policy detail, so --logs.enabled alone must never start
// exporting them.
var logsConfigSnapshotFirewallEnabled = kingpin.Flag(
	"logs.config-snapshot.firewall.enabled",
	"Ship compact per-rule firewall and NAT configuration snapshots to Loki. Off by default; requires --logs.enabled. "+
		"Snapshots contain firewall policy and network-topology detail, are deduplicated by content hash, and repeat as a 6h heartbeat.",
).Envar("OPN2OTEL_LOGS_CONFIG_SNAPSHOT_FIREWALL_ENABLED").Default("false").Bool()

// LogsConfigSnapshotFirewallEnabled reports whether the firewall/NAT config
// snapshot provider is enabled. It intentionally does not imply any other
// configuration family.
func LogsConfigSnapshotFirewallEnabled() bool { return *logsConfigSnapshotFirewallEnabled }
