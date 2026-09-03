package options

import "github.com/alecthomas/kingpin/v2"

// Security-posture snapshots are independently opt-in. They identify pending
// update posture, certificate-expiry roll-ups and API-key owners, so enabling
// generic log shipping must never begin exporting them implicitly.
var logsConfigSnapshotSecurityPostureEnabled = kingpin.Flag(
	"logs.config-snapshot.security-posture.enabled",
	"Ship a compact firmware, certificate-expiry and API-key-owner security-posture snapshot to Loki. Off by default; requires --logs.enabled. Snapshots are deduplicated by content hash and repeat as a 7d heartbeat.",
).Envar("OPN2OTEL_LOGS_CONFIG_SNAPSHOT_SECURITY_POSTURE_ENABLED").Default("false").Bool()

// LogsConfigSnapshotSecurityPostureEnabled reports whether the independent
// security-posture snapshot provider is enabled.
func LogsConfigSnapshotSecurityPostureEnabled() bool {
	return *logsConfigSnapshotSecurityPostureEnabled
}
