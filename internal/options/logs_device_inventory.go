package options

import "github.com/alecthomas/kingpin/v2"

// Device inventory is a separate configstate family because it contains
// potentially identifying network data (MAC addresses, IP addresses and host
// names). It is opt-in even when the log pipeline itself is enabled.
var logsConfigSnapshotDevicesEnabled = kingpin.Flag(
	"logs.config-snapshot.devices.enabled",
	"Ship one deduplicated device-inventory record per observed network device to Loki. "+
		"Records fuse ARP, NDP, DHCP, host-discovery and LLDP observations and carry MAC, IPs, "+
		"hostname, interface, first/last-seen and OUI-vendor fields. Off by default; requires "+
		"--logs.enabled. The family ships on content change and repeats on the configstate "+
		"heartbeat.",
).Envar("OPN2OTEL_LOGS_CONFIG_SNAPSHOT_DEVICES_ENABLED").Default("false").Bool()

// LogsConfigSnapshotDeviceInventoryEnabled reports whether the device-inventory
// configstate family is enabled. It does not imply --logs.enabled or any other
// snapshot family.
func LogsConfigSnapshotDevicesEnabled() bool {
	return *logsConfigSnapshotDevicesEnabled
}

// LogsConfigSnapshotDeviceInventoryEnabled is retained as a descriptive alias
// for callers that name the family rather than the frozen flag segment. The
// public CLI/env contract is LogsConfigSnapshotDevicesEnabled above.
func LogsConfigSnapshotDeviceInventoryEnabled() bool {
	return LogsConfigSnapshotDevicesEnabled()
}
