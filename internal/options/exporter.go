package options

import (
	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/exporter-toolkit/web/kingpinflag"
)

var (
	MetricsPath = kingpin.Flag(
		"web.telemetry-path",
		"Path under which to expose metrics.",
	).Default("/metrics").String()
	DisableExporterMetrics = kingpin.Flag(
		"web.disable-exporter-metrics",
		"Exclude metrics about the exporter itself (promhttp_*, process_*, go_*).",
	).Envar("OPNSENSE_EXPORTER_DISABLE_EXPORTER_METRICS").Bool()
	InstanceLabel = kingpin.Flag(
		"exporter.instance-label",
		"Label to use to identify the instance in every metric. "+
			"If you have multiple instances of the exporter, you can differentiate them by using "+
			"different value in this flag, that represents the instance of the target OPNsense. "+
			"If left empty, it defaults to the OPNsense hostname reported by the API "+
			"(falling back to the configured OPNsense address if that lookup fails).",
	).Envar("OPNSENSE_EXPORTER_INSTANCE_LABEL").Default("").String()

	WebConfig = kingpinflag.AddFlags(kingpin.CommandLine, ":8080")
)
