package options

import (
	"fmt"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/exporter-toolkit/web/kingpinflag"
)

var (
	MetricsPath = kingpin.Flag(
		"web.telemetry-path",
		"Path under which to expose metrics.",
	).Envar("OPNSENSE_EXPORTER_WEB_TELEMETRY_PATH").Default("/metrics").String()
	DisableExporterMetrics = kingpin.Flag(
		"web.disable-exporter-metrics",
		"Exclude metrics about the exporter itself (promhttp_*, process_*, go_*).",
	).Envar("OPNSENSE_EXPORTER_DISABLE_EXPORTER_METRICS").Bool()
	InstanceLabel = kingpin.Flag(
		"exporter.instance-label",
		"Label to use to identify the instance in every metric. "+
			"If you have multiple instances of the exporter, you can differentiate them by using "+
			"different value in this flag, that represents the instance of the target OPNsense. "+
			"If left empty, it defaults to the configured OPNsense address (deterministic). "+
			"Set --exporter.instance-use-hostname to derive it from the OPNsense hostname instead.",
	).Envar("OPNSENSE_EXPORTER_INSTANCE_LABEL").Default("").String()
	InstanceUseHostname = kingpin.Flag(
		"exporter.instance-use-hostname",
		"When --exporter.instance-label is empty, derive the instance label from the OPNsense "+
			"hostname reported by the API instead of the configured address. This lookup is "+
			"deterministic: it blocks at startup and, if the hostname cannot be obtained, the "+
			"exporter refuses to start (rather than silently falling back to the address, which "+
			"would make the label depend on startup timing and flip between restarts).",
	).Envar("OPNSENSE_EXPORTER_INSTANCE_USE_HOSTNAME").Default("false").Bool()

	ScrapeTimeoutOffset = kingpin.Flag(
		"exporter.scrape-timeout-offset",
		"Duration subtracted from Prometheus' X-Prometheus-Scrape-Timeout-Seconds header when deriving the scrape deadline, so the exporter finishes and responds before Prometheus gives up. If the offset would consume the whole budget, the raw header timeout is used.",
	).Envar("OPNSENSE_EXPORTER_SCRAPE_TIMEOUT_OFFSET").Default("500ms").Duration()

	MaxScrapeDuration = kingpin.Flag(
		"exporter.max-scrape-duration",
		"Upper bound on a single collection when the caller supplies no deadline of its own (a header-less /metrics scrape or the OTLP-bridge periodic gather). Prevents a stalled/blackholed firewall from holding the shared collector lock unbounded and blacking out every concurrent deadline-bound scrape.",
	).Envar("OPNSENSE_EXPORTER_MAX_SCRAPE_DURATION").Default("50s").Duration()

	WebConfig = kingpinflag.AddFlags(kingpin.CommandLine, ":8080")
)

// ValidateMetricsPath checks the resolved --web.telemetry-path value. An empty or
// non-"/"-prefixed value would make net/http.ServeMux.register panic with a raw stack
// trace (e.g. when a Helm/env template renders the flag blank); reject it here so the
// caller can exit via the normal logged config-error path instead of crash-looping.
func ValidateMetricsPath(path string) error {
	if path == "" {
		return fmt.Errorf("--web.telemetry-path (OPNSENSE_EXPORTER_WEB_TELEMETRY_PATH) must not be empty")
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("--web.telemetry-path must start with '/', got %q", path)
	}
	return nil
}
