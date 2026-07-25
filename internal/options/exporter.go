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
		"Exclude metrics about the exporter itself (process_*, go_*).",
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
		"Upper bound on a single collector poll (#336). Since serving /metrics now replays an in-memory snapshot rather than calling the API, this bounds each background poll so a stalled/blackholed endpoint frees its poll-concurrency slot instead of holding it open. Serving itself is never blocked by it.",
	).Envar("OPNSENSE_EXPORTER_MAX_SCRAPE_DURATION").Default("50s").Duration()

	CollectorPollInterval = kingpin.Flag(
		"collector.poll-interval",
		"Default interval at which each collector polls the OPNsense API into the in-memory snapshot that /metrics and the OTLP bridge replay (#336). A collector may declare its own faster/slower tier; every interval is clamped to [5s, 15m].",
	).Envar("OPNSENSE_EXPORTER_COLLECTOR_POLL_INTERVAL").Default("60s").Duration()

	CollectorHealthPollInterval = kingpin.Flag(
		"collector.health-poll-interval",
		"Interval at which the exporter polls the OPNsense health endpoint (#386). This is the circuit-breaker cadence: the health poll sets and clears the process-wide 'firewall unreachable' flag, so it bounds how quickly collectors resume after the box recovers. Independent of --collector.poll-interval since #386, which previously controlled it by accident. Clamped to [5s, 15m].",
	).Envar("OPNSENSE_EXPORTER_COLLECTOR_HEALTH_POLL_INTERVAL").Default("60s").Duration()

	CollectorPollIntervalOverrides = kingpin.Flag(
		"collector.poll-interval-override",
		"Override a specific collector's poll interval as <collector>=<duration> (repeatable; clamped to [5s, 15m]). Wins over the collector's built-in tier. Example: --collector.poll-interval-override=gateways=10s --collector.poll-interval-override=smart=1h.",
	).Envar("OPNSENSE_EXPORTER_COLLECTOR_POLL_INTERVAL_OVERRIDE").StringMap()

	IDSAlertLookback = kingpin.Flag(
		"exporter.ids-alert-lookback",
		"Lookback window over which opnsense_ids_recent_alerts counts Suricata eve alerts (a gauge). Only used when --exporter.enable-ids-alerts is set. Counts are a floor when more than 500 alerts fall inside the window.",
	).Envar("OPNSENSE_EXPORTER_IDS_ALERT_LOOKBACK").Default("15m").Duration()

	WebConfig = kingpinflag.AddFlags(kingpin.CommandLine, ":8080")
)

// ValidateMetricsPath checks the resolved --web.telemetry-path value. An empty or
// non-"/"-prefixed value would make net/http.ServeMux.register panic with a raw stack
// trace (e.g. when a Helm/env template renders the flag blank); reject it here so the
// caller can exit via the normal logged config-error path instead of crash-looping.
//
// reserved lists the fixed routes the exporter registers itself (the health and
// readiness handlers). Registering the metrics handler under one of those patterns
// and then registering the fixed handler under the same pattern is a duplicate
// pattern, which net/http.ServeMux treats as a programmer error and panics on — so a
// syntactically valid --web.telemetry-path=/-/healthy would crash-loop. Reject the
// collision here instead. The caller passes the paths so this stays the single source
// of truth without an import edge into the server package.
func ValidateMetricsPath(path string, reserved ...string) error {
	if path == "" {
		return fmt.Errorf("--web.telemetry-path (OPNSENSE_EXPORTER_WEB_TELEMETRY_PATH) must not be empty")
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("--web.telemetry-path must start with '/', got %q", path)
	}
	for _, r := range reserved {
		if path == r {
			return fmt.Errorf("--web.telemetry-path (OPNSENSE_EXPORTER_WEB_TELEMETRY_PATH) %q collides with the reserved %q route; choose a different path", path, r)
		}
	}
	return nil
}
