package options

import (
	"fmt"

	"github.com/alecthomas/kingpin/v2"
)

// logsSelfEnabled opts the exporter's own slog records into the OTLP log
// shipping pipeline. It is deliberately separate from logs.enabled: the latter
// controls the event sources, while this switch controls whether process logs
// are also admitted to that shared pipeline.
var logsSelfEnabled = kingpin.Flag(
	"logs.self.enabled",
	"Ship the exporter's own slog records through the OTLP logs sink as well as stderr. Off by default; requires --logs.enabled and --logs.sink=otlp.",
).Envar("OPN2OTEL_LOGS_SELF_ENABLED").Default("false").Bool()

// LogsSelfEnabled reports whether the exporter's own slog records should be
// attached to the shared OTLP log pipeline.
func LogsSelfEnabled() bool { return *logsSelfEnabled }

// ValidateLogsSelf checks the dependencies of the self-log adapter without
// reading flag state. Keeping this pure lets resolveOptions use the same rule
// for both --config.check and a real start, while callers can safely pass an
// empty sink when --logs.enabled is false and no LogsConfig exists.
func ValidateLogsSelf(enabled, logsEnabled bool, sink string) error {
	if !enabled {
		return nil
	}
	if !logsEnabled {
		return fmt.Errorf("--logs.self.enabled requires --logs.enabled")
	}
	if sink != "otlp" {
		return fmt.Errorf("--logs.self.enabled requires --logs.sink=otlp; stdout cannot carry OTLP resource attributes")
	}
	return nil
}
