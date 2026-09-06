package options

import (
	"fmt"

	"github.com/alecthomas/kingpin/v2"
)

// Console modes for --log.console. They are an enum rather than a boolean
// because the choice is "which copy of a record is authoritative", and a
// negated boolean (--log.no-console) reads as "log nothing", which is not what
// quiet does.
const (
	// LogConsoleFull tees every record: stderr and, with self-logs on, OTLP.
	LogConsoleFull = "full"
	// LogConsoleQuiet keeps stderr for the records the OTLP self-log path could
	// not take, and nothing else.
	LogConsoleQuiet = "quiet"
)

// logConsole selects how much of the exporter's own slog stream stays on
// stderr. It exists for the deployment where a node log collector already
// ships the container's stderr: with --logs.self.enabled on, every line then
// lands twice, once without the exporter's OTLP resource identity.
var logConsole = kingpin.Flag(
	"log.console",
	"How much of the exporter's own log stream stays on stderr: full (default) writes every record, "+
		"quiet writes only records the OTLP self-log path could not take. Requires --logs.self.enabled.",
).Envar("OPN2OTEL_LOG_CONSOLE").Default(LogConsoleFull).Enum(LogConsoleFull, LogConsoleQuiet)

// LogConsole reports the selected console mode.
func LogConsole() string { return *logConsole }

// LogConsoleIsQuiet reports whether stderr should carry only the self-log
// records the OTLP pipeline refused.
func LogConsoleIsQuiet() bool { return *logConsole == LogConsoleQuiet }

// ValidateLogConsole rejects quiet mode without the OTLP self-log path. It is
// pure for the same reason ValidateLogsSelf is: --config.check and a real start
// must apply one rule, not two that can drift.
//
// Quiet mode without self-logs is not a quieter exporter, it is a silent one:
// nothing would carry the records stderr stopped printing.
func ValidateLogConsole(console string, selfEnabled bool) error {
	if console != LogConsoleQuiet {
		return nil
	}
	if !selfEnabled {
		return fmt.Errorf(
			"--log.console=quiet requires --logs.self.enabled; without the OTLP self-log path " +
				"the suppressed records would go nowhere")
	}
	return nil
}
