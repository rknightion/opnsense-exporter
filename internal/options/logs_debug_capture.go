package options

import (
	"strings"

	"github.com/alecthomas/kingpin/v2"
)

// Debug-capture is the shared sink that dumps the receiver signals the exporter
// does NOT model (unhandled Zenarmor endpoints, unknown families, parse errors,
// unparsed syslog lines) to disk for inspection (#330). The dir + cap are global;
// each receiver opts in with its own --logs.<recv>.debug-capture bool, so one bind
// mount serves every receiver and the byte cap governs the whole of it.
var (
	logsDebugCaptureDir = kingpin.Flag(
		"logs.debug-capture.dir",
		"Directory to dump UNMODELLED receiver signals into for inspection, as NDJSON under "+
			"<dir>/<receiver>/ (files are 0600 and carry real network data — addresses, DNS "+
			"queries, TLS SNI, HTTP hosts). Off unless set. Enable capture per receiver with "+
			"--logs.zenarmor.debug-capture / --logs.syslog.debug-capture. Point a writable bind "+
			"mount here; only signals the exporter cannot model are written, never the full stream.",
	).Envar("OPNSENSE_EXPORTER_LOGS_DEBUG_CAPTURE_DIR").Default("").String()

	// Base2 so 256MiB parses. The cap governs the WHOLE dir, counting bytes left by
	// previous runs, and STOPS capture when reached (oldest samples kept) rather than
	// rotating them away — the first time we see an unknown is the sample worth having.
	logsDebugCaptureMaxBytes = kingpin.Flag(
		"logs.debug-capture.max-bytes",
		"Total size cap for --logs.debug-capture.dir (e.g. 256MiB, 1GB). Capture STOPS when the "+
			"dir reaches this, keeping the oldest samples; it never deletes to make room, so a "+
			"debug capture can never fill the disk. Counts bytes left by previous runs.",
	).Envar("OPNSENSE_EXPORTER_LOGS_DEBUG_CAPTURE_MAX_BYTES").Default("256MiB").Bytes()
)

// LogsDebugCaptureDir returns the trimmed capture directory, empty when unset.
func LogsDebugCaptureDir() string { return strings.TrimSpace(*logsDebugCaptureDir) }

// LogsDebugCaptureEnabled reports whether a capture dir is configured at all. A
// per-receiver toggle is meaningful only when this is true.
func LogsDebugCaptureEnabled() bool { return LogsDebugCaptureDir() != "" }

// defaultDebugCaptureMaxBytes floors the cap. A zero/negative cap would make the
// capturer treat the dir as UNLIMITED — the opposite of this feature's purpose — so a
// non-positive value (including the unparsed zero in a unit test, or an explicit 0)
// resolves to this default rather than "no cap". The disk must always be protected.
const defaultDebugCaptureMaxBytes int64 = 256 << 20

// LogsDebugCaptureMaxBytes returns the configured cap in bytes, never non-positive.
func LogsDebugCaptureMaxBytes() int64 {
	if logsDebugCaptureMaxBytes == nil || int64(*logsDebugCaptureMaxBytes) <= 0 {
		return defaultDebugCaptureMaxBytes
	}
	return int64(*logsDebugCaptureMaxBytes)
}
