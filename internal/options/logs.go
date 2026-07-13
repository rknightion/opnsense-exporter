package options

import (
	"fmt"
	"time"

	"github.com/alecthomas/kingpin/v2"
)

// minPollInterval is the hard floor on --logs.poll-interval. Polling the OPNsense
// API faster than this spawns configd/python work on the box every few seconds
// for no benefit at homelab/SMB event volumes.
const minPollInterval = 5 * time.Second

var (
	logsEnabled = kingpin.Flag(
		"logs.enabled",
		"Enable the opt-in log/event shipping pipeline (polls OPNsense event APIs and ships to Loki via OTLP). "+
			"Off by default. Independent of --otlp.enabled (which gates metrics).",
	).Envar("OPNSENSE_EXPORTER_LOGS_ENABLED").Default("false").Bool()
	logsSink = kingpin.Flag(
		"logs.sink",
		"Log shipping sink: otlp (OTLP logs, reuses the --otlp.* transport) or stdout (one JSON line per event).",
	).Envar("OPNSENSE_EXPORTER_LOGS_SINK").Default("otlp").Enum("otlp", "stdout")
	logsPollInterval = kingpin.Flag(
		"logs.poll-interval",
		"Base interval between event polls per source (floor 5s). Sources may raise their own floor.",
	).Envar("OPNSENSE_EXPORTER_LOGS_POLL_INTERVAL").Default("10s").Duration()
	logsBufferSize = kingpin.Flag(
		"logs.buffer-size",
		"Capacity of the in-memory backpressure queue between pollers and the sink. On overflow the oldest "+
			"record is dropped and counted (logs_dropped_total).",
	).Envar("OPNSENSE_EXPORTER_LOGS_BUFFER_SIZE").Default("4096").Int()
	logsBatchMax = kingpin.Flag(
		"logs.batch-max",
		"Maximum number of records the emitter hands to the sink per batch.",
	).Envar("OPNSENSE_EXPORTER_LOGS_BATCH_MAX").Default("1000").Int()
	logsStateFile = kingpin.Flag(
		"logs.state-file",
		"Optional path to persist per-source cursors across restarts (atomic JSON). Empty = in-memory only "+
			"(resume from now on restart).",
	).Envar("OPNSENSE_EXPORTER_LOGS_STATE_FILE").Default("").String()
)

// LogsConfig is the resolved configuration for the log-shipping pipeline.
// Transport (endpoint/protocol/TLS/headers/service-name) for the OTLP sink is
// resolved separately via OTLPTransport so metrics (--otlp.enabled) and logs
// (--logs.enabled) share one transport family without either gating the other.
type LogsConfig struct {
	Sink         string // "otlp" | "stdout"
	PollInterval time.Duration
	BufferSize   int
	BatchMax     int
	StateFile    string
}

// Validate checks an enabled logs configuration for internal consistency.
func (c *LogsConfig) Validate() error {
	switch c.Sink {
	case "otlp", "stdout":
	default:
		return fmt.Errorf("logs sink must be otlp or stdout, got %q", c.Sink)
	}
	if c.PollInterval < minPollInterval {
		return fmt.Errorf("logs poll-interval must be >= %s, got %s", minPollInterval, c.PollInterval)
	}
	if c.BufferSize < 1 {
		return fmt.Errorf("logs buffer-size must be positive, got %d", c.BufferSize)
	}
	if c.BatchMax < 1 {
		return fmt.Errorf("logs batch-max must be positive, got %d", c.BatchMax)
	}
	return nil
}

// Logs assembles the log-shipping configuration from flags/env. The returned
// bool reports whether the pipeline is enabled (true only when --logs.enabled is
// set).
func Logs() (*LogsConfig, bool, error) {
	if !*logsEnabled {
		return nil, false, nil
	}
	cfg := &LogsConfig{
		Sink:         *logsSink,
		PollInterval: *logsPollInterval,
		BufferSize:   *logsBufferSize,
		BatchMax:     *logsBatchMax,
		StateFile:    *logsStateFile,
	}
	if err := cfg.Validate(); err != nil {
		return nil, false, err
	}
	return cfg, true, nil
}
