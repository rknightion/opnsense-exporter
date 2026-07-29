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
			"record is dropped and counted (logs_dropped_total). At the measured ~475 bytes/record retained "+
			"size, 65536 records is ~31MB, comfortably under the 128MiB --logs.buffer-max-bytes default, so "+
			"the two bounds read against one number instead of this record cap silently binding first at a "+
			"fraction of the byte budget.",
	).Envar("OPNSENSE_EXPORTER_LOGS_BUFFER_SIZE").Default("65536").Int()
	logsBatchMax = kingpin.Flag(
		"logs.batch-max",
		"Maximum number of records the emitter hands to the sink per batch. The sink pays a fixed "+
			"per-resource-partition round-trip, and distinct partitions plateau with batch duration, so a "+
			"larger batch amortises that fixed cost almost linearly rather than costing proportionally more.",
	).Envar("OPNSENSE_EXPORTER_LOGS_BATCH_MAX").Default("5000").Int()
	logsBufferMaxBytes = kingpin.Flag(
		"logs.buffer-max-bytes",
		"Aggregate byte budget for the in-memory backpressure queue. The record-count cap "+
			"(--logs.buffer-size) alone does not bound memory: a receiver preserves each record's raw body, "+
			"so a few large records can outweigh thousands of small ones. On overflow the oldest record is "+
			"dropped and counted, exactly as for the count cap. 0 disables the byte budget.",
	).Envar("OPNSENSE_EXPORTER_LOGS_BUFFER_MAX_BYTES").Default("134217728").Int()
	logsMaxRecordBytes = kingpin.Flag(
		"logs.max-record-bytes",
		"Maximum estimated retained size for a single record - its body, source and attributes plus a "+
			"fixed overhead allowance, measured the same way as --logs.buffer-max-bytes so the two read "+
			"against one number. A record larger than this is rejected at ingest and counted rather than "+
			"queued, so one oversized record cannot occupy the whole queue budget or become a batch the "+
			"sink permanently refuses. 0 disables the per-record cap.",
	).Envar("OPNSENSE_EXPORTER_LOGS_MAX_RECORD_BYTES").Default("1048576").Int()
	logsShipMaxAttempts = kingpin.Flag(
		"logs.ship-max-attempts",
		"Maximum delivery attempts for one batch before it is dropped and counted "+
			"(logs_dropped_total{reason=\"ship_failed_permanent\"}). Retries are exponentially backed off. "+
			"Without this bound a batch the sink permanently refuses is retried forever by the single emitter "+
			"goroutine, wedging all subsequent delivery. 0 restores unlimited retries.",
	).Envar("OPNSENSE_EXPORTER_LOGS_SHIP_MAX_ATTEMPTS").Default("10").Int()
	logsMaxMetricKeys = kingpin.Flag(
		"logs.max-metric-keys",
		"Maximum distinct label tuples retained per derived log_events metric family. Receivers are "+
			"push-based and syslog over UDP has a spoofable source, so tuple values are sender-controlled: "+
			"without this bound a sender can grow process-lifetime metric state without limit. Tuples beyond "+
			"the cap fold into a counted overflow series rather than being dropped silently. 0 disables the cap.",
	).Envar("OPNSENSE_EXPORTER_LOGS_MAX_METRIC_KEYS").Default("5000").Int()
	logsStateFile = kingpin.Flag(
		"logs.state-file",
		"Optional path to persist per-source cursors across restarts (atomic JSON). Empty = in-memory only "+
			"(resume from now on restart).",
	).Envar("OPNSENSE_EXPORTER_LOGS_STATE_FILE").Default("").String()
	logsShipConcurrency = kingpin.Flag(
		"logs.ship-concurrency",
		"Maximum number of resource partitions within one batch that the sink exports concurrently. Each "+
			"partition is a separate synchronous wire request, so a batch of N partitions previously cost N "+
			"sequential round-trips. 1 restores the old fully-sequential behaviour. Values below 1 are "+
			"normalised to 1.",
	).Envar("OPNSENSE_EXPORTER_LOGS_SHIP_CONCURRENCY").Default("8").Int()
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
	// BufferMaxBytes and MaxRecordBytes bound queue MEMORY, which BufferSize does
	// not: it counts records, and a receiver preserves each record's raw body. Zero
	// disables either bound.
	BufferMaxBytes int
	MaxRecordBytes int
	// ShipMaxAttempts bounds retries for one batch. Zero means unlimited, which is
	// the pre-#325 behaviour and lets a permanently-refused batch wedge the emitter.
	ShipMaxAttempts int
	// MaxMetricKeys bounds distinct label tuples per derived metric family. Zero
	// disables the cap.
	MaxMetricKeys int
	// ShipConcurrency bounds how many resource partitions within one batch the
	// sink exports concurrently. Always normalised to at least 1.
	ShipConcurrency int
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
	// A batch larger than the whole queue can never be filled, so batch-max
	// silently caps effective batch size at buffer-size instead of the value
	// the operator asked for. Refuse the combination rather than accept a flag
	// that can never do what it says.
	if c.BatchMax > c.BufferSize {
		return fmt.Errorf(
			"logs batch-max (%d) must not exceed logs buffer-size (%d); a batch larger than the whole queue can never be filled",
			c.BatchMax, c.BufferSize)
	}
	if c.BufferMaxBytes < 0 {
		return fmt.Errorf("logs buffer-max-bytes must not be negative, got %d", c.BufferMaxBytes)
	}
	if c.MaxRecordBytes < 0 {
		return fmt.Errorf("logs max-record-bytes must not be negative, got %d", c.MaxRecordBytes)
	}
	// A per-record cap above the whole queue budget can never admit a record, so
	// the pipeline would silently reject everything. Refuse the combination rather
	// than ship a receiver that accepts nothing.
	if c.BufferMaxBytes > 0 && c.MaxRecordBytes > c.BufferMaxBytes {
		return fmt.Errorf(
			"logs max-record-bytes (%d) must not exceed logs buffer-max-bytes (%d); no record could ever be queued",
			c.MaxRecordBytes, c.BufferMaxBytes)
	}
	if c.ShipMaxAttempts < 0 {
		return fmt.Errorf("logs ship-max-attempts must not be negative, got %d", c.ShipMaxAttempts)
	}
	if c.MaxMetricKeys < 0 {
		return fmt.Errorf("logs max-metric-keys must not be negative, got %d", c.MaxMetricKeys)
	}
	// A non-positive concurrency is a benign misconfiguration, not an impossible
	// combination, so normalise rather than error.
	if c.ShipConcurrency < 1 {
		c.ShipConcurrency = 1
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

		BufferMaxBytes:  *logsBufferMaxBytes,
		MaxRecordBytes:  *logsMaxRecordBytes,
		ShipMaxAttempts: *logsShipMaxAttempts,
		MaxMetricKeys:   *logsMaxMetricKeys,
		ShipConcurrency: *logsShipConcurrency,
	}
	if err := cfg.Validate(); err != nil {
		return nil, false, err
	}
	return cfg, true, nil
}
