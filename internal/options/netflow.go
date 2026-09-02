package options

import (
	"fmt"

	"github.com/alecthomas/kingpin/v2"
)

const (
	// DefaultNetflowWorkers is the number of decoder goroutines used when the
	// NetFlow worker count is not explicitly set.
	DefaultNetflowWorkers = 4
	// DefaultNetflowQueueSize is the number of datagrams buffered between the
	// NetFlow socket reader and its decoder workers by default.
	DefaultNetflowQueueSize = 1024
)

var (
	flowNetflowWorkers = kingpin.Flag(
		"flow.netflow.workers",
		"Number of concurrent NetFlow datagram decoder workers. More workers can increase decode throughput, but delivery order is not preserved. 0 uses the built-in default of 4.",
	).Envar("OPN2OTEL_FLOW_NETFLOW_WORKERS").Default("4").Int()

	flowNetflowQueueSize = kingpin.Flag(
		"flow.netflow.queue-size",
		"Maximum number of NetFlow datagrams buffered between the socket reader and decoder workers. A full queue drops and counts the datagram rather than blocking the reader. 0 uses the built-in default of 1024.",
	).Envar("OPN2OTEL_FLOW_NETFLOW_QUEUE_SIZE").Default("1024").Int()
)

// NetflowConfig contains the sizing knobs for the NetFlow UDP listener. Zero
// selects the listener's built-in default; negative values are invalid.
//
// This is deliberately separate from FlowConfig: the flow package owns the
// receiver's runtime configuration, while this small options surface owns only
// the two worker-pool controls added after the rest of the flow flags existed.
type NetflowConfig struct {
	Workers   int
	QueueSize int
}

// Netflow resolves and validates the NetFlow worker-pool sizing flags. It is
// safe to call before kingpin.Parse as well: an unset integer flag reads zero,
// which resolves to the same defaults that a parsed invocation receives.
func Netflow() (NetflowConfig, error) {
	cfg := NetflowConfig{
		Workers:   netflowWorkersValue(),
		QueueSize: netflowQueueSizeValue(),
	}
	if err := cfg.Validate(); err != nil {
		return NetflowConfig{}, err
	}
	return cfg, nil
}

// NetflowWorkers returns the resolved worker count. Callers that need startup
// validation should use Netflow, not this convenience accessor.
func NetflowWorkers() int {
	return netflowWorkersValue()
}

// NetflowQueueSize returns the resolved queue depth. Callers that need startup
// validation should use Netflow, not this convenience accessor.
func NetflowQueueSize() int {
	return netflowQueueSizeValue()
}

func netflowWorkersValue() int {
	if *flowNetflowWorkers == 0 {
		return DefaultNetflowWorkers
	}
	return *flowNetflowWorkers
}

func netflowQueueSizeValue() int {
	if *flowNetflowQueueSize == 0 {
		return DefaultNetflowQueueSize
	}
	return *flowNetflowQueueSize
}

// Validate rejects negative values before they can reach the listener. Zero is
// intentionally valid and means "use the built-in default", matching the
// listener's existing zero-value behavior and making an omitted pre-parse value
// safe as well.
func (c NetflowConfig) Validate() error {
	if c.Workers < 0 {
		return fmt.Errorf("flow: --flow.netflow.workers must not be negative (got %d); 0 uses the built-in default", c.Workers)
	}
	if c.QueueSize < 0 {
		return fmt.Errorf("flow: --flow.netflow.queue-size must not be negative (got %d); 0 uses the built-in default", c.QueueSize)
	}
	return nil
}
