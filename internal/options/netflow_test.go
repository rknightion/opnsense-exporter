package options

import (
	"strings"
	"testing"

	"github.com/alecthomas/kingpin/v2"
)

func TestNetflowSizingFlagDefaults(t *testing.T) {
	type flagExpectation struct {
		envar        string
		defaultValue string
	}
	expectations := map[string]flagExpectation{
		"flow.netflow.workers": {
			envar:        "OPN2OTEL_FLOW_NETFLOW_WORKERS",
			defaultValue: "4",
		},
		"flow.netflow.queue-size": {
			envar:        "OPN2OTEL_FLOW_NETFLOW_QUEUE_SIZE",
			defaultValue: "1024",
		},
	}

	flags := map[string]*kingpin.FlagModel{}
	for _, f := range kingpin.CommandLine.Model().Flags {
		if _, wanted := expectations[f.Name]; wanted {
			flags[f.Name] = f
		}
	}

	for name, want := range expectations {
		f, ok := flags[name]
		if !ok {
			t.Errorf("--%s is not registered", name)
			continue
		}
		if got := strings.Join(f.Default, ","); got != want.defaultValue {
			t.Errorf("--%s default = %q, want %q", name, got, want.defaultValue)
		}
		if f.Envar != want.envar {
			t.Errorf("--%s env var = %q, want %q", name, f.Envar, want.envar)
		}
	}
}

func TestNetflowConfigAcceptsZeroAsBuiltInDefault(t *testing.T) {
	if err := (NetflowConfig{Workers: 0, QueueSize: 0}).Validate(); err != nil {
		t.Fatalf("zero sizing should select the listener defaults: %v", err)
	}
}

func TestNetflowConfigRejectsNegativeSizing(t *testing.T) {
	for _, cfg := range []NetflowConfig{
		{Workers: -1, QueueSize: 1024},
		{Workers: 4, QueueSize: -1},
		{Workers: -1, QueueSize: -1},
	} {
		if err := cfg.Validate(); err == nil {
			t.Errorf("negative NetFlow sizing accepted: %+v", cfg)
		}
	}
}

func TestNetflowConfigAcceptsPositiveSizing(t *testing.T) {
	if err := (NetflowConfig{Workers: 8, QueueSize: 4096}).Validate(); err != nil {
		t.Fatalf("positive NetFlow sizing rejected: %v", err)
	}
}

func TestNetflowResolvesConfiguredSizing(t *testing.T) {
	oldWorkers, oldQueueSize := *flowNetflowWorkers, *flowNetflowQueueSize
	t.Cleanup(func() {
		*flowNetflowWorkers = oldWorkers
		*flowNetflowQueueSize = oldQueueSize
	})
	*flowNetflowWorkers = 8
	*flowNetflowQueueSize = 4096

	cfg, err := Netflow()
	if err != nil {
		t.Fatalf("configured NetFlow sizing rejected: %v", err)
	}
	if cfg.Workers != 8 || cfg.QueueSize != 4096 {
		t.Fatalf("resolved NetFlow sizing = %+v, want workers=8 queue-size=4096", cfg)
	}
}

func TestNetflowResolvesZeroToBuiltInDefaults(t *testing.T) {
	oldWorkers, oldQueueSize := *flowNetflowWorkers, *flowNetflowQueueSize
	t.Cleanup(func() {
		*flowNetflowWorkers = oldWorkers
		*flowNetflowQueueSize = oldQueueSize
	})
	*flowNetflowWorkers = 0
	*flowNetflowQueueSize = 0

	cfg, err := Netflow()
	if err != nil {
		t.Fatalf("zero NetFlow sizing rejected: %v", err)
	}
	if cfg.Workers != DefaultNetflowWorkers || cfg.QueueSize != DefaultNetflowQueueSize {
		t.Fatalf("zero NetFlow sizing = %+v, want workers=%d queue-size=%d",
			cfg, DefaultNetflowWorkers, DefaultNetflowQueueSize)
	}
}

func TestNetflowRejectsConfiguredNegativeSizing(t *testing.T) {
	oldWorkers, oldQueueSize := *flowNetflowWorkers, *flowNetflowQueueSize
	t.Cleanup(func() {
		*flowNetflowWorkers = oldWorkers
		*flowNetflowQueueSize = oldQueueSize
	})
	*flowNetflowWorkers = -1
	*flowNetflowQueueSize = 1024

	if _, err := Netflow(); err == nil {
		t.Fatal("negative NetFlow worker count was accepted")
	}

	*flowNetflowWorkers = 4
	*flowNetflowQueueSize = -1
	if _, err := Netflow(); err == nil {
		t.Fatal("negative NetFlow queue size was accepted")
	}
}
