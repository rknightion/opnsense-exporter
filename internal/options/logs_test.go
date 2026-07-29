package options

import (
	"testing"
	"time"

	"github.com/alecthomas/kingpin/v2"
)

func TestLogsConfigValidate(t *testing.T) {
	base := func() *LogsConfig {
		return &LogsConfig{Sink: "otlp", PollInterval: 10 * time.Second, BufferSize: 4096, BatchMax: 1000}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*LogsConfig)
		want   string
	}{
		{"bad sink", func(c *LogsConfig) { c.Sink = "kafka" }, "sink"},
		{"below poll floor", func(c *LogsConfig) { c.PollInterval = time.Second }, "poll-interval"},
		{"zero buffer", func(c *LogsConfig) { c.BufferSize = 0 }, "buffer-size"},
		{"zero batch", func(c *LogsConfig) { c.BatchMax = 0 }, "batch-max"},
		{"batch-max exceeds buffer-size", func(c *LogsConfig) { c.BatchMax = 5000; c.BufferSize = 4096 }, "batch-max"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			}
			if !contains(err.Error(), tc.want) {
				t.Fatalf("error %q missing %q", err.Error(), tc.want)
			}
		})
	}
}

func TestLogsPollFloorConstant(t *testing.T) {
	if minPollInterval != 5*time.Second {
		t.Fatalf("poll floor drifted: %s", minPollInterval)
	}
}

// TestLogsConfigValidate_ShipConcurrencyNormalised covers the --logs.ship-concurrency
// contract: a non-positive value is a benign misconfiguration, normalised to 1 rather
// than rejected as an error (unlike buffer-size/batch-max, which do error).
func TestLogsConfigValidate_ShipConcurrencyNormalised(t *testing.T) {
	cases := []struct {
		name  string
		input int
		want  int
	}{
		{"zero normalised to one", 0, 1},
		{"negative normalised to one", -5, 1},
		{"positive left untouched", 8, 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &LogsConfig{
				Sink: "otlp", PollInterval: 10 * time.Second, BufferSize: 4096, BatchMax: 1000,
				ShipConcurrency: tc.input,
			}
			if err := c.Validate(); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.ShipConcurrency != tc.want {
				t.Fatalf("ShipConcurrency = %d, want %d", c.ShipConcurrency, tc.want)
			}
		})
	}
}

// TestLogsFlagDefaults locks the flag surface this brief froze as a seam for the
// concurrent internal/logship lane: --logs.buffer-size (65536, up from the old 4096
// which bound at 1.5% of the byte budget), --logs.batch-max (5000, up from 1000, to
// amortise the sink's fixed per-partition round-trip), and the new
// --logs.ship-concurrency (default 8, env OPNSENSE_EXPORTER_LOGS_SHIP_CONCURRENCY).
func TestLogsFlagDefaults(t *testing.T) {
	RegisterAllFlags()
	model := kingpin.CommandLine.Model()

	want := map[string]struct {
		def   string
		envar string
	}{
		"logs.buffer-size":      {"65536", "OPNSENSE_EXPORTER_LOGS_BUFFER_SIZE"},
		"logs.batch-max":        {"5000", "OPNSENSE_EXPORTER_LOGS_BATCH_MAX"},
		"logs.ship-concurrency": {"8", "OPNSENSE_EXPORTER_LOGS_SHIP_CONCURRENCY"},
	}

	found := map[string]bool{}
	for _, f := range model.Flags {
		w, ok := want[f.Name]
		if !ok {
			continue
		}
		found[f.Name] = true
		if len(f.Default) != 1 || f.Default[0] != w.def {
			t.Errorf("--%s default = %v, want [%q]", f.Name, f.Default, w.def)
		}
		if f.Envar != w.envar {
			t.Errorf("--%s envar = %q, want %q", f.Name, f.Envar, w.envar)
		}
	}
	for name := range want {
		if !found[name] {
			t.Errorf("flag --%s not registered", name)
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
