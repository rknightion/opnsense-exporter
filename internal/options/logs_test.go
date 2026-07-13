package options

import (
	"testing"
	"time"
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
