package options

import (
	"strings"
	"testing"

	"github.com/alecthomas/kingpin/v2"
)

func TestLogsSelfFlagDefaultsOff(t *testing.T) {
	RegisterAllFlags()
	model := kingpin.CommandLine.Model()
	for _, flag := range model.Flags {
		if flag.Name != "logs.self.enabled" {
			continue
		}
		if len(flag.Default) != 1 || flag.Default[0] != "false" {
			t.Fatalf("--logs.self.enabled default = %v, want [false]", flag.Default)
		}
		if flag.Envar != "OPN2OTEL_LOGS_SELF_ENABLED" {
			t.Fatalf("--logs.self.enabled envar = %q, want OPN2OTEL_LOGS_SELF_ENABLED", flag.Envar)
		}
		return
	}
	t.Fatal("--logs.self.enabled is not registered")
}

func TestValidateLogsSelf(t *testing.T) {
	tests := []struct {
		name        string
		enabled     bool
		logsEnabled bool
		sink        string
		want        string
	}{
		{name: "off ignores dependencies", enabled: false, logsEnabled: false, sink: "stdout"},
		{name: "requires pipeline", enabled: true, logsEnabled: false, sink: "otlp", want: "requires --logs.enabled"},
		{name: "requires otlp", enabled: true, logsEnabled: true, sink: "stdout", want: "requires --logs.sink=otlp"},
		{name: "otlp accepted", enabled: true, logsEnabled: true, sink: "otlp"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateLogsSelf(tc.enabled, tc.logsEnabled, tc.sink)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("ValidateLogsSelf() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateLogsSelf() error = %v, want substring %q", err, tc.want)
			}
		})
	}
}
