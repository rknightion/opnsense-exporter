package options

import (
	"strings"
	"testing"

	"github.com/alecthomas/kingpin/v2"
)

func TestLogConsoleFlagDefaultsToFull(t *testing.T) {
	RegisterAllFlags()
	model := kingpin.CommandLine.Model()
	for _, flag := range model.Flags {
		if flag.Name != "log.console" {
			continue
		}
		if len(flag.Default) != 1 || flag.Default[0] != LogConsoleFull {
			t.Fatalf("--log.console default = %v, want [%s]", flag.Default, LogConsoleFull)
		}
		if flag.Envar != "OPN2OTEL_LOG_CONSOLE" {
			t.Fatalf("--log.console envar = %q, want OPN2OTEL_LOG_CONSOLE", flag.Envar)
		}
		return
	}
	t.Fatal("--log.console is not registered")
}

func TestValidateLogConsole(t *testing.T) {
	tests := []struct {
		name        string
		console     string
		selfEnabled bool
		want        []string
	}{
		{name: "full without self-logs", console: LogConsoleFull, selfEnabled: false},
		{name: "full with self-logs", console: LogConsoleFull, selfEnabled: true},
		{name: "quiet with self-logs", console: LogConsoleQuiet, selfEnabled: true},
		{
			name:    "quiet without self-logs names both flags",
			console: LogConsoleQuiet,
			want:    []string{"--log.console=quiet", "--logs.self.enabled"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateLogConsole(tc.console, tc.selfEnabled)
			if len(tc.want) == 0 {
				if err != nil {
					t.Fatalf("ValidateLogConsole() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateLogConsole() error = nil, want substrings %v", tc.want)
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("ValidateLogConsole() error = %v, want substring %q", err, want)
				}
			}
		})
	}
}
