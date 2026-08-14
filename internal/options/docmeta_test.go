package options_test

import (
	"strings"
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/rknightion/opnsense2otel/v4/internal/collector"
	"github.com/rknightion/opnsense2otel/v4/internal/options"
)

func TestCollectorFlagsCoverAllSwitchFlags(t *testing.T) {
	options.RegisterAllFlags()
	model := kingpin.CommandLine.Model()

	declared := map[string]options.CollectorFlag{}
	for _, cf := range options.CollectorFlags {
		if _, dup := declared[cf.Flag]; dup {
			t.Errorf("duplicate CollectorFlags entry %q", cf.Flag)
		}
		declared[cf.Flag] = cf
		if _, ok := collector.SubsystemDisplayNames[cf.Subsystem]; !ok {
			t.Errorf("CollectorFlags entry %q references unknown subsystem %q", cf.Flag, cf.Subsystem)
		}
	}

	// exporter.enable-all-available (#517) is exempt: it is the blanket switch
	// that flips every OTHER enable-* collector switch, not a switch for one
	// collector of its own, so it has no single CollectorFlags subsystem to
	// declare.
	const blanketEnableFlag = "exporter.enable-all-available"

	modelFlags := map[string]bool{}
	for _, f := range model.Flags {
		modelFlags[f.Name] = true
		if f.Name == blanketEnableFlag {
			continue
		}
		if strings.HasPrefix(f.Name, "exporter.disable-") || strings.HasPrefix(f.Name, "exporter.enable-") {
			if _, ok := declared[f.Name]; !ok {
				t.Errorf("flag --%s has no CollectorFlags entry (add one in collectors.go)", f.Name)
			}
		}
	}
	for _, cf := range options.CollectorFlags {
		if !modelFlags[cf.Flag] {
			t.Errorf("CollectorFlags entry %q matches no registered flag", cf.Flag)
		}
	}
}

// TestEveryCollectorHasDisableSwitch covers #143: every collector that self-registers
// via init() must have a CollectorFlags entry (a disable or enable switch), so a future
// collector added without one — the exact gap that left interfaces/protocol/services
// ungated — fails this test instead of silently shipping non-optional.
func TestEveryCollectorHasDisableSwitch(t *testing.T) {
	options.RegisterAllFlags()

	flaggedSubsystems := map[string]bool{}
	for _, cf := range options.CollectorFlags {
		if !cf.Detail { // detail flags gate extra metrics, not the collector's registration
			flaggedSubsystems[cf.Subsystem] = true
		}
	}
	for _, c := range collector.AllCollectors() {
		if !flaggedSubsystems[c.Name()] {
			t.Errorf("collector %q has no enable/disable CollectorFlags entry (add one per the AGENTS.md recipe)", c.Name())
		}
	}
}

func TestRegisterAllFlagsIdempotent(t *testing.T) {
	options.RegisterAllFlags()
	options.RegisterAllFlags() // second call must not panic (kingpin panics on duplicate flags)
}

// TestAllFlagsHaveEnvar covers #141: every project-owned flag must be settable via an
// OPN2OTEL_-prefixed env var (a fully env-driven deployment), and
// --web.telemetry-path specifically must expose OPN2OTEL_WEB_TELEMETRY_PATH.
func TestAllFlagsHaveEnvar(t *testing.T) {
	options.RegisterAllFlags()
	model := kingpin.CommandLine.Model()

	var telemetry *kingpin.FlagModel
	for _, f := range model.Flags {
		// Skip toolkit-provided flags (web.*, help, version) except the project's own
		// web.telemetry-path, which we assert explicitly below.
		if f.Name == "web.telemetry-path" {
			telemetry = f
			continue
		}
		if !strings.HasPrefix(f.Name, "opnsense.") && !strings.HasPrefix(f.Name, "exporter.") && !strings.HasPrefix(f.Name, "otlp.") {
			continue
		}
		if f.Envar == "" {
			t.Errorf("project flag --%s has no env var binding", f.Name)
		}
		if !strings.HasPrefix(f.Envar, "OPN2OTEL_") {
			t.Errorf("flag --%s env var %q is not OPN2OTEL_-prefixed", f.Name, f.Envar)
		}
	}
	if telemetry == nil {
		t.Fatal("web.telemetry-path flag not found")
	}
	if telemetry.Envar != "OPN2OTEL_WEB_TELEMETRY_PATH" {
		t.Errorf("web.telemetry-path env var = %q, want OPN2OTEL_WEB_TELEMETRY_PATH", telemetry.Envar)
	}
}
