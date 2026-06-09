package options_test

import (
	"strings"
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/rknightion/opnsense-exporter/internal/collector"
	"github.com/rknightion/opnsense-exporter/internal/options"
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

	modelFlags := map[string]bool{}
	for _, f := range model.Flags {
		modelFlags[f.Name] = true
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

func TestRegisterAllFlagsIdempotent(t *testing.T) {
	options.RegisterAllFlags()
	options.RegisterAllFlags() // second call must not panic (kingpin panics on duplicate flags)
}
