package options

import (
	"strings"
	"testing"

	"github.com/alecthomas/kingpin/v2"
)

// A flag that quietly does nothing looks exactly like a quiet network, so every
// incoherent combination is a startup error rather than a silent no-op — the same
// rule --logs.zenarmor.families validation already follows.
func TestFlowConfig_RejectsNetflowWithoutFlowEnabled(t *testing.T) {
	c := FlowConfig{Enabled: false, NetflowEnabled: true, TopN: 1000, MaxKeys: 2500}
	if err := c.Validate(); err == nil {
		t.Fatal("--flow.netflow.enabled without --flow.enabled must be a startup error")
	}
}

func TestFlowConfig_RejectsNegativeBounds(t *testing.T) {
	for _, c := range []FlowConfig{
		{Enabled: true, TopN: -1, MaxKeys: 2500},
		{Enabled: true, TopN: 1000, MaxKeys: -1},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("negative bound accepted: %+v", c)
		}
	}
}

// top-n above max-keys is incoherent rather than merely odd: the emit cap can never
// bind above the insert cap, so the operator asked for something that cannot
// happen and should be told rather than left believing it took effect.
func TestFlowConfig_RejectsTopNAboveMaxKeys(t *testing.T) {
	if err := (FlowConfig{Enabled: true, TopN: 5000, MaxKeys: 2500}).Validate(); err == nil {
		t.Fatal("--flow.top-n above --flow.max-keys must be rejected")
	}
	// Zero means unbounded on either side, so neither combination is incoherent.
	for _, c := range []FlowConfig{
		{Enabled: true, TopN: 5000, MaxKeys: 0},
		{Enabled: true, TopN: 0, MaxKeys: 2500},
		{Enabled: true, TopN: 0, MaxKeys: 0},
	} {
		if err := c.Validate(); err != nil {
			t.Errorf("unbounded config rejected: %+v: %v", c, err)
		}
	}
}

// The shipped defaults are read from the flag model rather than from the parsed
// values: this package's tests must never call kingpin.Parse, which would os.Exit
// on the required connection flags (see webui_test.go:8).
func TestFlowConfig_ShippedDefaults(t *testing.T) {
	defaults := map[string]string{}
	for _, f := range kingpin.CommandLine.Model().Flags {
		if strings.HasPrefix(f.Name, "flow.") {
			defaults[f.Name] = strings.Join(f.Default, ",")
		}
	}
	for name, want := range map[string]string{
		// On by default: phase 1 opens no socket and derives from documents the
		// exporter already parses, so defaulting it off would ship a metric family
		// absent on every deployment.
		"flow.enabled":  "true",
		"flow.zenarmor": "true",
		"flow.top-n":    "1000",
		"flow.max-keys": "2500",
	} {
		if got, ok := defaults[name]; !ok {
			t.Errorf("--%s is not registered", name)
		} else if got != want {
			t.Errorf("--%s default = %q, want %q", name, got, want)
		}
	}
	// The NetFlow lane is phase 2: no flag may exist for it yet, or an operator can
	// turn on a listener that is not there.
	for name := range defaults {
		if strings.HasPrefix(name, "flow.netflow") {
			t.Errorf("--%s exists but the NetFlow lane is phase 2", name)
		}
	}
	// And those defaults must actually validate as a config.
	if err := (FlowConfig{Enabled: true, Zenarmor: true, TopN: 1000, MaxKeys: 2500}).Validate(); err != nil {
		t.Fatalf("the shipped defaults do not validate: %v", err)
	}
}
