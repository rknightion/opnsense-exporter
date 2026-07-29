package collector

import (
	"testing"

	"github.com/rknightion/opnsense-exporter/internal/options"
)

// Each availability probe carries the flag and the why-it-is-off reason it
// reports to the operator, and both are copied from options.CollectorFlags.
// Two copies of a string that must agree is exactly the shape that drifts
// silently: nothing else fails when a flag's reason is reworded over there and
// the probe keeps announcing the old one, and the operator then reads a stale
// justification for a collector we have just told them to switch on.
func TestAvailabilityProbesMatchCollectorFlags(t *testing.T) {
	byFlag := make(map[string]options.CollectorFlag, len(options.CollectorFlags))
	for _, cf := range options.CollectorFlags {
		byFlag[cf.Flag] = cf
	}

	for _, probe := range featureAvailabilityProbes {
		cf, ok := byFlag[probe.Flag]
		if !ok {
			t.Errorf("probe %q names flag %q, which has no CollectorFlags entry", probe.Feature, probe.Flag)
			continue
		}
		if cf.Subsystem != probe.Feature {
			t.Errorf("probe %q is bound to flag %q, whose subsystem is %q — the feature label "+
				"must be the subsystem the flag enables", probe.Feature, probe.Flag, cf.Subsystem)
		}
		if cf.Reason == "" {
			t.Errorf("CollectorFlags entry for %q has no Reason, so the probe has nothing "+
				"truthful to tell an operator about why the collector is off", probe.Flag)
		}
		if probe.Reason != cf.Reason {
			t.Errorf("probe %q reports reason\n\t%q\nbut CollectorFlags says\n\t%q\n"+
				"they are two copies of one fact and must agree", probe.Feature, probe.Reason, cf.Reason)
		}
	}
}
