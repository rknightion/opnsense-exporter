package collector

import (
	"testing"

	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense2otel/v4/internal/options"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// The probe table is plain data, so nothing in the type system stops a row from
// naming an endpoint that does not exist, a subsystem that is not a collector, or
// an endpoint whose 404 does not actually mean "plugin absent". Each of those
// fails silently at runtime — a mistyped endpoint name reads as a permanently
// unavailable plugin, which looks exactly like a plugin you have not installed.
func TestAvailabilityProbeTableIsWellFormed(t *testing.T) {
	cfg := options.OPNSenseConfig{
		Protocol: "https", Host: "example.invalid",
		APIKey: "k", APISecret: "s", MaxRetries: 1,
	}
	client, err := opnsense.NewClient(cfg, "t", promslog.NewNopLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	gated := make(map[opnsense.EndpointName]bool)
	for _, name := range opnsense.PluginGatedEndpoints() {
		gated[opnsense.EndpointName(name)] = true
	}

	seen := make(map[string]bool, len(featureAvailabilityProbes))
	for _, probe := range featureAvailabilityProbes {
		if seen[probe.Feature] {
			t.Errorf("feature %q is probed twice; the later row silently wins", probe.Feature)
		}
		seen[probe.Feature] = true

		if _, ok := SubsystemDisplayNames[probe.Feature]; !ok {
			t.Errorf("probe feature %q is not a registered collector subsystem, so its "+
				"availability metric would join to nothing", probe.Feature)
		}
		if _, ok := client.EndpointPathFor(probe.Endpoint); !ok {
			t.Errorf("probe for %q names endpoint %q, which the client does not know — it would "+
				"report the plugin as permanently absent", probe.Feature, probe.Endpoint)
		}
		if !gated[probe.Endpoint] {
			t.Errorf("probe for %q uses endpoint %q, which is not in PluginGatedEndpoints(): a 404 "+
				"there does NOT mean the plugin is absent, so the probe would misreport a core "+
				"route change as an uninstalled plugin", probe.Feature, probe.Endpoint)
		}
	}
}

// The report tells an operator which flag to set. If the subsystem has no
// CollectorFlags entry there is no flag to name, and the log line goes out with an
// empty one — which is worse than saying nothing, because it looks like a bug in
// the exporter rather than a gap in its metadata.
func TestEveryProbedFeatureHasAFlagToRecommend(t *testing.T) {
	for _, probe := range featureAvailabilityProbes {
		flag, envar, _ := featureFlagMeta(probe.Feature)
		if flag == "" || envar == "" {
			t.Errorf("feature %q has no CollectorFlags entry, so the availability report "+
				"cannot name a flag or env var for it (got flag=%q envar=%q)", probe.Feature, flag, envar)
		}
	}
}

func TestEnvarForFlag(t *testing.T) {
	for _, tc := range []struct{ flag, want string }{
		{"exporter.enable-smart", "OPN2OTEL_ENABLE_SMART"},
		{"exporter.disable-crowdsec", "OPN2OTEL_DISABLE_CROWDSEC"},
		{"exporter.enable-unbound-qstats", "OPN2OTEL_ENABLE_UNBOUND_QSTATS"},
	} {
		if got := envarForFlag(tc.flag); got != tc.want {
			t.Errorf("envarForFlag(%q) = %q, want %q", tc.flag, got, tc.want)
		}
	}
}
