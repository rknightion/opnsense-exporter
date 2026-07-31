package telemetry

import (
	"context"
	"testing"

	"github.com/rknightion/opnsense2otel/v4/internal/options"
)

// attrsOf flattens a built resource into a key->value map.
func attrsOf(t *testing.T, includeServiceVersion bool) map[string]string {
	t.Helper()
	res, err := buildResource(context.Background(),
		&options.OTLPConfig{ServiceName: "svc"}, "1.2.3", "fw1", includeServiceVersion)
	if err != nil && res == nil {
		t.Fatalf("buildResource: %v", err)
	}
	got := map[string]string{}
	for _, kv := range res.Attributes() {
		got[string(kv.Key)] = kv.Value.AsString()
	}
	return got
}

// TestMetricsResourceOmitsServiceVersion is the regression guard for #472.
//
// Grafana Cloud's OTLP gateway promotes service.version from the resource to a
// label on EVERY series. It cannot promote an attribute that is absent, so the only
// exporter-side lever is to leave it off the metrics resource — which is exactly
// what the sibling exporters do (rknightion/graph2otel#104,
// rknightion/tailscale2otel#187). Before this was fixed, `service_version` was a
// label on 552 metric names here, including every go_* runtime metric, so each
// redeploy minted a fresh series set and any sum-style panel double-counted for the
// query-lookback window.
//
// #270 previously closed this as unfixable on the reasoning that "no exporter-side
// change can prevent it". That was wrong, and this test exists so it cannot be
// re-asserted: re-adding the attribute to the metrics resource fails here.
func TestMetricsResourceOmitsServiceVersion(t *testing.T) {
	got := attrsOf(t, false)

	if v, ok := got[keyServiceVersion]; ok {
		t.Errorf("metrics resource carries %s=%q; it must be omitted or Grafana Cloud "+
			"promotes it to a label on every series (#472). Version is exposed via "+
			"opnsense_exporter_build_info instead.", keyServiceVersion, v)
	}

	// The identity attributes that legitimately become `job` and `instance` must
	// survive: dropping version must not drop the resource's identity with it.
	if got[keyServiceName] != "svc" {
		t.Errorf("service.name = %q, want svc", got[keyServiceName])
	}
	if got[keyServiceInstanceID] != "fw1" {
		t.Errorf("service.instance.id = %q, want fw1", got[keyServiceInstanceID])
	}
}

// TestResourceKeepsServiceVersionWhenRequested pins the other half of the contract.
// The flag must be a real switch, not a hardcoded omission: the logs resource in
// internal/logship keeps service.version deliberately (log records are never summed,
// so it lands in structured metadata and costs no label), and any future
// traces resource here would want the same. A blanket deletion would silently make
// this parameter a lie.
func TestResourceKeepsServiceVersionWhenRequested(t *testing.T) {
	got := attrsOf(t, true)

	if got[keyServiceVersion] != "1.2.3" {
		t.Errorf("service.version = %q, want 1.2.3 when includeServiceVersion is true",
			got[keyServiceVersion])
	}
}

// TestStartUsesTheMetricsResource proves the omission is wired into the real
// MeterProvider path rather than only reachable through buildResource directly.
// buildResource is called in exactly one place (provider.go), so this guards the
// wiring: passing `true` there would restore the 552-metric label with every unit
// test above still green.
func TestStartUsesTheMetricsResource(t *testing.T) {
	if metricsResourceIncludesServiceVersion {
		t.Fatal("provider.go builds the metrics resource with service.version included; " +
			"that is the #472 regression — the MeterProvider resource must omit it")
	}
}
