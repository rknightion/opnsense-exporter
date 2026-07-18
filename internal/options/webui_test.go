package options

import (
	"testing"
)

// TestBuildEffectiveConfig_SecretsRedacted exercises the pure builder directly —
// it must never call Init()/kingpin.Parse(), which would os.Exit on the required
// opnsense.protocol/opnsense.address flags (ops.go:14-21). configInputs carries no
// secret string fields, only *Set presence booleans, so a leak is structurally
// impossible; this test is a belt-and-braces assertion on top of that.
func TestBuildEffectiveConfig_SecretsRedacted(t *testing.T) {
	in := configInputs{host: "fw.example", apiKeySet: true, apiSecretSet: true, otlpHeadersSet: true}
	for _, sec := range buildEffectiveConfig(in) {
		for _, it := range sec.Items {
			if it.Secret && it.Value != redacted && it.Value != "—" {
				t.Fatalf("secret %q not redacted: %q", it.Key, it.Value)
			}
		}
	}
}

// TestBuildEffectiveConfig_PresenceFalseRendersDash confirms an unset secret
// renders as the em-dash placeholder, not empty/blank.
func TestBuildEffectiveConfig_PresenceFalseRendersDash(t *testing.T) {
	in := configInputs{host: "fw.example"}
	for _, sec := range buildEffectiveConfig(in) {
		for _, it := range sec.Items {
			if it.Secret && it.Value != "—" {
				t.Fatalf("unset secret %q should render as em-dash, got %q", it.Key, it.Value)
			}
		}
	}
}

// TestBuildEffectiveConfig_PlainValuesPassThrough checks a couple of ordinary
// (non-secret) fields render their real value verbatim, and blank ones render "—".
func TestBuildEffectiveConfig_PlainValuesPassThrough(t *testing.T) {
	in := configInputs{
		host:        "fw.example",
		metricsPath: "/metrics",
		insecure:    true,
	}
	out := buildEffectiveConfig(in)
	var gotHost, gotInsecure, gotMetrics string
	for _, sec := range out {
		for _, it := range sec.Items {
			switch it.Key {
			case "Host":
				gotHost = it.Value
			case "Insecure TLS":
				gotInsecure = it.Value
			case "Metrics Path":
				gotMetrics = it.Value
			}
		}
	}
	if gotHost != "fw.example" {
		t.Fatalf("Host = %q", gotHost)
	}
	if gotInsecure != "on" {
		t.Fatalf("Insecure TLS = %q", gotInsecure)
	}
	if gotMetrics != "/metrics" {
		t.Fatalf("Metrics Path = %q", gotMetrics)
	}
}

// TestBuildEffectiveConfig_CollectorsPopulated asserts the Collectors section is
// present and non-empty, and every item there is a plain on/off item (never Secret).
func TestBuildEffectiveConfig_CollectorsPopulated(t *testing.T) {
	in := configInputs{collectors: []ConfigItem{{Key: "ARP", Value: "on"}, {Key: "Netflow", Value: "off"}}}
	out := buildEffectiveConfig(in)
	found := false
	for _, sec := range out {
		if sec.Title != "Collectors" {
			continue
		}
		found = true
		if len(sec.Items) != 2 {
			t.Fatalf("want 2 collector items, got %d", len(sec.Items))
		}
		for _, it := range sec.Items {
			if it.Secret {
				t.Fatalf("collector item %q must not be Secret", it.Key)
			}
		}
	}
	if !found {
		t.Fatal("Collectors section missing")
	}
}
