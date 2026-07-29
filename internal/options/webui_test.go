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

func TestPrettifyFieldName(t *testing.T) {
	cases := map[string]string{
		"ARP":               "ARP",
		"Cron":              "Cron",
		"Wireguard":         "Wireguard",
		"IPsec":             "IPsec",
		"IPsecLeaseDetails": "IPsec Lease Details",
		"FirewallNATCounts": "Firewall NAT Counts",
		"OpenVPNDetails":    "Open VPN Details",
		"TrafficShaper":     "Traffic Shaper",
		"UnboundQStats":     "Unbound QStats",
	}
	for in, want := range cases {
		if got := prettifyFieldName(in); got != want {
			t.Errorf("prettifyFieldName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestBuildEffectiveConfig_AnnotationsLogsFlowPresent covers #518: --config.check
// and the /config page previously printed nothing for annotations, log shipping
// or flow even when all three were fully configured. Assert the sections exist
// and carry the specific facts the issue calls out as security/operationally
// relevant (allowlist count, not just on/off; token/lookback/max-per-cycle).
func TestBuildEffectiveConfig_AnnotationsLogsFlowPresent(t *testing.T) {
	in := configInputs{
		host: "fw.example",

		annotationsEnabled:     true,
		annotationsURL:         "https://grafana.example",
		annotationsTokenSet:    true,
		annotationsLookback:    "24h0m0s",
		annotationsInterval:    "1m0s",
		annotationsMaxPerCycle: 20,

		logsEnabled: true,
		logsSink:    "otlp",

		syslogEnabled:        true,
		syslogListen:         "udp :5514, tcp :5514",
		syslogTLS:            false,
		syslogAllowlistCount: 3,
		syslogDebugCapture:   true,

		zenarmorEnabled:        true,
		zenarmorListen:         ":9200",
		zenarmorTLS:            true,
		zenarmorAllowlistCount: 0,
		zenarmorDebugCapture:   false,

		logsDebugCaptureDir: "/var/log/capture",

		flowEnabled:   true,
		flowCorrelate: true,
		flowLogMode:   "per_flow",

		netflowEnabled:        true,
		netflowListen:         ":2055",
		netflowAllowlistCount: 1,
		netflowDebugCapture:   "unidentified",
	}
	sections := buildEffectiveConfig(in)

	byTitle := map[string]ConfigSection{}
	for _, sec := range sections {
		byTitle[sec.Title] = sec
	}

	for _, want := range []string{"Annotations", "Log shipping", "Flow"} {
		if _, ok := byTitle[want]; !ok {
			t.Fatalf("missing section %q", want)
		}
	}

	items := func(title string) map[string]ConfigItem {
		m := map[string]ConfigItem{}
		for _, it := range byTitle[title].Items {
			m[it.Key] = it
		}
		return m
	}

	ann := items("Annotations")
	if ann["Enabled"].Value != "on" {
		t.Errorf("Annotations Enabled = %q, want on", ann["Enabled"].Value)
	}
	if ann["Grafana URL"].Value != "https://grafana.example" {
		t.Errorf("Grafana URL = %q", ann["Grafana URL"].Value)
	}
	if !ann["Token"].Secret || ann["Token"].Value != redacted {
		t.Errorf("Token = %+v, want redacted secret", ann["Token"])
	}
	if ann["Lookback"].Value != "24h0m0s" {
		t.Errorf("Lookback = %q", ann["Lookback"].Value)
	}
	if ann["Max Per Cycle"].Value != "20" {
		t.Errorf("Max Per Cycle = %q", ann["Max Per Cycle"].Value)
	}

	logs := items("Log shipping")
	if logs["Syslog Allowed Peers"].Value != "set (3 prefixes)" {
		t.Errorf("Syslog Allowed Peers = %q", logs["Syslog Allowed Peers"].Value)
	}
	if logs["Zenarmor Allowed Peers"].Value != "open (no allowlist)" {
		t.Errorf("Zenarmor Allowed Peers = %q", logs["Zenarmor Allowed Peers"].Value)
	}
	if logs["Syslog Debug Capture"].Value != "on" {
		t.Errorf("Syslog Debug Capture = %q", logs["Syslog Debug Capture"].Value)
	}
	if logs["Debug Capture Dir"].Value != "/var/log/capture" {
		t.Errorf("Debug Capture Dir = %q", logs["Debug Capture Dir"].Value)
	}
	if logs["Zenarmor TLS"].Value != "on" {
		t.Errorf("Zenarmor TLS = %q", logs["Zenarmor TLS"].Value)
	}

	flow := items("Flow")
	if flow["NetFlow Allowed Peers"].Value != "set (1 prefix)" {
		t.Errorf("NetFlow Allowed Peers = %q", flow["NetFlow Allowed Peers"].Value)
	}
	if flow["NetFlow Debug Capture"].Value != "unidentified" {
		t.Errorf("NetFlow Debug Capture = %q", flow["NetFlow Debug Capture"].Value)
	}
}

func TestCollectorConfigItems_HaveDisplay(t *testing.T) {
	items := collectorConfigItems()
	if len(items) == 0 {
		t.Fatal("no collector items")
	}
	for _, it := range items {
		if it.Key == "" || it.Display == "" {
			t.Fatalf("collector item missing Key/Display: %+v", it)
		}
	}
}
