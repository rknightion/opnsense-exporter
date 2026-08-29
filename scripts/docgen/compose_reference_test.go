package main

import (
	"bytes"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v2"
)

// TestComposeReferenceCoversEveryFlag is the coverage gate: a flag added to the
// exporter and missed here would ship silently absent from the one page meant
// to enumerate all of them.
func TestComposeReferenceCoversEveryFlag(t *testing.T) {
	flags := collectAllFlags()
	content := string(renderComposeReference(flags))
	for _, f := range flags {
		token := f.Envar
		if token == "" {
			token = "--" + f.Name
		}
		if !strings.Contains(content, token) {
			t.Errorf("flag %q: token %q not found in generated compose reference", f.Name, token)
		}
	}
}

// TestComposeReferenceDeterministic pins byte-identical output across runs:
// the page is generated content checked into docs, so a flaky rendering (map
// iteration, timestamps) would make `just docs-check` fail intermittently.
func TestComposeReferenceDeterministic(t *testing.T) {
	flags := collectAllFlags()
	a := renderComposeReference(flags)
	b := renderComposeReference(flags)
	if !bytes.Equal(a, b) {
		t.Fatal("renderComposeReference is not deterministic across runs")
	}
}

// TestComposeReferenceYAMLParses extracts the fenced yaml block and parses it
// with the vendored go.yaml.in/yaml/v2 (already vendored via
// go.opentelemetry.io's transitive dependency tree; no new module added).
// Every documented setting is a YAML comment, so a syntactically broken
// example would still parse - this test only proves the skeleton (services,
// image, environment, ports) is valid YAML, matching what `docker compose
// config` would need to at least parse.
func TestComposeReferenceYAMLParses(t *testing.T) {
	content := string(renderComposeReference(collectAllFlags()))
	block := extractYAMLBlock(t, content)

	var doc struct {
		Services map[string]struct {
			Image         string            `yaml:"image"`
			ContainerName string            `yaml:"container_name"`
			Restart       string            `yaml:"restart"`
			Environment   map[string]string `yaml:"environment"`
			Ports         []string          `yaml:"ports"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(block), &doc); err != nil {
		t.Fatalf("generated compose reference is not valid YAML: %v\n---\n%s", err, block)
	}
	svc, ok := doc.Services["opnsense2otel"]
	if !ok {
		t.Fatal("services.opnsense2otel missing")
	}
	if svc.Image != "ghcr.io/rknightion/opnsense2otel:latest" {
		t.Errorf("image = %q", svc.Image)
	}
	if svc.Restart != "always" {
		t.Errorf("restart = %q, want always", svc.Restart)
	}
	// The two Required flags must be live (uncommented) keys, everything else
	// commented, so environment should contain exactly the OPNsense address +
	// protocol placeholders and nothing more.
	if svc.Environment["OPN2OTEL_OPS_PROTOCOL"] != "https" {
		t.Errorf("OPN2OTEL_OPS_PROTOCOL = %q, want https", svc.Environment["OPN2OTEL_OPS_PROTOCOL"])
	}
	if svc.Environment["OPN2OTEL_OPS_API"] != "opnsense.example.com" {
		t.Errorf("OPN2OTEL_OPS_API = %q, want opnsense.example.com", svc.Environment["OPN2OTEL_OPS_API"])
	}
	if len(svc.Environment) != 2 {
		t.Errorf("environment has %d live keys, want exactly the 2 required flags: %v", len(svc.Environment), svc.Environment)
	}
	if len(svc.Ports) != 1 || svc.Ports[0] != "8080:8080" {
		t.Errorf("ports = %v, want exactly [\"8080:8080\"] live (receiver ports must stay commented)", svc.Ports)
	}
}

// TestComposeReferenceKnownDefaults spot-checks a few defaults render with
// their real value, catching a wiring mistake in yamlQuote/writeFlagEntry that
// the coverage test (presence only) would not.
func TestComposeReferenceKnownDefaults(t *testing.T) {
	content := string(renderComposeReference(collectAllFlags()))
	for _, tc := range []struct{ envar, want string }{
		{"OPN2OTEL_OTLP_PROTOCOL", `# OPN2OTEL_OTLP_PROTOCOL: "http/protobuf"`},
		{"OPN2OTEL_LOGS_SYSLOG_LISTEN_UDP", `# OPN2OTEL_LOGS_SYSLOG_LISTEN_UDP: ":5514"`},
		{"OPN2OTEL_FLOW_TOP_N", `# OPN2OTEL_FLOW_TOP_N: "10000"`},
	} {
		if !strings.Contains(content, tc.want) {
			t.Errorf("expected line %q not found for %s", tc.want, tc.envar)
		}
	}
}

// TestComposeReferenceFlagOnlyDocumented proves --config.check (no env var) is
// documented as a command:-only setting rather than silently dropped for
// lacking an environment: home.
func TestComposeReferenceFlagOnlyDocumented(t *testing.T) {
	content := string(renderComposeReference(collectAllFlags()))
	if !strings.Contains(content, "--config.check") {
		t.Error("--config.check not documented")
	}
	if !strings.Contains(content, "Flag-only settings") {
		t.Error("no flag-only settings banner explaining command: vs environment:")
	}
}

// TestComposeReferencePortsDocumented pins the three receiver ports and the
// syslog UDP/TCP pairing warning, which existing docs already flag as the
// commonest reason a receiver looks like it received nothing.
func TestComposeReferencePortsDocumented(t *testing.T) {
	content := string(renderComposeReference(collectAllFlags()))
	for _, want := range []string{
		`"5514:5514/udp"`,
		`"5514:5514/tcp"`,
		`"9200:9200"`,
		`"2055:2055/udp"`,
		"logs.syslog.enabled",
		"logs.zenarmor.enabled",
		"flow.netflow.enabled",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("expected %q in ports section", want)
		}
	}
	if !strings.Contains(content, "only one transport") {
		t.Error("syslog UDP/TCP publish-both warning missing")
	}
}

// extractYAMLBlock pulls the content between the first ```yaml fence and its
// closing ```.
func extractYAMLBlock(t *testing.T, content string) string {
	t.Helper()
	start := strings.Index(content, "```yaml")
	if start == -1 {
		t.Fatal("no ```yaml fence found")
	}
	start += len("```yaml")
	if nl := strings.IndexByte(content[start:], '\n'); nl >= 0 {
		start += nl + 1
	}
	end := strings.Index(content[start:], "```")
	if end == -1 {
		t.Fatal("no closing ``` found")
	}
	return content[start : start+end]
}

// TestWrapComposeCommentRespectsWidth is a narrow unit test on the wrapping
// helper itself, independent of any flag content.
func TestWrapComposeCommentRespectsWidth(t *testing.T) {
	long := strings.Repeat("word ", 40)
	lines := wrapComposeComment("      # ", long)
	if len(lines) < 2 {
		t.Fatalf("expected wrapping to produce multiple lines, got %d", len(lines))
	}
	for _, l := range lines {
		if len(l) > composeCommentWidth {
			t.Errorf("line exceeds %d cols (%d): %q", composeCommentWidth, len(l), l)
		}
		if !strings.HasPrefix(l, "      # ") {
			t.Errorf("line missing prefix: %q", l)
		}
	}
}
