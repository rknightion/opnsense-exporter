package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractDocTokens(t *testing.T) {
	text := "Use `--opnsense.address` and set OPN2OTEL_OPS_API_KEY or OPS_API_KEY_FILE. " +
		"The removed --runtime.gomaxprocs flag. Sentence ends with --otlp.enabled."
	flags, envs := extractDocTokens(text)
	wantFlags := map[string]bool{"opnsense.address": true, "runtime.gomaxprocs": true, "otlp.enabled": true}
	for f := range wantFlags {
		if !flags[f] {
			t.Errorf("flag token %q not extracted (got %v)", f, flags)
		}
	}
	if flags["otlp.enabled."] {
		t.Error("trailing punctuation not trimmed from flag token")
	}
	for _, e := range []string{"OPN2OTEL_OPS_API_KEY", "OPS_API_KEY_FILE"} {
		if !envs[e] {
			t.Errorf("env token %q not extracted", e)
		}
	}
}

func TestDoclintFlagsUnknownTokens(t *testing.T) {
	known := knownTokens(collectAllFlags())
	problems := lintText("doc.md", "set --opnsense.adress and OPN2OTEL_TYPO_VAR", known, map[string]bool{})
	if len(problems) != 2 {
		t.Fatalf("expected 2 problems, got %d: %v", len(problems), problems)
	}
	problems = lintText("doc.md", "set --opnsense.address and OPN2OTEL_OPS_API_KEY and OPS_API_SECRET_FILE", known, map[string]bool{})
	if len(problems) != 0 {
		t.Fatalf("expected no problems, got %v", problems)
	}
	// allowlisted historical flag
	problems = lintText("doc.md", "the removed --runtime.gomaxprocs flag", known, map[string]bool{"runtime.gomaxprocs": true})
	if len(problems) != 0 {
		t.Fatalf("allowlist not honoured: %v", problems)
	}
}

// TestFlowDocDefaultsMatchFlagModel keeps the hand-written flow overview tied
// to the kingpin model. docs/configuration.md is generated, but docs/flow.md is
// intentionally a short operator-facing guide and therefore needs this small
// drift check for the defaults it repeats.
func TestFlowDocDefaultsMatchFlagModel(t *testing.T) {
	root := findRepoRoot()
	raw, err := os.ReadFile(filepath.Join(root, "docs", "flow.md"))
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		columns := strings.Split(line, "|")
		if len(columns) < 4 {
			continue
		}
		flag := strings.Trim(strings.TrimSpace(columns[1]), "`")
		switch flag {
		case "--flow.top-n", "--flow.max-keys":
			got[flag] = strings.Trim(strings.TrimSpace(columns[2]), "`")
		}
	}

	want := map[string]string{}
	for _, flag := range collectAllFlags() {
		switch flag.Name {
		case "flow.top-n", "flow.max-keys":
			want["--"+flag.Name] = flag.Default
		}
	}
	if len(want) != 2 {
		t.Fatalf("flag model yielded %d flow defaults, want 2: %v", len(want), want)
	}
	for flag, expected := range want {
		if actual, ok := got[flag]; !ok {
			t.Errorf("docs/flow.md is missing %s", flag)
		} else if actual != expected {
			t.Errorf("docs/flow.md %s default = %q, want %q", flag, actual, expected)
		}
	}
}

// TestFlagShapeCatchesNonWhitelistedPrefix guards the #151 fix: extraction matches any
// dotted long flag by shape, so a wrong namespace (e.g. --collector.disable-arp-table, a
// typo of --exporter.disable-arp-table, or --metrics.path for --web.telemetry-path) is
// caught rather than silently ignored because its prefix wasn't in a hardcoded list.
func TestFlagShapeCatchesNonWhitelistedPrefix(t *testing.T) {
	flags, _ := extractDocTokens("run with --collector.disable-arp-table and expose --metrics.path")
	for _, f := range []string{"collector.disable-arp-table", "metrics.path"} {
		if !flags[f] {
			t.Errorf("shape-based extraction missed non-whitelisted-prefix flag %q (got %v)", f, flags)
		}
	}

	known := knownTokens(collectAllFlags())
	problems := lintText("README.md", "run with --collector.disable-arp-table", known, map[string]bool{})
	if len(problems) != 1 || !strings.Contains(problems[0], "collector.disable-arp-table") {
		t.Fatalf("expected the bogus --collector.disable-arp-table flag to be flagged, got %v", problems)
	}
}

// TestEnvBrandPrefixTypoDetected guards the #151 env fix: a typo in the OPNSENSE brand
// prefix (OPNSENSE_EXPORT_… missing the ER) is caught, while genuinely-third-party envs
// (OTEL_*, SSL_CERT_FILE) and justfile vars (OPS_*, GO_LICENSES_VERSION) are NOT — they
// legitimately do not appear in the kingpin model.
func TestEnvBrandPrefixTypoDetected(t *testing.T) {
	_, envs := extractDocTokens("set OPNSENSE_EXPORT_OPS_API_KEY plus OTEL_SERVICE_NAME and GO_LICENSES_VERSION and SSL_CERT_FILE")
	if !envs["OPNSENSE_EXPORT_OPS_API_KEY"] {
		t.Errorf("brand-prefix-typo env not extracted (got %v)", envs)
	}
	for _, notMine := range []string{"OTEL_SERVICE_NAME", "GO_LICENSES_VERSION", "SSL_CERT_FILE"} {
		if envs[notMine] {
			t.Errorf("third-party/justfile env %q must not be matched (got %v)", notMine, envs)
		}
	}

	known := knownTokens(collectAllFlags())
	problems := lintText("doc.md", "set OPNSENSE_EXPORT_OPS_API_KEY", known, map[string]bool{})
	if len(problems) != 1 || !strings.Contains(problems[0], "OPNSENSE_EXPORT_OPS_API_KEY") {
		t.Fatalf("expected the typo'd brand env to be flagged, got %v", problems)
	}
}

// TestLintTargetsIncludeGrafanaTabs guards that grafana/tabs/*.py panel descriptions are
// linted (#151), so renaming a flag referenced in a tab module breaks docs-check.
func TestLintTargetsIncludeGrafanaTabs(t *testing.T) {
	targets := lintTargets(findRepoRoot())
	var tabCount int
	for _, tgt := range targets {
		if strings.HasPrefix(filepath.ToSlash(tgt), "grafana/tabs/") && strings.HasSuffix(tgt, ".py") {
			tabCount++
		}
	}
	if tabCount == 0 {
		t.Fatalf("lintTargets did not include any grafana/tabs/*.py file: %v", targets)
	}

	// A bogus flag inside tab-module content must be reported.
	known := knownTokens(collectAllFlags())
	problems := lintText("grafana/tabs/example.py", `panel(description="see --exporter.enable-bogus-details")`, known, map[string]bool{})
	if len(problems) != 1 || !strings.Contains(problems[0], "exporter.enable-bogus-details") {
		t.Fatalf("expected a bogus flag in a tab file to be flagged, got %v", problems)
	}
}

// TestLintTargetsIncludeCharts guards that the Helm chart is linted like any other
// doc: a renamed flag can rot charts/opnsense2otel/templates/_helpers.tpl (which
// builds the exporter's args/env list from flag and env names) or README.md
// undetected otherwise.
func TestLintTargetsIncludeCharts(t *testing.T) {
	targets := lintTargets(findRepoRoot())
	want := map[string]bool{
		"charts/opnsense2otel/templates/_helpers.tpl": false,
		"charts/opnsense2otel/README.md":              false,
		"charts/opnsense2otel/tests/test-chart.sh":    false,
	}
	for _, tgt := range targets {
		if _, ok := want[filepath.ToSlash(tgt)]; ok {
			want[filepath.ToSlash(tgt)] = true
		}
	}
	for path, found := range want {
		if !found {
			t.Errorf("lintTargets did not include %s: %v", path, targets)
		}
	}
}

// TestDoclintCatchesBogusFlagInChart is the point of the charts/ extension: a bogus
// flag inside chart content (a Helm template, in this case) must be reported exactly
// like one inside prose.
func TestDoclintCatchesBogusFlagInChart(t *testing.T) {
	known := knownTokens(collectAllFlags())
	problems := lintText(
		"charts/opnsense2otel/templates/_helpers.tpl",
		`- "--exporter.enable-bogus-details"`,
		known, map[string]bool{},
	)
	if len(problems) != 1 || !strings.Contains(problems[0], "exporter.enable-bogus-details") {
		t.Fatalf("expected a bogus flag in a chart template to be flagged, got %v", problems)
	}
}

// TestRunDoclintChartHasNoFalsePositives runs the real doclint pass over the real
// chart and asserts no charts/ file produces a problem. This is the regression test
// for the _helpers.tpl hasPrefix guards (`hasPrefix "--logs.syslog." $arg` etc): those
// extract to a bare namespace stem ("logs.syslog") rather than a real flag name, and
// must be allowlisted in doclint_allow.txt rather than flagged as unknown.
func TestRunDoclintChartHasNoFalsePositives(t *testing.T) {
	repoRoot := findRepoRoot()
	problems := runDoclint(repoRoot, collectAllFlags())
	for _, p := range problems {
		if strings.HasPrefix(p, "charts/") {
			t.Errorf("unexpected doclint problem in chart: %s", p)
		}
	}
}
