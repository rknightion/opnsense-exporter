package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractDocTokens(t *testing.T) {
	text := "Use `--opnsense.address` and set OPNSENSE_EXPORTER_OPS_API_KEY or OPS_API_KEY_FILE. " +
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
	for _, e := range []string{"OPNSENSE_EXPORTER_OPS_API_KEY", "OPS_API_KEY_FILE"} {
		if !envs[e] {
			t.Errorf("env token %q not extracted", e)
		}
	}
}

func TestDoclintFlagsUnknownTokens(t *testing.T) {
	known := knownTokens(collectAllFlags())
	problems := lintText("doc.md", "set --opnsense.adress and OPNSENSE_EXPORTER_TYPO_VAR", known, map[string]bool{})
	if len(problems) != 2 {
		t.Fatalf("expected 2 problems, got %d: %v", len(problems), problems)
	}
	problems = lintText("doc.md", "set --opnsense.address and OPNSENSE_EXPORTER_OPS_API_KEY and OPS_API_SECRET_FILE", known, map[string]bool{})
	if len(problems) != 0 {
		t.Fatalf("expected no problems, got %v", problems)
	}
	// allowlisted historical flag
	problems = lintText("doc.md", "the removed --runtime.gomaxprocs flag", known, map[string]bool{"runtime.gomaxprocs": true})
	if len(problems) != 0 {
		t.Fatalf("allowlist not honoured: %v", problems)
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
// (OTEL_*, SSL_CERT_FILE) and Makefile vars (OPS_*, GO_LICENSES_VERSION) are NOT — they
// legitimately do not appear in the kingpin model.
func TestEnvBrandPrefixTypoDetected(t *testing.T) {
	_, envs := extractDocTokens("set OPNSENSE_EXPORT_OPS_API_KEY plus OTEL_SERVICE_NAME and GO_LICENSES_VERSION and SSL_CERT_FILE")
	if !envs["OPNSENSE_EXPORT_OPS_API_KEY"] {
		t.Errorf("brand-prefix-typo env not extracted (got %v)", envs)
	}
	for _, notMine := range []string{"OTEL_SERVICE_NAME", "GO_LICENSES_VERSION", "SSL_CERT_FILE"} {
		if envs[notMine] {
			t.Errorf("third-party/Makefile env %q must not be matched (got %v)", notMine, envs)
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
