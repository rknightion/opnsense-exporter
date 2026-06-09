package main

import (
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
