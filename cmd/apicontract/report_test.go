package main

import (
	"strings"
	"testing"
)

func TestRenderMarkdownErrorsAndWarnings(t *testing.T) {
	reps := []Report{{
		Ref: "master",
		Errors: []Finding{{Endpoint: "ghost", OurPath: "api/core/service/gone", OurMethod: "GET",
			Kind: KindMissing, Detail: "no matching controller/command in OPNsense source"}},
		Warnings: []Finding{{Endpoint: "firewallRules", OurPath: "api/firewall/filter/search_rule",
			OurMethod: "GET", Kind: KindVerb, Detail: "exporter uses GET; source advertises [POST]"}},
	}}
	md := RenderMarkdown(reps)
	if !strings.Contains(md, "master") {
		t.Error("expected ref heading")
	}
	if !strings.Contains(md, "ghost") || !strings.Contains(md, "api/core/service/gone") {
		t.Error("expected missing-endpoint row")
	}
	if !strings.Contains(md, "firewallRules") {
		t.Error("expected verb-warning row")
	}
}

func TestRenderMarkdownCleanWhenNoDrift(t *testing.T) {
	md := RenderMarkdown([]Report{{Ref: "master"}})
	if !strings.Contains(strings.ToLower(md), "no drift") {
		t.Errorf("expected clean message, got %q", md)
	}
}

// TestHasWarningsIndependentOfErrors covers #93 acceptance #1: verb-drift warnings must
// surface a distinct signal that is true even when there are no errors (so HasErrors,
// which gates the exit code, stays false while HasWarnings is true).
func TestHasWarningsIndependentOfErrors(t *testing.T) {
	verbOnly := []Report{{Ref: "master", Warnings: []Finding{{
		Endpoint: "firewallRules", OurPath: "api/firewall/filter/search_rule",
		OurMethod: "GET", Kind: KindVerb, Detail: "exporter uses GET; source advertises [POST]"}}}}
	if HasErrors(verbOnly) {
		t.Error("verb-drift-only report must not be an error (exit code stays 0)")
	}
	if !HasWarnings(verbOnly) {
		t.Error("verb-drift-only report must report HasWarnings=true")
	}

	clean := []Report{{Ref: "master"}}
	if HasWarnings(clean) {
		t.Error("clean report must report HasWarnings=false")
	}
}

// TestGitHubOutputsWarningsOnly covers #93 acceptance #2/#5: a warnings-only diff must
// emit drift=false + warnings=true, so the workflow files/updates the issue (drift OR
// warnings) but the hard-fail/close-when-clean steps (gated on drift/warnings) behave.
func TestGitHubOutputsWarningsOnly(t *testing.T) {
	verbOnly := []Report{{Ref: "master", Warnings: []Finding{{Endpoint: "x", Kind: KindVerb}}}}
	if got := GitHubOutputs(verbOnly); got != "drift=false\nwarnings=true\n" {
		t.Errorf("warnings-only outputs = %q", got)
	}
	missing := []Report{{Ref: "master", Errors: []Finding{{Endpoint: "y", Kind: KindMissing}}}}
	if got := GitHubOutputs(missing); got != "drift=true\nwarnings=false\n" {
		t.Errorf("missing outputs = %q", got)
	}
	clean := []Report{{Ref: "master"}}
	if got := GitHubOutputs(clean); got != "drift=false\nwarnings=false\n" {
		t.Errorf("clean outputs = %q", got)
	}
}
