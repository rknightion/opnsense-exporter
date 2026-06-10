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
