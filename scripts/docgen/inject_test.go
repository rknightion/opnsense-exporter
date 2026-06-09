package main

import (
	"regexp"
	"strings"
	"testing"
)

func TestInjectRegion(t *testing.T) {
	doc := "intro\n<!-- docgen:begin:x -->\nOLD\n<!-- docgen:end:x -->\noutro\n"
	got, err := injectRegion(doc, "x", "NEW TABLE")
	if err != nil {
		t.Fatal(err)
	}
	want := "intro\n<!-- docgen:begin:x -->\nNEW TABLE\n<!-- docgen:end:x -->\noutro\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestInjectRegionMissingMarker(t *testing.T) {
	if _, err := injectRegion("no markers here", "x", "c"); err == nil {
		t.Error("expected error for missing markers")
	}
	if _, err := injectRegion("<!-- docgen:end:x -->\n<!-- docgen:begin:x -->", "x", "c"); err == nil {
		t.Error("expected error for end-before-begin")
	}
}

func TestApplyStatRule(t *testing.T) {
	rule := statRule{
		Pattern: regexp.MustCompile(`\d+\+? (Prometheus )?metrics across \d+ (concurrent )?collectors`),
		Replace: "305 ${1}metrics across 30 ${2}collectors",
		MinHits: 2,
	}
	in := "has 320+ metrics across 26 collectors and 300+ Prometheus metrics across 30 concurrent collectors"
	out, err := applyStatRule(in, rule)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "305 metrics across 30 collectors") ||
		!strings.Contains(out, "305 Prometheus metrics across 30 concurrent collectors") {
		t.Errorf("unexpected output: %s", out)
	}
	if _, err := applyStatRule("no counts here", rule); err == nil {
		t.Error("expected MinHits violation error")
	}
}
