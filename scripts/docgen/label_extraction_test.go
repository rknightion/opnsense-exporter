package main

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// TestResolveAppendLabels covers #118 acceptance #4: docgen must resolve a labels argument built
// with an append(...) chain (base slice spread + literal), not just a plain composite literal.
func TestResolveAppendLabels(t *testing.T) {
	src := `package collector

func (c *x) Register() {
	srcLabels := []string{"source_name", "source_id", "source_instance"}
	c.plain = buildPrometheusDesc(c.subsystem, "plain", "h", srcLabels)
	c.win = buildPrometheusDesc(c.subsystem, "events_per_second", "h",
		append(append([]string{}, srcLabels...), "window"))
	c.none = buildPrometheusDesc(c.subsystem, "service_running", "h", nil)
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	metrics := findBuildPrometheusDescCalls(f, "syslog", fset)
	got := map[string]string{}
	for _, m := range metrics {
		got[m.Name] = strings.Join(m.Labels, ",")
	}
	if got["events_per_second"] != "source_name,source_id,source_instance,window" {
		t.Errorf("append-built labels resolved to %q, want the base slice + \"window\"", got["events_per_second"])
	}
	if got["plain"] != "source_name,source_id,source_instance" {
		t.Errorf("plain local-var labels resolved to %q", got["plain"])
	}
	if got["service_running"] != "" {
		t.Errorf("nil labels resolved to %q, want empty", got["service_running"])
	}
}

// TestVerifyDetectsLabelMismatch covers #118 acceptance #3: a metric whose documented label set
// differs from its runtime Desc must fail verifyMetricsAgainstRegistry.
func TestVerifyDetectsLabelMismatch(t *testing.T) {
	repoRoot := findRepoRoot()
	subsystems := parseSubsystemConstants(repoRoot + "/internal/collector/collector.go")
	astCollectors := parseAllCollectors(repoRoot+"/internal/collector", subsystems)

	// Corrupt one real metric's documented labels; verify must catch the divergence.
	patched := false
	for ci := range astCollectors {
		for mi := range astCollectors[ci].Metrics {
			if astCollectors[ci].Metrics[mi].FullName == "opnsense_syslog_events_per_second" {
				astCollectors[ci].Metrics[mi].Labels = []string{"bogus_label"}
				patched = true
			}
		}
	}
	if !patched {
		t.Fatal("did not find opnsense_syslog_events_per_second to corrupt")
	}
	topLevel := parseTopLevelMetrics(repoRoot + "/internal/collector/collector.go")
	err := verifyMetricsAgainstRegistry(astCollectors, topLevel)
	if err == nil || !strings.Contains(err.Error(), "label set differs") {
		t.Fatalf("expected a label-mismatch error, got: %v", err)
	}
}
