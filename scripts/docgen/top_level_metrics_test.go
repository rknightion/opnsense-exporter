package main

import (
	"strings"
	"testing"
)

// TestVerifyCoversTopLevelCollector covers #119 acceptance #1: verifyMetricsAgainstRegistry must
// cross-check the top-level Collector.Describe() output (opnsense_up, exporter_*), not just
// collector.AllCollectors(). Dropping a top-level metric from the documented set must make the
// top-level Describe() pass flag it as missing.
func TestVerifyCoversTopLevelCollector(t *testing.T) {
	repoRoot := findRepoRoot()
	subsystems := parseSubsystemConstants(repoRoot + "/internal/collector/collector.go")
	astCollectors := parseAllCollectors(repoRoot+"/internal/collector", subsystems)
	topLevel := parseTopLevelMetrics(repoRoot + "/internal/collector/collector.go")

	if err := verifyMetricsAgainstRegistry(astCollectors, topLevel); err != nil {
		t.Fatalf("verification should pass against current source: %v", err)
	}

	var filtered []MetricInfo
	for _, m := range topLevel {
		if m.FullName != "opnsense_up" {
			filtered = append(filtered, m)
		}
	}
	if len(filtered) == len(topLevel) {
		t.Fatal("opnsense_up not present in parsed top-level metrics — test premise stale")
	}
	err := verifyMetricsAgainstRegistry(astCollectors, filtered)
	if err == nil || !strings.Contains(err.Error(), "opnsense_up") || !strings.Contains(err.Error(), "top-level Collector") {
		t.Fatalf("expected opnsense_up flagged as missing from the top-level Collector, got: %v", err)
	}
}
