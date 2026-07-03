package main

import "testing"

func TestDescFQName(t *testing.T) {
	in := `Desc{fqName: "opnsense_arp_table_entries", help: "x", constLabels: {}, variableLabels: {ip,mac}}`
	if got := descFQName(in); got != "opnsense_arp_table_entries" {
		t.Errorf("got %q", got)
	}
	if got := descFQName("garbage"); got != "" {
		t.Errorf("expected empty for garbage, got %q", got)
	}
}

func TestVerifyAgainstRegistryPasses(t *testing.T) {
	repoRoot := findRepoRoot()
	subsystems := parseSubsystemConstants(repoRoot + "/internal/collector/collector.go")
	astCollectors := parseAllCollectors(repoRoot+"/internal/collector", subsystems)
	topLevel := parseTopLevelMetrics(repoRoot + "/internal/collector/collector.go")
	if err := verifyMetricsAgainstRegistry(astCollectors, topLevel); err != nil {
		t.Fatalf("registry verification failed against current source: %v", err)
	}
}
