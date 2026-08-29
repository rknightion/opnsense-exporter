package main

import (
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/rknightion/opnsense2otel/v4/internal/collector"
)

// TestAgentsMDCollectorCount guards #117: the agent instructions' "N sub-collectors" figure must
// match the actual number of registered sub-collectors. It drifted to a stale 30 while the registry
// grew to 47; this test (plus the stat-pin rule) fails if it drifts again. The instructions moved
// CLAUDE.md -> AGENTS.md on 2026-08-14 when tracking moved in-repo; CLAUDE.md is now a one-line
// import of AGENTS.md, so the figure only exists in AGENTS.md.
func TestAgentsMDCollectorCount(t *testing.T) {
	repoRoot := findRepoRoot()
	raw, err := os.ReadFile(repoRoot + "/AGENTS.md")
	if err != nil {
		t.Fatalf("reading AGENTS.md: %v", err)
	}
	m := regexp.MustCompile(`(\d+) sub-collectors`).FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatal("AGENTS.md no longer contains a \"N sub-collectors\" figure to pin")
	}
	got, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parsing count %q: %v", m[1], err)
	}
	want := len(collector.AllCollectors())
	if got != want {
		t.Errorf("AGENTS.md says %d sub-collectors, but %d are registered (run `just docs`)", got, want)
	}
}
