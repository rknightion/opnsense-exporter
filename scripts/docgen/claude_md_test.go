package main

import (
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/rknightion/opnsense2otel/v4/internal/collector"
)

// TestClaudeMDCollectorCount guards #117: CLAUDE.md's "N sub-collectors" figure must match the
// actual number of registered sub-collectors. It drifted to a stale 30 while the registry grew to
// 47; this test (plus the stat-pin rule for CLAUDE.md) fails if it drifts again.
func TestClaudeMDCollectorCount(t *testing.T) {
	repoRoot := findRepoRoot()
	raw, err := os.ReadFile(repoRoot + "/CLAUDE.md")
	if err != nil {
		t.Fatalf("reading CLAUDE.md: %v", err)
	}
	m := regexp.MustCompile(`(\d+) sub-collectors`).FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatal("CLAUDE.md no longer contains a \"N sub-collectors\" figure to pin")
	}
	got, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parsing count %q: %v", m[1], err)
	}
	want := len(collector.AllCollectors())
	if got != want {
		t.Errorf("CLAUDE.md says %d sub-collectors, but %d are registered (run `make docs`)", got, want)
	}
}
