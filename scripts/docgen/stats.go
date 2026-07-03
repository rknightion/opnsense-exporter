package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

type docStats struct {
	Metrics     int
	Collectors  int
	DashMetrics int
	DashTabs    int
}

// loadDashboardStats reads grafana/dashboard-stats.json, written by
// `make dashboard`, so dashboard counts in prose track the dashboard build.
func loadDashboardStats(repoRoot string) (metrics, tabs int) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "grafana", "dashboard-stats.json"))
	if err != nil {
		fatal("reading grafana/dashboard-stats.json (run 'make dashboard' first): %v", err)
	}
	var s struct {
		Metrics int `json:"metrics"`
		Panels  int `json:"panels"`
		Tabs    int `json:"tabs"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		fatal("parsing grafana/dashboard-stats.json: %v", err)
	}
	if s.Metrics == 0 || s.Tabs == 0 {
		fatal("grafana/dashboard-stats.json has zero metrics/tabs; rerun 'make dashboard'")
	}
	return s.Metrics, s.Tabs
}

// statRules pins every numeric metric/collector/dashboard count that appears
// in prose, TOML or YAML. A rule that stops matching is a hard error.
func statRules(s docStats) []statRule {
	across := regexp.MustCompile(`\d+\+? (Prometheus )?metrics across \d+ (concurrent )?collectors`)
	acrossRepl := fmt.Sprintf("%d ${1}metrics across %d ${2}collectors", s.Metrics, s.Collectors)
	allProm := regexp.MustCompile(`all \d+\+? Prometheus metrics`)
	allPromRepl := fmt.Sprintf("all %d Prometheus metrics", s.Metrics)
	subCollectors := regexp.MustCompile(`\d+ sub-collectors`)
	subCollectorsRepl := fmt.Sprintf("%d sub-collectors", s.Collectors)
	allCollectors := regexp.MustCompile(`all \d+ collectors`)
	allCollectorsRepl := fmt.Sprintf("all %d collectors", s.Collectors)
	approxCollectors := regexp.MustCompile(`~\d+ collectors`)
	approxCollectorsRepl := fmt.Sprintf("~%d collectors", s.Collectors)
	dash := regexp.MustCompile(`all \d+ metrics across \d+ tabs`)
	dashRepl := fmt.Sprintf("all %d metrics across %d tabs", s.DashMetrics, s.DashTabs)

	return []statRule{
		{File: "zensical.toml", Pattern: across, Replace: acrossRepl, MinHits: 1},
		{File: "docs/.meta.yml", Pattern: across, Replace: acrossRepl, MinHits: 1},
		{File: "docs/collectors/.meta.yml", Pattern: regexp.MustCompile(`all \d+ OPNsense Exporter collectors`),
			Replace: fmt.Sprintf("all %d OPNsense Exporter collectors", s.Collectors), MinHits: 1},
		{File: "docs/index.md", Pattern: across, Replace: acrossRepl, MinHits: 2},
		{File: "docs/index.md", Pattern: allProm, Replace: allPromRepl, MinHits: 1},
		{File: "docs/index.md", Pattern: regexp.MustCompile(`\*\*\d+ collectors\*\*`),
			Replace: fmt.Sprintf("**%d collectors**", s.Collectors), MinHits: 1},
		{File: "docs/index.md", Pattern: subCollectors, Replace: subCollectorsRepl, MinHits: 1},
		{File: "docs/metrics/index.md", Pattern: allProm, Replace: allPromRepl, MinHits: 1},
		{File: "docs/metrics/index.md", Pattern: across, Replace: acrossRepl, MinHits: 1},
		{File: "docs/metrics/index.md", Pattern: regexp.MustCompile(`\*\*\d+\+? metrics\*\* across \d+ collectors`),
			Replace: fmt.Sprintf("**%d metrics** across %d collectors", s.Metrics, s.Collectors), MinHits: 1},
		{File: "docs/collectors/index.md", Pattern: regexp.MustCompile(`all \d+ OPNsense Exporter collectors`),
			Replace: fmt.Sprintf("all %d OPNsense Exporter collectors", s.Collectors), MinHits: 1},
		{File: "docs/collectors/index.md", Pattern: subCollectors, Replace: subCollectorsRepl, MinHits: 1},
		{File: "docs/architecture.md", Pattern: subCollectors, Replace: subCollectorsRepl, MinHits: 1},
		// CLAUDE.md + these three docs pages sat outside the pin allowlist and drifted to a stale
		// "30 collectors" while the real count grew to 47 (#117). Pin them so make docs-check fails
		// on future drift.
		{File: "CLAUDE.md", Pattern: subCollectors, Replace: subCollectorsRepl, MinHits: 1},
		{File: "docs/404.md", Pattern: allCollectors, Replace: allCollectorsRepl, MinHits: 1},
		{File: "docs/getting-started.md", Pattern: allCollectors, Replace: allCollectorsRepl, MinHits: 1},
		{File: "docs/troubleshooting.md", Pattern: approxCollectors, Replace: approxCollectorsRepl, MinHits: 1},
		{File: "README.md", Pattern: across, Replace: acrossRepl, MinHits: 1},
		{File: "README.md", Pattern: dash, Replace: dashRepl, MinHits: 1},
		{File: "docs/integration-dashboards.md", Pattern: dash, Replace: dashRepl, MinHits: 1},
	}
}

// applyStatRules runs every rule against its file and hands the result to out
// (which writes it, or records drift in check mode).
func applyStatRules(out *output, rules []statRule) {
	byFile := map[string][]statRule{}
	var order []string
	for _, r := range rules {
		if _, seen := byFile[r.File]; !seen {
			order = append(order, r.File)
		}
		byFile[r.File] = append(byFile[r.File], r)
	}
	for _, file := range order {
		path := filepath.Join(out.repoRoot, file)
		raw, err := os.ReadFile(path)
		if err != nil {
			fatal("reading %s: %v", path, err)
		}
		content := string(raw)
		for _, r := range byFile[file] {
			content, err = applyStatRule(content, r)
			if err != nil {
				fatal("%v", err)
			}
		}
		out.write(path, []byte(content))
	}
	fmt.Fprintf(os.Stderr, "docgen: applied %d stat rules across %d files\n", len(rules), len(byFile))
}
