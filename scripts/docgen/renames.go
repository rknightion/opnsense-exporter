package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rknightion/opnsense2otel/v5/internal/metriclint"
)

// renderMetricRenames renders the operator-facing v5.0 metric migration table
// from the same ledger that rejects retired names in metriclint.
func renderMetricRenames() string {
	renames := metriclint.RenamedMetrics()
	if len(renames) == 0 {
		fatal("metric rename ledger is empty")
	}

	var b strings.Builder
	b.WriteString("| Source file | Old metric | New metric | Release |\n")
	b.WriteString("|-------------|------------|------------|---------|\n")
	for _, rename := range renames {
		if rename.File == "" || rename.OldFullName == "" || rename.NewFullName == "" || rename.Release == "" {
			fatal("metric rename ledger contains an incomplete row: %#v", rename)
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` |\n",
			rename.File, rename.OldFullName, rename.NewFullName, rename.Release)
	}
	return b.String()
}

// injectUpgradingDoc fills the migration table in docs/upgrading.md from the
// metric-lint ledger. The surrounding migration guidance remains authored prose.
func injectUpgradingDoc(out *output) {
	path := filepath.Join(out.repoRoot, "docs", "upgrading.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		fatal("reading %s: %v", path, err)
	}
	doc, err := injectRegion(string(raw), "metric-renames", renderMetricRenames())
	if err != nil {
		fatal("upgrading.md: %v", err)
	}
	fmt.Fprintf(os.Stderr, "docgen: metric rename table: %d rows\n", len(metriclint.RenamedMetrics()))
	out.write(path, []byte(doc))
}
