package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/internal/collector"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

// descFQName pulls the fqName out of a *prometheus.Desc's String() form. Desc
// exposes no accessor, and its String() is the only stable way at the name —
// the same technique scripts/docgen/verify.go uses to cross-check the generated
// metrics reference against the live registry.
var descFQName = regexp.MustCompile(`fqName: "([^"]+)"`)

// registeredMetricFamilies is every metric family the exporter can emit,
// enumerated by registering every sub-collector and walking Describe(). This is
// the registry itself, not a generated document, so it cannot go stale.
func registeredMetricFamilies(t *testing.T) map[string]bool {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	names := map[string]bool{}
	for _, inst := range collector.AllCollectors() {
		inst.Register("opnsense", "apidrift-test", log)
		ch := make(chan *prometheus.Desc, 4096)
		inst.Describe(ch)
		close(ch)
		for d := range ch {
			if m := descFQName.FindStringSubmatch(d.String()); m != nil {
				names[m[1]] = true
			}
		}
	}
	if len(names) == 0 {
		t.Fatal("no metric families enumerated from the collector registry")
	}
	return names
}

// TestCoverageLedgerNamesRealMetrics is the ledger's own mirror of the #591
// finding — a perfect claim about absent data. A required coverage entry exists
// to say "this path backs THIS metric family, so the canary must exercise it",
// and TestCommittedCoverageLedgerIntegrity already rejects an entry that names
// no metric at all. What nothing checked until #599 is whether the name it does
// give is REAL: an `opnsense_`-prefixed typo, or a family renamed or deleted
// since the entry was written, satisfies the prefix check and then quietly
// protects nothing. Every metric-backing path in a run would still be reported
// as required coverage, naming a series no dashboard, alert or operator can
// ever find.
//
// This resolves the ledger against the collector registry rather than against
// the generated metrics reference, so it also fails when a metric is renamed in
// code without regenerating the docs.
//
// Scope, stated so it is not mistaken for more than it is: this validates the
// human's claim, it does NOT derive it. Nothing here can tell that a path which
// backs a metric was never ledgered at all — see the automation verdict in
// opnsense/schema_coverage.go's package comment for why that direction is not
// mechanically decidable in this codebase.
func TestCoverageLedgerNamesRealMetrics(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	path := filepath.Join(root, coverageLedgerPath)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat ledger: %v", err)
	}
	ledger, err := opnsense.LoadCoverageLedger(path)
	if err != nil {
		t.Fatalf("LoadCoverageLedger: %v", err)
	}
	if len(ledger) == 0 {
		t.Fatal("the committed coverage ledger is empty")
	}

	registered := registeredMetricFamilies(t)

	var endpoints []string
	for endpoint := range ledger {
		endpoints = append(endpoints, endpoint)
	}
	sort.Strings(endpoints)

	for _, endpoint := range endpoints {
		for _, e := range ledger[endpoint].Required {
			for _, m := range e.Metrics {
				if !registered[m] {
					t.Errorf("%s required %q: names metric family %q, which no collector registers "+
						"(renamed, deleted, or a typo — the entry protects nothing)",
						endpoint, e.Path, m)
				}
			}
		}
	}
}
