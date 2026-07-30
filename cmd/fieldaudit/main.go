// Command fieldaudit reports struct fields in package opnsense that are
// unmarshalled from an OPNsense API response and then never read — the
// mechanical form of the recurring #544 mistake, where a rich per-row payload is
// decoded and its identifying dimension quietly dropped.
//
// The check is type-aware (go/types over the whole module) rather than textual:
// a textual scan both invents false positives on common field names and misses
// real ones, because a name can appear on an unrelated type.
//
// Usage:
//
//	go run ./cmd/fieldaudit          # report everything, exit 1 on unexempted findings
//	go run ./cmd/fieldaudit -all     # include already-exempted fields in the report
//
// The same analysis runs as a unit test (audit_test.go), so it rides `make test`
// and CI with no workflow change.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	showAll := flag.Bool("all", false, "also list fields that are already exempted")
	flag.Parse()

	root, err := FindModuleRoot(".")
	if err != nil {
		fmt.Fprintln(os.Stderr, "fieldaudit:", err)
		os.Exit(2)
	}
	findings, err := Audit(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fieldaudit:", err)
		os.Exit(2)
	}

	var unexempted []Finding
	for _, f := range findings {
		exempt, isExempt := Exemptions[f.Key]
		switch {
		case !isExempt:
			unexempted = append(unexempted, f)
		case *showAll:
			fmt.Printf("  exempt  %-62s json:%-28q %s\n", f.Key, f.JSONTag, f.Pos)
			fmt.Printf("          reason: %s\n", collapse(exempt))
		}
	}

	stale := staleExemptions(findings)
	for _, key := range stale {
		fmt.Printf("  STALE   %s — field is gone or is now read; delete the exemption\n", key)
	}

	for _, f := range unexempted {
		fmt.Printf("  DEAD    %-62s json:%-28q %s\n", f.Key, f.JSONTag, f.Pos)
	}

	fmt.Printf("\n%d json-tagged field(s) in package opnsense are decoded and never read: "+
		"%d exempted, %d unexempted, %d stale exemption(s).\n",
		len(findings), len(findings)-len(unexempted), len(unexempted), len(stale))

	if len(unexempted) > 0 || len(stale) > 0 {
		os.Exit(1)
	}
}

// staleExemptions returns ledger keys that no longer name a dead field.
func staleExemptions(findings []Finding) []string {
	live := map[string]bool{}
	for _, f := range findings {
		live[f.Key] = true
	}
	var stale []string
	for key := range Exemptions {
		if !live[key] {
			stale = append(stale, key)
		}
	}
	return stale
}

func collapse(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
