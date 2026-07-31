package main

import (
	"fmt"
	"os"

	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// coverageLedgerPath is the committed live-coverage ledger (#377), resolved
// from the repo root exactly like the --exemptions default in main.go — the
// live-canary workflow runs `go run ./cmd/apidrift` from the checkout root.
// Overridden in tests.
var coverageLedgerPath = "opnsense/testdata/schemas/coverage.json"

// canaryProfile is the probe target this run is reporting on, set from --profile
// in main alongside generation. It selects the coverage ledger's per-profile
// overrides (#611); empty means the base ledger, which is what a local run with
// no target named gets. Overridden in tests.
//
// A package var rather than a parameter threaded through aggregate and
// renderReport, matching how generation and coverageLedgerPath already work in
// this command — main validates it against opnsense.KnownProbeProfiles() before
// anything reads it, so an unknown value cannot reach here.
var canaryProfile string

// loadCoverageIndex compiles the committed coverage ledger for canaryProfile. A
// missing file is an empty ledger (every unverified path stays informational,
// i.e. the behaviour that predates #377); a malformed one is reported on stderr
// and likewise degrades to empty, because a ledger typo must not take the whole
// drift canary down.
func loadCoverageIndex() opnsense.CoverageIndex {
	ledger, err := opnsense.LoadCoverageLedger(coverageLedgerPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apidrift: coverage ledger %s unusable, treating every unverified path as informational: %v\n", coverageLedgerPath, err)
		return opnsense.CoverageLedger{}.Index(canaryProfile)
	}
	return ledger.Index(canaryProfile)
}

// coverageFinding is one endpoint/path pair the run could not verify, with the
// ledger entry that classifies it. Structure only: the path is the validator's
// normalized schema path, so no dynamic-map identity or payload value is here.
type coverageFinding struct {
	Endpoint string
	Path     string
	Entry    opnsense.CoveragePath
}

// coverageReview splits every unverified path in the run into the three
// severity buckets, and separately lists the standing blind spots the ledger
// declares. Duplicate endpoint/path pairs collapse to one finding.
type coverageReview struct {
	// RequiredUnresolved backs an emitted metric and was NOT observed —
	// warning-level, the one actionable bucket.
	RequiredUnresolved []coverageFinding
	// StateOptional is ledgered box/hardware state — informational.
	StateOptional []coverageFinding
	// Unledgered is everything else the run could not verify — informational,
	// but still named rather than counted.
	Unledgered []coverageFinding
	// Opaque lists every required entry the schema models as KindAny, straight
	// from the ledger: no live run can ever clear these, so they are reported
	// unconditionally as named blind spots instead of warning forever.
	Opaque []coverageFinding
	// Endpoints counts endpoints with at least one unverified path (the
	// headline number the report has always printed).
	Endpoints int
}

// reviewCoverage classifies a run's unverified paths against the ledger.
func reviewCoverage(results []probeResult, ix opnsense.CoverageIndex) coverageReview {
	var rev coverageReview
	for _, r := range results {
		if len(r.Res.Unverified) == 0 {
			continue
		}
		rev.Endpoints++
		seen := make(map[string]bool, len(r.Res.Unverified))
		for _, p := range r.Res.Unverified {
			if seen[p] {
				continue
			}
			seen[p] = true
			f := coverageFinding{Endpoint: r.Endpoint, Path: p}
			class, entry, ok := ix.Classify(r.Endpoint, p)
			f.Entry = entry
			switch {
			case !ok:
				rev.Unledgered = append(rev.Unledgered, f)
			case class == opnsense.CoverageStateOptional:
				rev.StateOptional = append(rev.StateOptional, f)
			case entry.Opaque:
				// Listed from the ledger below, not from the run.
			default:
				rev.RequiredUnresolved = append(rev.RequiredUnresolved, f)
			}
		}
	}
	rev.Opaque = opaqueRequired(ix)
	return rev
}

// opaqueRequired lists every opaque required entry in the ledger, so the
// section is deterministic and independent of what the box happened to serve.
func opaqueRequired(ix opnsense.CoverageIndex) []coverageFinding {
	var out []coverageFinding
	for _, e := range ix.Entries() {
		if e.Class == opnsense.CoverageRequired && e.Opaque {
			out = append(out, coverageFinding{Endpoint: e.Endpoint, Path: e.Path, Entry: e.CoveragePath})
		}
	}
	return out
}
