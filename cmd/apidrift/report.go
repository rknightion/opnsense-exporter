package main

import (
	"fmt"
	"strings"

	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// pluginGatedSet returns the plugin-gated endpoint names as a lookup. A
// plugin-gated endpoint answering 404 means the plugin is not installed on the
// box — expected, exactly as the exporter itself treats it (feature absent),
// never drift. A genuine upstream route removal is caught by the source-diff
// (api-contract) canary instead, so masking it here is safe.
func pluginGatedSet() map[string]bool {
	gated := opnsense.PluginGatedEndpoints()
	m := make(map[string]bool, len(gated))
	for _, e := range gated {
		m[string(e)] = true
	}
	return m
}

// aggregate derives the two severity signals the workflow consumes: drift
// (breaking — a type conflict the exporter would decode wrongly) and warnings
// (missing paths, unexpected keys, unexpected nested keys, an unresolved
// required coverage path, a vanished CORE endpoint, probe problems). A
// plugin-gated endpoint answering 404 is expected (plugin not installed) and is
// NOT a warning — otherwise a box that simply doesn't run every optional
// plugin would keep the drift issue open forever.
//
// Unverified paths are the same story one level down: only a path the coverage
// ledger marks required-and-verifiable warns (#377). State-optional, unledgered
// and structurally-opaque paths stay informational, because a warning no live
// run could ever clear is permanent noise, not a signal.
func aggregate(results []probeResult) (drift, warnings bool) {
	gated := pluginGatedSet()
	if len(reviewCoverage(results, loadCoverageIndex()).RequiredUnresolved) > 0 {
		warnings = true
	}
	for _, r := range results {
		if len(r.Res.Mismatches) > 0 {
			drift = true
		}
		unexpectedAbsent := r.Absent && !gated[r.Endpoint]
		// UnknownPaths became a warning again in #457, which triaged the first
		// live baseline (#376, 2026-07-25: 1003 unmodelled nested paths across
		// 62 endpoints) into opnsense/testdata/schemas/exemptions.json's
		// knownExtraPaths. An UNEXEMPTED nested extra is exactly as actionable
		// as an unexpected top-level key — the caller either exempts it (with a
		// reason and prune trigger) or files it as a modeling opportunity, the
		// same as every other warning class here.
		if len(r.Res.Missing) > 0 || len(r.Res.UnknownTopKeys) > 0 ||
			len(r.Res.UnknownPaths) > 0 ||
			unexpectedAbsent || r.ProbeErr != "" || r.SkippedParam {
			warnings = true
		}
	}
	return drift, warnings
}

// codeList renders metric family names as an inline backticked list.
func codeList(names []string) string {
	quoted := make([]string, 0, len(names))
	for _, n := range names {
		quoted = append(quoted, "`"+n+"`")
	}
	return strings.Join(quoted, ", ")
}

// renderReport builds the markdown drift report. It prints endpoint names,
// key paths, JSON type names and HTTP statuses ONLY — never response values,
// because the report lands in a public issue.
// generation names the OPNsense release channel this run probed, e.g.
// "devel 27.1.a_40" or "release 26.7.1_1". It is stamped into the report
// heading so two boxes' findings are never confused for one another (#490).
//
// The support window is current + previous stable, so a key that is new on the
// nightly box is NOT yet real for anyone on a release, and a key removed there
// must still be tolerated while a release in the window sends it. Without the
// stamp a reader cannot tell which of those they are looking at. Empty renders
// the historical unlabelled heading.
var generation string

func renderReport(results []probeResult, exempt map[string]string) string {
	var b strings.Builder
	if generation != "" {
		fmt.Fprintf(&b, "## OPNsense live-box schema canary — %s\n\n", generation)
	} else {
		b.WriteString("## OPNsense live-box schema canary\n\n")
	}

	var mismatched, missing, unknown, unknownNested, absentUnexpected, absentGated, errored, skipped, unverified, clean int
	gated := pluginGatedSet()
	for _, r := range results {
		switch {
		case r.ProbeErr != "":
			errored++
		case r.Absent:
			if gated[r.Endpoint] {
				absentGated++
			} else {
				absentUnexpected++
			}
		case r.SkippedParam:
			skipped++
		case len(r.Res.Mismatches) > 0:
			mismatched++
		case len(r.Res.Missing) > 0 || len(r.Res.UnknownTopKeys) > 0 || len(r.Res.UnknownPaths) > 0:
			// counted below per category
		default:
			clean++
		}
		if len(r.Res.Missing) > 0 {
			missing++
		}
		if len(r.Res.UnknownTopKeys) > 0 {
			unknown++
		}
		if len(r.Res.UnknownPaths) > 0 {
			unknownNested++
		}
		if len(r.Res.Unverified) > 0 {
			unverified++
		}
	}
	fmt.Fprintf(&b, "Probed **%d** endpoints: %d clean, %d with breaking type drift, %d with missing paths, %d with unexpected top-level keys, %d with unexpected nested keys, %d absent 404 (%d unexpected, %d plugin-gated/expected), %d probe errors, %d skipped (no live parameter).\n\n",
		len(results), clean, mismatched, missing, unknown, unknownNested, absentUnexpected+absentGated, absentUnexpected, absentGated, errored, skipped)

	section := func(title string, body func()) {
		start := b.Len()
		fmt.Fprintf(&b, "### %s\n\n", title)
		mark := b.Len()
		body()
		if b.Len() == mark {
			// nothing written — drop the header again
			s := b.String()[:start]
			b.Reset()
			b.WriteString(s)
		} else {
			b.WriteString("\n")
		}
	}

	section("🔴 Breaking: type mismatches", func() {
		for _, r := range results {
			for _, m := range r.Res.Mismatches {
				path := m.Path
				if path == "" {
					path = "(top level)"
				}
				fmt.Fprintf(&b, "- `%s` `%s`: expected %s, live box serves %s\n", r.Endpoint, path, m.Expected, m.Got)
			}
		}
	})

	section("🟡 Missing key paths (renamed/removed upstream, or box state — exempt in `opnsense/testdata/schemas/exemptions.json` if legitimate)", func() {
		for _, r := range results {
			for _, p := range r.Res.Missing {
				fmt.Fprintf(&b, "- `%s` `%s`\n", r.Endpoint, p)
			}
		}
	})

	section("🟡 Unexpected top-level keys (data we do not model)", func() {
		for _, r := range results {
			for _, k := range r.Res.UnknownTopKeys {
				fmt.Fprintf(&b, "- `%s` top-level key `%s`\n", r.Endpoint, k)
			}
		}
	})

	// Nested extras (#376, warning since #457). Paths are normalized by the
	// validator: array elements are "[]" and dynamic map identities are "*", so
	// a hostname, peer identity or interface name can never reach this public
	// report.
	section("🟡 Unexpected nested keys (data we do not model — exempt in `opnsense/testdata/schemas/exemptions.json` under `knownExtraPaths` if legitimate)", func() {
		for _, r := range results {
			for _, p := range r.Res.UnknownPaths {
				fmt.Fprintf(&b, "- `%s` `%s`\n", r.Endpoint, p)
			}
		}
	})

	section("🟡 Core endpoints absent on the box (404 — route renamed or removed upstream?)", func() {
		for _, r := range results {
			if r.Absent && !gated[r.Endpoint] {
				fmt.Fprintf(&b, "- `%s` (`%s`) — a non-plugin endpoint 404'd; investigate\n", r.Endpoint, r.Path)
			}
		}
	})

	section("ℹ️ Plugin-gated endpoints absent (plugin not installed — expected, not drift)", func() {
		for _, r := range results {
			if r.Absent && gated[r.Endpoint] {
				fmt.Fprintf(&b, "- `%s` (`%s`)\n", r.Endpoint, r.Path)
			}
		}
	})

	section("🟡 Probe errors", func() {
		for _, r := range results {
			if r.ProbeErr != "" {
				fmt.Fprintf(&b, "- `%s` (HTTP %d): %s\n", r.Endpoint, r.Status, r.ProbeErr)
			}
		}
	})

	section("⚪ Skipped (parameterized, no live parameter)", func() {
		for _, r := range results {
			if r.SkippedParam {
				fmt.Fprintf(&b, "- `%s` — covered by the e2e smoke instead\n", r.Endpoint)
			}
		}
	})

	// Live coverage (#377): every unverified endpoint/path pair is named, split
	// by its class in the committed coverage ledger. Paths only — the validator
	// has already normalized array elements to "[]" and dynamic map identities
	// to "*", and no value ever enters a ValidationResult.
	review := reviewCoverage(results, loadCoverageIndex())

	section("🟡 Unverified paths that back metrics (required coverage — exercise the testbed)", func() {
		for _, f := range review.RequiredUnresolved {
			fmt.Fprintf(&b, "- `%s` `%s` — backs %s\n", f.Endpoint, f.Path, codeList(f.Entry.Metrics))
			if f.Entry.Blocker != "" {
				fmt.Fprintf(&b, "  - blocker: %s\n", f.Entry.Blocker)
			}
			if f.Entry.Exercise != "" {
				fmt.Fprintf(&b, "  - exercise: %s\n", f.Entry.Exercise)
			}
		}
	})

	section("ℹ️ Standing blind spots (required coverage the schema models as `any` — no live run can clear these)", func() {
		for _, f := range review.Opaque {
			fmt.Fprintf(&b, "- `%s` `%s` — backs %s\n", f.Endpoint, f.Path, codeList(f.Entry.Metrics))
			if f.Entry.Blocker != "" {
				fmt.Fprintf(&b, "  - %s\n", f.Entry.Blocker)
			}
		}
	})

	section("ℹ️ Unverified paths (ledgered box/hardware state)", func() {
		for _, f := range review.StateOptional {
			fmt.Fprintf(&b, "- `%s` `%s` — %s\n", f.Endpoint, f.Path, f.Entry.Reason)
		}
	})

	section("ℹ️ Unverified paths (not in `opnsense/testdata/schemas/coverage.json` — classify if one backs a metric)", func() {
		for _, f := range review.Unledgered {
			fmt.Fprintf(&b, "- `%s` `%s`\n", f.Endpoint, f.Path)
		}
	})

	if unverified > 0 {
		fmt.Fprintf(&b, "%d endpoints have paths that could not be verified (empty lists/maps or nulls on the box) — see the per-path sections above.\n\n", unverified)
	}
	if len(exempt) > 0 {
		fmt.Fprintf(&b, "%d endpoints have no schema (see `schemaExemptEndpoints` in `opnsense/schema_registry.go`).\n", len(exempt))
	}
	return b.String()
}
