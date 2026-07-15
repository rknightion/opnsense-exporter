package main

import (
	"fmt"
	"strings"

	"github.com/rknightion/opnsense-exporter/opnsense"
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
// (missing paths, unexpected keys, a vanished CORE endpoint, probe problems). A
// plugin-gated endpoint answering 404 is expected (plugin not installed) and is
// NOT a warning — otherwise a box that simply doesn't run every optional plugin
// would keep the drift issue open forever.
func aggregate(results []probeResult) (drift, warnings bool) {
	gated := pluginGatedSet()
	for _, r := range results {
		if len(r.Res.Mismatches) > 0 {
			drift = true
		}
		unexpectedAbsent := r.Absent && !gated[r.Endpoint]
		if len(r.Res.Missing) > 0 || len(r.Res.UnknownTopKeys) > 0 ||
			unexpectedAbsent || r.ProbeErr != "" || r.SkippedParam {
			warnings = true
		}
	}
	return drift, warnings
}

// renderReport builds the markdown drift report. It prints endpoint names,
// key paths, JSON type names and HTTP statuses ONLY — never response values,
// because the report lands in a public issue.
func renderReport(results []probeResult, exempt map[string]string) string {
	var b strings.Builder
	b.WriteString("## OPNsense live-box schema canary\n\n")

	var mismatched, missing, unknown, absentUnexpected, absentGated, errored, skipped, unverified, clean int
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
		case len(r.Res.Missing) > 0 || len(r.Res.UnknownTopKeys) > 0:
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
		if len(r.Res.Unverified) > 0 {
			unverified++
		}
	}
	fmt.Fprintf(&b, "Probed **%d** endpoints: %d clean, %d with breaking type drift, %d with missing paths, %d with unexpected top-level keys, %d absent 404 (%d unexpected, %d plugin-gated/expected), %d probe errors, %d skipped (no live parameter).\n\n",
		len(results), clean, mismatched, missing, unknown, absentUnexpected+absentGated, absentUnexpected, absentGated, errored, skipped)

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

	if unverified > 0 {
		fmt.Fprintf(&b, "%d endpoints have paths that could not be verified (empty lists/maps on the box) — increase box activity to cover them.\n\n", unverified)
	}
	if len(exempt) > 0 {
		fmt.Fprintf(&b, "%d endpoints have no schema (see `schemaExemptEndpoints` in `opnsense/schema_registry.go`).\n", len(exempt))
	}
	return b.String()
}
