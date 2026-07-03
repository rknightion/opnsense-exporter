package main

import (
	"fmt"
	"strings"
)

// HasErrors reports whether any ref had an error-class finding.
func HasErrors(reps []Report) bool {
	for _, r := range reps {
		if len(r.Errors) > 0 {
			return true
		}
	}
	return false
}

// HasWarnings reports whether any ref had a warning-class finding (verb drift, e.g.
// the CVE-2026-30868 GET->POST tightening class). This is deliberately independent of
// HasErrors: verb drift does not change the exit code (it must not force a hard CI
// failure), but the workflow needs a distinct signal so a warnings-only run still files
// or updates the api-drift issue instead of finishing silently green (#93).
func HasWarnings(reps []Report) bool {
	for _, r := range reps {
		if len(r.Warnings) > 0 {
			return true
		}
	}
	return false
}

// GitHubOutputs renders the `drift`/`warnings` step outputs consumed by
// api-contract.yml. `drift` gates the hard-fail + close-when-clean steps; `warnings`
// (OR'd with drift) gates issue creation/update and blocks the close-when-clean step
// while verb drift is still live. Written to $GITHUB_OUTPUT by main.
func GitHubOutputs(reps []Report) string {
	return fmt.Sprintf("drift=%t\nwarnings=%t\n", HasErrors(reps), HasWarnings(reps))
}

// RenderMarkdown produces the issue body summarising drift across refs.
func RenderMarkdown(reps []Report) string {
	var b strings.Builder
	b.WriteString("## OPNsense API contract check\n\n")
	clean := true
	for _, r := range reps {
		if len(r.Errors) > 0 || len(r.Warnings) > 0 {
			clean = false
		}
	}
	if clean {
		b.WriteString("No drift detected across checked refs.\n")
		return b.String()
	}
	for _, r := range reps {
		fmt.Fprintf(&b, "### `%s`\n\n", r.Ref)
		if len(r.Errors) == 0 && len(r.Warnings) == 0 {
			b.WriteString("No drift.\n\n")
			continue
		}
		if len(r.Errors) > 0 {
			b.WriteString("**Missing endpoints (breaking — endpoint not found in source):**\n\n")
			b.WriteString("| Endpoint | Path | Detail |\n|---|---|---|\n")
			for _, f := range r.Errors {
				fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n", f.Endpoint, f.OurPath, f.Detail)
			}
			b.WriteString("\n")
		}
		if len(r.Warnings) > 0 {
			b.WriteString("**Verb drift (warning — method may have changed):**\n\n")
			b.WriteString("| Endpoint | Path | Detail |\n|---|---|---|\n")
			for _, f := range r.Warnings {
				fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n", f.Endpoint, f.OurPath, f.Detail)
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}
