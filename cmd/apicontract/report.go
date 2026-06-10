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
