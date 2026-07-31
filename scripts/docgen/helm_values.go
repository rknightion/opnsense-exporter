package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/rknightion/opnsense2otel/v4/internal/options"
)

// helmValuesWrapWidth matches envExampleWrapWidth's reasoning (some help strings quote
// a flag/env name inline) but is narrower: settings-block comments sit two spaces
// deeper than the flush-left .env.example, and values.yaml is read in a chart viewer
// that doesn't always give a full terminal width.
const helmValuesWrapWidth = 92

// excludedFromHelmSettings lists flags that must never appear in the generated
// settings block, with the reason rendered into values.yaml so the omission reads as
// deliberate rather than a docgen gap.
var excludedFromHelmSettings = map[string]string{
	"config.check": "one-shot validate-and-exit; wiring it through settings would turn " +
		"every pod start into a no-op that exits 0 instead of running the exporter",
}

// cumulativeValue structurally matches kingpin's unexported repeatableFlag interface.
// Go interface satisfaction is structural, so a flag's real Value (accumulator,
// stringMapValue, ...) still satisfies this even though the interface it was written
// against lives unexported in the kingpin package. True for .Strings()/.StringMap()
// flags: kingpin accepts one CLI occurrence per element rather than one joined value,
// so the chart must render one --flag=value arg per list element, not a comma join.
type cumulativeValue interface{ IsCumulative() bool }

// boolFlagValue structurally matches kingpin's unexported boolFlag interface, same
// trick as cumulativeValue.
type boolFlagValue interface{ IsBoolFlag() bool }

// flagShape is the rendering shape of one flag's value, read off the live kingpin
// model rather than guessed from the flag name.
type flagShape struct {
	IsList bool
	IsBool bool
}

// flagShapes derives IsList/IsBool for every registered flag. Consulted once by
// renderHelmSettingsBlock; not part of FlagDoc because flags.go is a frozen seam
// shared with the other generated artifacts.
func flagShapes() map[string]flagShape {
	options.RegisterAllFlags()
	out := map[string]flagShape{}
	for _, f := range kingpin.CommandLine.Model().Flags {
		var s flagShape
		if c, ok := f.Value.(cumulativeValue); ok {
			s.IsList = c.IsCumulative()
		}
		if b, ok := f.Value.(boolFlagValue); ok {
			s.IsBool = b.IsBoolFlag()
		}
		out[f.Name] = s
	}
	return out
}

// generateHelmValues injects the generated settings block into the chart values.
func generateHelmValues(out *output, chartDir string, flags []FlagDoc) {
	valuesPath := filepath.Join(chartDir, "values.yaml")
	content := renderHelmSettingsBlock(flags)

	doc, err := os.ReadFile(valuesPath)
	if err != nil {
		fatal("reading %s: %v", valuesPath, err)
	}
	injected, err := injectYAMLRegion(string(doc), "helm-settings", content)
	if err != nil {
		fatal("injecting helm-settings region in %s: %v", valuesPath, err)
	}
	out.write(valuesPath, []byte(injected))
}

// injectYAMLRegion is inject.go's injectRegion, adapted for a YAML host file.
// injectRegion's substitution is doc[:bi+len(begin)] + content + doc[ei:], which drops
// whatever preceded the end marker's own match inside the replaced span -- for a
// markdown host that's fine (the marker is a bare, harmless HTML comment either way),
// but a YAML host needs '#' immediately before "<!-- docgen:end:... -->" or that line
// stops being a comment and breaks the parse (verified: pyyaml raises "could not find
// expected ':'" on a bare marker line following a mapping). So this variant matches
// whole LINES containing each marker and never touches the marker lines themselves --
// only what sits between them -- keeping their original "# " prefix intact. Same
// marker text/name as injectRegion, so `grep docgen:begin` still finds every region
// regardless of host file type.
func injectYAMLRegion(doc, name, content string) (string, error) {
	begin := fmt.Sprintf("<!-- docgen:begin:%s -->", name)
	end := fmt.Sprintf("<!-- docgen:end:%s -->", name)

	lines := strings.Split(doc, "\n")
	beginIdx, endIdx := -1, -1
	for i, line := range lines {
		if strings.Contains(line, begin) {
			beginIdx = i
		}
		if strings.Contains(line, end) {
			endIdx = i
			break // first end marker after any begin match(es); region is non-overlapping
		}
	}
	if beginIdx < 0 || endIdx < 0 {
		return "", fmt.Errorf("docgen region %q: marker missing (begin found=%v, end found=%v)", name, beginIdx >= 0, endIdx >= 0)
	}
	if endIdx < beginIdx {
		return "", fmt.Errorf("docgen region %q: end marker before begin marker", name)
	}

	out := make([]string, 0, len(lines))
	out = append(out, lines[:beginIdx+1]...)
	out = append(out, strings.Split(strings.TrimRight(content, "\n"), "\n")...)
	out = append(out, lines[endIdx:]...)
	return strings.Join(out, "\n"), nil
}

// renderHelmSettingsBlock builds the text that sits between the helm-settings
// markers: a `settings:` key whose children are every flag, commented out, grouped
// and blurbed exactly as env_example.go and the mkdocs configuration reference are —
// one grouping (flaggroups.go) feeds all three artifacts, so they cannot drift into
// different section layouts as flags are added. It is a pure function of flags so
// tests can call it directly without touching disk, and two calls with the same
// input are byte-identical (no map iteration, no timestamps).
func renderHelmSettingsBlock(flags []FlagDoc) string {
	if unmatched := groupFlagsUnmatched(flags); len(unmatched) > 0 {
		fatal("helm_values: flags matched by no group rule (add a prefix to groupRules in flaggroups.go): %v", unmatched)
	}
	shapes := flagShapes()

	var b strings.Builder
	b.WriteString("settings:\n")

	for _, group := range groupFlags(flags) {
		visible := make([]FlagDoc, 0, len(group.Flags))
		for _, f := range group.Flags {
			if _, excluded := excludedFromHelmSettings[f.Name]; !excluded {
				visible = append(visible, f)
			}
		}
		if len(visible) == 0 {
			continue
		}

		b.WriteString("\n")
		fmt.Fprintf(&b, "  # ---- %s ----\n", group.Title)
		for _, line := range wrapHelmComment(group.Blurb, "  ") {
			b.WriteString(line)
			b.WriteString("\n")
		}

		for _, f := range visible {
			b.WriteString("  #\n")
			for _, line := range wrapHelmComment(f.Help, "  ") {
				b.WriteString(line)
				b.WriteString("\n")
			}
			fmt.Fprintf(&b, "  # %s\n", renderHelmSettingLine(f, shapes[f.Name]))
		}
	}

	b.WriteString("\n  # Excluded on purpose -- never renderable via settings at all:\n")
	for _, name := range sortedExcludedNames() {
		fmt.Fprintf(&b, "  #   %s: %s\n", name, excludedFromHelmSettings[name])
	}

	return b.String()
}

func sortedExcludedNames() []string {
	names := make([]string, 0, len(excludedFromHelmSettings))
	for name := range excludedFromHelmSettings {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// renderHelmSettingLine renders one `name: value` YAML mapping entry (without the
// leading comment marker, added by the caller) so that deleting the leading "# "
// after "  " produces a valid child of the settings: map.
func renderHelmSettingLine(f FlagDoc, shape flagShape) string {
	switch {
	case shape.IsList:
		items := splitDefaultList(f.Default)
		if len(items) == 0 {
			return f.Name + ": []  # LIST -- one --" + f.Name + "=value arg per element"
		}
		quoted := make([]string, len(items))
		for i, item := range items {
			quoted[i] = yamlQuote(item)
		}
		return f.Name + ": [" + strings.Join(quoted, ", ") + "]  # LIST -- one --" + f.Name + "=value arg per element"
	case shape.IsBool:
		v := f.Default
		if v != "true" && v != "false" {
			v = "false"
		}
		return f.Name + ": " + v
	default:
		return f.Name + ": " + yamlQuote(f.Default)
	}
}

// splitDefaultList parses FlagDoc.Default (a comma-joined kingpin default, see
// collectAllFlags) back into elements. Every repeatable flag in this exporter
// ships with an empty default, so this only guards against one being added later.
func splitDefaultList(def string) []string {
	if def == "" {
		return nil
	}
	return strings.Split(def, ",")
}

// wrapHelmComment word-wraps text into indent+"# "-prefixed lines, mirroring
// env_example.go's wrapComment but at the settings block's own indent and width.
func wrapHelmComment(text string, indent string) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	width := helmValuesWrapWidth
	var lines []string
	line := indent + "# " + words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = indent + "# " + w
			continue
		}
		line += " " + w
	}
	lines = append(lines, line)
	return lines
}
