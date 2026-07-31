package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelmValuesListsEveryFlagExceptConfigCheck(t *testing.T) {
	flags := collectAllFlags()
	block := renderHelmSettingsBlock(flags)

	for _, f := range flags {
		if f.Name == "config.check" {
			if !strings.Contains(block, "config.check: ") {
				t.Error("config.check should still be named in the excluded-flags footer")
			}
			if strings.Contains(block, "\n  # config.check: \"") {
				t.Error("config.check must never render as a settable settings entry")
			}
			continue
		}
		if !strings.Contains(block, "  # "+f.Name+": ") {
			t.Errorf("flag %q not found as a commented settings entry in the generated block", f.Name)
		}
	}
}

func TestHelmValuesDeterministic(t *testing.T) {
	flags := collectAllFlags()
	a := renderHelmSettingsBlock(flags)
	b := renderHelmSettingsBlock(flags)
	if a != b {
		t.Fatal("renderHelmSettingsBlock is not deterministic across two calls with the same input")
	}
}

func TestHelmValuesRepeatableFlagsMarkedAsList(t *testing.T) {
	flags := collectAllFlags()
	block := renderHelmSettingsBlock(flags)

	for _, name := range []string{
		"flow.netflow.allowed-peers",
		"collector.poll-interval-override",
		"annotations.extra-tags",
		"logs.zenarmor.exclude",
	} {
		want := "  # " + name + ": []  # LIST -- one --" + name + "=value arg per element"
		if !strings.Contains(block, want) {
			t.Errorf("expected repeatable flag %q to render as a LIST entry, got block:\n%s", name, block)
		}
	}

	// logs.syslog.allowed-peers and logs.zenarmor.allowed-peers are plain .String()
	// flags (the chart itself comma-joins allowedPeers into one value) -- they must
	// NOT be marked LIST.
	for _, name := range []string{"logs.syslog.allowed-peers", "logs.zenarmor.allowed-peers"} {
		if strings.Contains(block, name+": []  # LIST") {
			t.Errorf("flag %q is not repeatable in the kingpin model and must not render as LIST", name)
		}
	}
}

func TestHelmValuesSpotCheckKnownDefaults(t *testing.T) {
	flags := collectAllFlags()
	block := renderHelmSettingsBlock(flags)

	cases := []struct {
		name string
		want string
	}{
		{"exporter.disable-arp-table", "  # exporter.disable-arp-table: false"},
		{"opnsense.max-retries", `  # opnsense.max-retries: "3"`},
		{"opnsense.timeout", `  # opnsense.timeout: "15s"`},
		{"opnsense.address", `  # opnsense.address: ""`},
	}
	for _, c := range cases {
		if !strings.Contains(block, c.want) {
			t.Errorf("expected line %q for flag %q, not found in block", c.want, c.name)
		}
	}
}

func TestHelmValuesGroupingCoversAllFlags(t *testing.T) {
	// helm_values.go leans on the same grouping as env_example.go and the mkdocs
	// configuration reference; this is the guard that a flag matched by no group
	// rule fails loudly here too, rather than quietly missing from the chart.
	flags := collectAllFlags()
	if unmatched := groupFlagsUnmatched(flags); len(unmatched) > 0 {
		t.Fatalf("flags unmatched by any group rule: %v", unmatched)
	}
}

// TestInjectYAMLRegionPreservesMarkerLines is the regression test for the bug that
// motivated writing this instead of reusing inject.go's injectRegion unmodified:
// injectRegion's fixed doc[:bi+len(begin)] + content + doc[ei:] splice drops whatever
// text preceded the end marker inside the replaced span, so on a YAML host the '#'
// before "<!-- docgen:end:... -->" is lost and the bare marker line breaks the YAML
// parse (reproduced with pyyaml: "could not find expected ':'"). injectYAMLRegion
// must keep both marker LINES byte-for-byte untouched.
func TestInjectYAMLRegionPreservesMarkerLines(t *testing.T) {
	doc := "a: 1\n" +
		"settings:\n" +
		"# <!-- docgen:begin:x -->\n" +
		"OLD\n" +
		"# <!-- docgen:end:x -->\n" +
		"b: 2\n"
	got, err := injectYAMLRegion(doc, "x", "NEW")
	if err != nil {
		t.Fatal(err)
	}
	want := "a: 1\n" +
		"settings:\n" +
		"# <!-- docgen:begin:x -->\n" +
		"NEW\n" +
		"# <!-- docgen:end:x -->\n" +
		"b: 2\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestInjectYAMLRegionMissingMarkerErrors(t *testing.T) {
	if _, err := injectYAMLRegion("no markers here", "x", "c"); err == nil {
		t.Fatal("expected an error for a missing marker")
	}
}

func TestInjectYAMLRegionEndBeforeBeginErrors(t *testing.T) {
	doc := "# <!-- docgen:end:x -->\n# <!-- docgen:begin:x -->\n"
	if _, err := injectYAMLRegion(doc, "x", "c"); err == nil {
		t.Fatal("expected an error when the end marker precedes the begin marker")
	}
}

// TestGeneratedValuesEndMarkerKeepsCommentPrefix is the artifact-level companion to
// TestInjectYAMLRegionPreservesMarkerLines: it pins the actual chart file rather than
// a synthetic doc, so a future change that switches this back to raw injectRegion (or
// otherwise regresses the marker line) fails here even without running `helm lint`.
func TestGeneratedValuesEndMarkerKeepsCommentPrefix(t *testing.T) {
	root := findRepoRoot()
	doc, err := os.ReadFile(filepath.Join(root, "charts", "opnsense2otel", "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(doc), "\n") {
		if strings.Contains(line, "<!-- docgen:end:helm-settings -->") {
			trimmed := strings.TrimLeft(line, " ")
			if !strings.HasPrefix(trimmed, "#") {
				t.Fatalf("end marker line is not a YAML comment: %q", line)
			}
			return
		}
	}
	t.Fatal("helm-settings end marker not found in charts/opnsense2otel/values.yaml")
}
