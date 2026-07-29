package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every flag in the kingpin model must appear in the rendered output --
// this is the whole point of the artifact: an operator reference that can't
// silently drop a flag when one is added.
func TestEnvExampleCoversEveryFlag(t *testing.T) {
	flags := collectAllFlags()
	content := renderEnvExample(flags)
	for _, f := range flags {
		needle := envVarName(f)
		if f.Envar == "" {
			needle = "--" + f.Name
		}
		if !strings.Contains(content, needle) {
			t.Errorf("flag %q (env %q) missing from .env.example output", f.Name, needle)
		}
	}
}

// Deterministic output: rendering twice from the same flag slice must
// produce byte-identical content, since docs-check compares generated
// content against what's committed.
func TestEnvExampleDeterministic(t *testing.T) {
	flags := collectAllFlags()
	a := renderEnvExample(flags)
	b := renderEnvExample(flags)
	if a != b {
		t.Fatal("renderEnvExample is not deterministic across two runs on the same input")
	}
}

// Spot-check a few known defaults render exactly, so a future default change
// upstream is caught here rather than only in a stale-docs CI failure.
func TestEnvExampleKnownDefaults(t *testing.T) {
	flags := collectAllFlags()
	content := renderEnvExample(flags)
	for _, want := range []string{
		"#OPNSENSE_EXPORTER_FLOW_TOP_N=1000",
		"#OPNSENSE_EXPORTER_OTLP_PROTOCOL=http/protobuf",
		"#OPNSENSE_EXPORTER_LOGS_SYSLOG_LISTEN_UDP=:5514",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("expected line %q in rendered output, not found", want)
		}
	}
}

// The two flags kingpin marks Required (--opnsense.address, --opnsense.protocol)
// must render uncommented; every other env-bearing flag must render commented.
func TestEnvExampleRequiredFlagsUncommented(t *testing.T) {
	flags := collectAllFlags()
	content := renderEnvExample(flags)

	var required []FlagDoc
	for _, f := range flags {
		if f.Required {
			required = append(required, f)
		}
	}
	if len(required) == 0 {
		t.Fatal("expected at least one Required flag in the kingpin model (ops.api/ops.protocol) -- model may have changed")
	}

	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimPrefix(line, "#")
		isVarLine := strings.Contains(line, "=") && !strings.HasPrefix(strings.TrimSpace(trimmed), "#") &&
			strings.Contains(line, "OPNSENSE_EXPORTER_")
		if !isVarLine {
			continue
		}
		commented := strings.HasPrefix(line, "#")
		name := strings.SplitN(line, "=", 2)[0]
		name = strings.TrimPrefix(name, "#")

		var matched *FlagDoc
		for i := range flags {
			if flags[i].Envar == name {
				matched = &flags[i]
				break
			}
		}
		if matched == nil {
			t.Errorf("line %q: env var %q not found in flag model", line, name)
			continue
		}
		if matched.Required && commented {
			t.Errorf("required flag %s rendered commented out: %q", matched.Name, line)
		}
		if !matched.Required && !commented {
			t.Errorf("non-required flag %s rendered uncommented: %q", matched.Name, line)
		}
	}
}

// --config.check has no Envar (it's a one-shot CLI flag, never a standing
// env setting) and must still appear, documented as flag-only, not silently
// dropped for lacking an env var.
func TestEnvExampleFlagOnlyEntry(t *testing.T) {
	flags := collectAllFlags()
	found := false
	for _, f := range flags {
		if f.Envar == "" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected at least one env-less flag in the kingpin model (config.check) -- model may have changed")
	}

	content := renderEnvExample(flags)
	if !strings.Contains(content, "flag: --config.check") {
		t.Error("expected --config.check documented in output")
	}
	if !strings.Contains(content, "flag-only, no environment variable equivalent") {
		t.Error("expected the flag-only note for an env-less flag")
	}
}

// generateEnvExample must actually go through output.write, not just build a
// string in memory -- this is the real seam the wiring pass calls.
func TestGenerateEnvExampleWritesThroughOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.example")
	flags := collectAllFlags()

	out := &output{checkMode: false, repoRoot: dir}
	generateEnvExample(out, path, flags)

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected generateEnvExample to write %s: %v", path, err)
	}
	if string(written) != renderEnvExample(flags) {
		t.Error("written content does not match renderEnvExample output")
	}
}
