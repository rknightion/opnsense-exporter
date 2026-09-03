package options

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/kingpin/v2"
)

const (
	atFileHelperEnv = "OPN2OTEL_TEST_AT_FILE_HELPER"
	atFilePathEnv   = "OPN2OTEL_TEST_AT_FILE_PATH"
)

func TestInitEnablesAtFileExpansion(t *testing.T) {
	argsFile := writeAtFileFixture(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestAtFileExpansionHelper$")
	cmd.Env = exporterTestEnvironment(
		atFileHelperEnv+"=1",
		atFilePathEnv+"="+argsFile,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("parse @file in helper subprocess: %v\n%s", err, output)
	}
	for _, want := range []string{
		"protocol=https",
		"address=firewall.example.invalid",
		"config_check=true",
	} {
		if !strings.Contains(string(output), want) {
			t.Errorf("helper output %q does not contain %q", output, want)
		}
	}
}

func TestAtFileExpansionHelper(t *testing.T) {
	if os.Getenv(atFileHelperEnv) != "1" {
		return
	}

	// Init owns this switch. Force the dependency default the other way so this
	// subprocess proves the exporter enables expansion rather than inheriting
	// Kingpin's current default by accident.
	kingpin.EnableFileExpansion = false
	os.Args = []string{
		"opnsense2otel",
		"@" + os.Getenv(atFilePathEnv),
		"--config.check",
	}
	Init()

	fmt.Printf("protocol=%s\naddress=%s\nconfig_check=%t\n", *opnsenseProtocol, *opnsenseAPI, *ConfigCheck)
}

func TestAtFileConfigCheckSubprocess(t *testing.T) {
	argsFile := writeAtFileFixture(t)
	repoRoot := filepath.Join("..", "..")
	cmd := exec.Command("go", "run", ".", "@"+argsFile, "--config.check")
	cmd.Dir = repoRoot
	cmd.Env = exporterTestEnvironment()

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("validate @file configuration: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "config check OK") {
		t.Fatalf("config check output %q does not contain success marker", output)
	}
}

func writeAtFileFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "exporter.args")
	contents := strings.Join([]string{
		"# Shared service arguments; comment and blank lines are ignored.",
		"",
		"--opnsense.protocol=https",
		"--opnsense.address=firewall.example.invalid",
		"--opnsense.api-key=test-key",
		"--opnsense.api-secret=test-secret",
		"--exporter.instance-label=test-firewall",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write arguments file: %v", err)
	}
	return path
}

func exporterTestEnvironment(extra ...string) []string {
	env := make([]string, 0, len(os.Environ())+len(extra))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "OPN2OTEL_") {
			continue
		}
		switch name {
		case "OPS_API_KEY_FILE", "OPS_API_SECRET_FILE", "PYROSCOPE_AUTH_USER_FILE", "PYROSCOPE_AUTH_PASSWORD_FILE":
			continue
		}
		env = append(env, entry)
	}
	return append(env, extra...)
}
