package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderGroupedTables(t *testing.T) {
	flags := collectAllFlags()
	tables := renderFlagTables(flags)

	required := []string{
		"flags-connection", "flags-exporter", "flags-pyroscope", "flags-otlp",
		"flags-collectors-default-on", "flags-collectors-opt-in",
		"flags-collectors-details", "flags-full-reference",
	}
	for _, name := range required {
		if tables[name] == "" {
			t.Errorf("no table rendered for region %q", name)
		}
	}
	if !strings.Contains(tables["flags-connection"], "`--opnsense.protocol`") {
		t.Error("connection table missing opnsense.protocol")
	}
	if !strings.Contains(tables["flags-collectors-default-on"], "ARP Table") {
		t.Error("default-on table missing ARP Table display name")
	}
	if !strings.Contains(tables["flags-collectors-opt-in"], "`--exporter.enable-netflow`") {
		t.Error("opt-in table missing netflow")
	}
	if !strings.Contains(tables["flags-collectors-details"], "`--exporter.enable-openvpn-details`") {
		t.Error("details table missing openvpn-details")
	}
	if !strings.Contains(tables["flags-full-reference"], "`--web.listen-address`") {
		t.Error("full reference missing web.listen-address")
	}
	if strings.Contains(tables["flags-exporter"], "exporter.disable-arp-table") {
		t.Error("collector switch leaked into exporter settings table")
	}
}

func TestRenderACLMatrixPreservesEndpointStatesAndCollectorModes(t *testing.T) {
	matrix := renderACLMatrix()

	for _, want := range []string{
		"ARP Table", "default-on", // base collector enabled unless disabled
		"NetFlow", "opt-in", // base collector enabled only by its switch
		"high-cardinality opt-in", "`--exporter.enable-arp-details`",
		"plugin-gated", "acmeCertificates",
		"unknown", "api/diagnostics/system/systemDisk", // unknown remains an explicit row
		"26.7.1", "26.1.11", "github.com/opnsense/plugins @ b59cf8e",
	} {
		if !strings.Contains(matrix, want) {
			t.Errorf("ACL matrix missing %q:\n%s", want, matrix)
		}
	}
	if strings.Contains(matrix, "read-only monitoring user") {
		t.Error("ACL matrix must not call a wildcard-ACL account read-only")
	}
}

func TestInjectSecurityDocReplacesACLMatrixRegion(t *testing.T) {
	repoRoot := t.TempDir()
	securityPath := filepath.Join(repoRoot, "docs", "security.md")
	if err := os.MkdirAll(filepath.Dir(securityPath), 0o755); err != nil {
		t.Fatal(err)
	}
	const source = "before\n<!-- docgen:begin:acl-matrix -->\nstale\n<!-- docgen:end:acl-matrix -->\nafter\n"
	if err := os.WriteFile(securityPath, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}

	injectSecurityDoc(&output{repoRoot: repoRoot})

	got, err := os.ReadFile(securityPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "stale") || !strings.Contains(string(got), "| Collector |") {
		t.Errorf("security document did not receive the generated ACL matrix:\n%s", got)
	}
}
