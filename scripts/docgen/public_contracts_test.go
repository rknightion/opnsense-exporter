package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPublicDocumentationContracts(t *testing.T) {
	repoRoot := findRepoRoot()
	read := func(name string) string {
		t.Helper()
		contents, err := os.ReadFile(filepath.Join(repoRoot, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(contents)
	}

	readme := read("README.md")
	for _, required := range []string{
		"configured OPNsense address",
		"--exporter.instance-use-hostname",
	} {
		if !strings.Contains(readme, required) {
			t.Errorf("README.md must document %q", required)
		}
	}
	if strings.Contains(readme, "defaults to the hostname") {
		t.Error("README.md must not describe the hostname as the default instance label")
	}

	gettingStarted := read("docs/getting-started.md")
	if !strings.Contains(gettingStarted, "[compatibility policy](compatibility.md)") {
		t.Error("Getting Started must link to the canonical compatibility policy")
	}
	if strings.Contains(gettingStarted, "tested with 24.x and 25.x") {
		t.Error("Getting Started must not retain historical supported-release text")
	}

	release := read("docs/development/release-process.md")
	if leadingVContainerTag(release) {
		t.Error("release-process.md must show no-leading-v container tags")
	}
	for _, artifact := range []string{
		"opnsense2otel_Darwin_arm64.tar.gz",
		"opnsense2otel_Linux_x86_64.tar.gz",
		"opnsense2otel_Windows_x86_64.zip",
		"checksums.txt.sigstore.json",
		"THIRD_PARTY_NOTICES.md",
	} {
		if !strings.Contains(release, artifact) {
			t.Errorf("release-process.md must name planned release artifact %q", artifact)
		}
	}

	manifest := read("deploy/k8s/deployment.yaml")
	doc := read("docs/deployment/kubernetes.md")
	rendered, err := injectRegion(doc, "kubernetes-deployment", renderKubernetesDeploymentRegion(manifest))
	if err != nil {
		t.Fatalf("Kubernetes documentation must have a generated deployment region: %v", err)
	}
	if rendered != doc {
		t.Error("Kubernetes documentation deployment example must match deploy/k8s/deployment.yaml")
	}
	copyable, err := extractKubernetesDeploymentYAML(doc)
	if err != nil {
		t.Fatalf("extract Kubernetes deployment YAML: %v", err)
	}
	if copyable != strings.TrimSpace(manifest) {
		t.Error("copyable Kubernetes YAML must equal deploy/k8s/deployment.yaml")
	}
	if strings.Contains(copyable, "docgen:") || strings.Contains(copyable, "<!--") {
		t.Error("copyable Kubernetes YAML contains documentation markers")
	}
}

func TestStatRulesPinEveryREADMERegistryCount(t *testing.T) {
	tests := []struct {
		name  string
		stale string
		want  string
	}{
		{
			name:  "metric reference",
			stale: "| [Metrics reference] | All 808 metrics with types, labels and PromQL |",
			want:  "All 829 metrics",
		},
		{
			name:  "collector reference",
			stale: "| [Collectors] | What each of the 61 collectors covers |",
			want:  "each of the 62 collectors",
		},
	}
	rules := statRules(docStats{Metrics: 829, Collectors: 62, DashMetrics: 828, DashTabs: 41, Alerts: 1})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rule *statRule
			for i := range rules {
				candidate := rules[i]
				if candidate.File == "README.md" && candidate.Pattern.MatchString(tt.stale) {
					rule = &candidate
					break
				}
			}
			if rule == nil {
				t.Fatalf("README count in %q has no stat rule", tt.stale)
			}
			updated, err := applyStatRule(tt.stale, *rule)
			if err != nil {
				t.Fatalf("apply README count rule: %v", err)
			}
			if !strings.Contains(updated, tt.want) {
				t.Fatalf("README count not generated: got %q, want it to contain %q", updated, tt.want)
			}
		})
	}
}

func TestMandatoryReleaseAssetsFollowWorkflowList(t *testing.T) {
	root := t.TempDir()
	writeTestReleasePlan(t, root, []string{
		"attestation.custom.json",
		"opnsense2otel_Linux_x86_64.tar.gz",
		"opnsense2otel_Linux_x86_64.tar.gz.sbom.json",
	})

	got, err := mandatoryReleaseAssets(root)
	if err != nil {
		t.Fatalf("mandatoryReleaseAssets: %v", err)
	}
	want := []string{
		"attestation.custom.json",
		"opnsense2otel_Linux_x86_64.tar.gz",
		"opnsense2otel_Linux_x86_64.tar.gz.sbom.json",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mandatory assets = %v, want workflow list %v", got, want)
	}
}

func TestMandatoryReleaseAssetsRejectUnknownArchiveFilename(t *testing.T) {
	root := t.TempDir()
	writeTestReleasePlan(t, root, []string{
		"checksums.txt",
		"opnsense2otel_Linux_x86_64.tar.gz",
		"opnsense2otel_Linux_x86_64.tar.gz.sbom.json",
		"opnsense2otel_Linux_386.tar.gz",
	})

	_, err := mandatoryReleaseAssets(root)
	if err == nil || !strings.Contains(err.Error(), "not produced by .goreleaser.yml") {
		t.Fatalf("mandatoryReleaseAssets error = %v, want unknown archive rejection", err)
	}
}

func TestDocumentedReleaseAssetsRejectUnknownFilename(t *testing.T) {
	doc := `before
<!-- docgen:begin:release-assets -->
- ` + "`checksums.txt`" + `
- ` + "`opnsense2otel_Linux_386.tar.gz`" + `
<!-- docgen:end:release-assets -->
after
`
	err := validateDocumentedReleaseAssets(doc, []string{"checksums.txt"})
	if err == nil || !strings.Contains(err.Error(), "opnsense2otel_Linux_386.tar.gz") {
		t.Fatalf("validateDocumentedReleaseAssets error = %v, want unknown filename rejection", err)
	}
}

func TestGoreleaserArchivesRejectUnsupportedNameTemplate(t *testing.T) {
	root := t.TempDir()
	config := `project_name: opnsense2otel
builds:
  - goos:
      - linux
    goarch:
      - amd64
archives:
  - formats: [tar.gz]
    name_template: "{{ .ProjectName }}-{{ .Os }}-{{ .Arch }}"
`
	if err := os.WriteFile(filepath.Join(root, ".goreleaser.yml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := goreleaserArchives(root); err == nil || !strings.Contains(err.Error(), "name_template") {
		t.Fatalf("goreleaserArchives error = %v, want unsupported name_template error", err)
	}
}

func TestGoreleaserArchivesRejectUnsupportedFormats(t *testing.T) {
	root := t.TempDir()
	config := `project_name: opnsense2otel
builds:
  - goos:
      - linux
    goarch:
      - amd64
archives:
  - formats: [zip]
    name_template: >-
      {{ .ProjectName }}_
      {{- title .Os }}_
      {{- if eq .Arch "amd64" }}x86_64
      {{- else if eq .Arch "386" }}i386
      {{- else }}{{ .Arch }}{{ end }}
    format_overrides:
      - goos: windows
        formats: [zip]
`
	if err := os.WriteFile(filepath.Join(root, ".goreleaser.yml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := goreleaserArchives(root); err == nil || !strings.Contains(err.Error(), "formats") {
		t.Fatalf("goreleaserArchives error = %v, want unsupported formats error", err)
	}
}

func TestLeadingVContainerTagIsVersionAgnostic(t *testing.T) {
	for _, doc := range []string{
		"| `v4.7.2` | Specific version |",
		"`ghcr.io/rknightion/opnsense2otel:v12.0.1`",
	} {
		if !leadingVContainerTag(doc) {
			t.Errorf("leading-v container tag not rejected: %q", doc)
		}
	}
	if leadingVContainerTag("| `4.7.2` | Specific version; no leading v |") {
		t.Error("valid no-leading-v container tag rejected")
	}
}

func TestPrepareOutputDirsCheckModeDoesNotCreateDirectories(t *testing.T) {
	root := t.TempDir()
	if err := prepareOutputDirs(root, true); err != nil {
		t.Fatalf("prepareOutputDirs check mode: %v", err)
	}
	for _, dir := range []string{"metrics", "collectors"} {
		if _, err := os.Stat(filepath.Join(root, "docs", dir)); !os.IsNotExist(err) {
			t.Errorf("check mode created docs/%s: stat error = %v", dir, err)
		}
	}
}

func writeTestReleasePlan(t *testing.T, root string, assets []string) {
	t.Helper()
	config := `project_name: opnsense2otel
builds:
  - goos:
      - linux
    goarch:
      - amd64
archives:
  - formats: [tar.gz]
    name_template: >-
      {{ .ProjectName }}_
      {{- title .Os }}_
      {{- if eq .Arch "amd64" }}x86_64
      {{- else if eq .Arch "386" }}i386
      {{- else }}{{ .Arch }}{{ end }}
    format_overrides:
      - goos: windows
        formats: [zip]
`
	if err := os.WriteFile(filepath.Join(root, ".goreleaser.yml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	workflowDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o700); err != nil {
		t.Fatal(err)
	}
	workflow := "jobs:\n  verify-release-assets:\n    steps:\n      - run: |\n          required=(\n"
	for _, asset := range assets {
		workflow += "            " + asset + "\n"
	}
	workflow += "          )\n"
	if err := os.WriteFile(filepath.Join(workflowDir, "release-please.yml"), []byte(workflow), 0o600); err != nil {
		t.Fatal(err)
	}
}
