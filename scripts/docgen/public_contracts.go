package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// injectPublicContractDocs renders documentation excerpts that must remain tied
// to executable repository sources. It deliberately uses output so -check is
// read-only and reports drift instead of repairing it.
func injectPublicContractDocs(out *output) {
	injectKubernetesDeploymentDoc(out)
	injectReleaseAssetsDoc(out)
}

func injectKubernetesDeploymentDoc(out *output) {
	manifest, err := os.ReadFile(filepath.Join(out.repoRoot, "deploy", "k8s", "deployment.yaml"))
	if err != nil {
		fatal("reading canonical Kubernetes deployment: %v", err)
	}
	path := filepath.Join(out.repoRoot, "docs", "deployment", "kubernetes.md")
	doc, err := os.ReadFile(path)
	if err != nil {
		fatal("reading Kubernetes deployment docs: %v", err)
	}
	rendered, err := injectRegion(string(doc), "kubernetes-deployment",
		renderKubernetesDeploymentRegion(string(manifest)))
	if err != nil {
		fatal("injecting Kubernetes deployment docs: %v", err)
	}
	out.write(path, []byte(rendered))
}

func renderKubernetesDeploymentRegion(manifest string) string {
	return "```yaml title=\"deployment.yaml\"\n" + strings.TrimSpace(manifest) + "\n```"
}

func extractKubernetesDeploymentYAML(doc string) (string, error) {
	const (
		begin = "<!-- docgen:begin:kubernetes-deployment -->"
		end   = "<!-- docgen:end:kubernetes-deployment -->"
		fence = "```yaml title=\"deployment.yaml\""
	)
	beginAt := strings.Index(doc, begin)
	endAt := strings.Index(doc, end)
	if beginAt < 0 || endAt < beginAt {
		return "", fmt.Errorf("kubernetes deployment docgen region is missing or reversed")
	}
	region := strings.TrimSpace(doc[beginAt+len(begin) : endAt])
	if !strings.HasPrefix(region, fence+"\n") || !strings.HasSuffix(region, "\n```") {
		return "", fmt.Errorf("kubernetes deployment docgen region must contain exactly one YAML fence")
	}
	yaml := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(region, fence+"\n"), "\n```"))
	if strings.Contains(yaml, "<!--") || strings.Contains(yaml, "docgen:") {
		return "", fmt.Errorf("copyable Kubernetes YAML contains documentation markers")
	}
	return yaml, nil
}

func injectReleaseAssetsDoc(out *output) {
	assets, err := mandatoryReleaseAssets(out.repoRoot)
	if err != nil {
		fatal("deriving release assets: %v", err)
	}
	path := filepath.Join(out.repoRoot, "docs", "development", "release-process.md")
	doc, err := os.ReadFile(path)
	if err != nil {
		fatal("reading release-process docs: %v", err)
	}
	var content strings.Builder
	for _, asset := range assets {
		fmt.Fprintf(&content, "- `%s`\n", asset)
	}
	rendered, err := injectRegion(string(doc), "release-assets", content.String())
	if err != nil {
		fatal("injecting release asset docs: %v", err)
	}
	out.write(path, []byte(rendered))
}

func validateDocumentedReleaseAssets(doc string, required []string) error {
	const (
		begin = "<!-- docgen:begin:release-assets -->"
		end   = "<!-- docgen:end:release-assets -->"
	)
	if strings.Count(doc, begin) != 1 || strings.Count(doc, end) != 1 {
		return fmt.Errorf("release asset docgen region must have exactly one begin and end marker")
	}
	beginAt := strings.Index(doc, begin)
	endAt := strings.Index(doc, end)
	if endAt < beginAt {
		return fmt.Errorf("release asset docgen region markers are reversed")
	}
	var documented []string
	assetLine := regexp.MustCompile("^\\- `([A-Za-z0-9][A-Za-z0-9._-]*)`$")
	for _, line := range strings.Split(strings.TrimSpace(doc[beginAt+len(begin):endAt]), "\n") {
		match := assetLine.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) != 2 {
			return fmt.Errorf("release asset docgen region contains invalid line %q", line)
		}
		documented = append(documented, match[1])
	}
	requiredSet := map[string]bool{}
	for _, asset := range required {
		requiredSet[asset] = true
	}
	for _, asset := range documented {
		if !requiredSet[asset] {
			return fmt.Errorf("release-process.md documents asset %q outside the mandatory release plan", asset)
		}
	}
	if len(documented) != len(required) {
		return fmt.Errorf("release-process.md documents %d mandatory assets, want %d", len(documented), len(required))
	}
	for i := range required {
		if documented[i] != required[i] {
			return fmt.Errorf("release-process.md asset %d is %q, want %q", i+1, documented[i], required[i])
		}
	}
	return nil
}

func mandatoryReleaseAssets(repoRoot string) ([]string, error) {
	archives, err := goreleaserArchives(repoRoot)
	if err != nil {
		return nil, err
	}
	assets, err := releaseWorkflowAssets(repoRoot)
	if err != nil {
		return nil, err
	}
	if err := validateReleaseArchiveAssets(repoRoot, assets, archives); err != nil {
		return nil, err
	}
	return assets, nil
}

func releaseWorkflowAssets(repoRoot string) ([]string, error) {
	path := filepath.Join(repoRoot, ".github", "workflows", "release-please.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read release workflow: %w", err)
	}
	var (
		assets  []string
		inArray bool
		found   bool
	)
	validAsset := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "required=(" {
			if found {
				return nil, fmt.Errorf("release workflow contains multiple required asset arrays")
			}
			found = true
			inArray = true
			continue
		}
		if !inArray {
			continue
		}
		if trimmed == ")" {
			inArray = false
			break
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !validAsset.MatchString(trimmed) {
			return nil, fmt.Errorf("release workflow required asset %q is not a literal filename", trimmed)
		}
		if seen[trimmed] {
			return nil, fmt.Errorf("release workflow repeats mandatory asset %q", trimmed)
		}
		seen[trimmed] = true
		assets = append(assets, trimmed)
	}
	if !found || inArray || len(assets) == 0 {
		return nil, fmt.Errorf("release workflow has no complete non-empty required asset array")
	}
	return assets, nil
}

func validateReleaseArchiveAssets(repoRoot string, required, archives []string) error {
	expected := map[string]bool{}
	for _, archive := range archives {
		expected[archive] = true
		expected[archive+".sbom.json"] = true
	}
	requiredSet := map[string]bool{}
	for _, asset := range required {
		requiredSet[asset] = true
	}
	for asset := range expected {
		if !requiredSet[asset] {
			return fmt.Errorf("release workflow is missing .goreleaser.yml asset %q", asset)
		}
	}
	config, err := os.ReadFile(filepath.Join(repoRoot, ".goreleaser.yml"))
	if err != nil {
		return fmt.Errorf("read .goreleaser.yml for project name: %w", err)
	}
	project := regexp.QuoteMeta(goreleaserProjectName(repoRoot, string(config)))
	archiveLike := regexp.MustCompile(`^` + project + `_.+\.(?:tar\.gz|zip)(?:\.sbom\.json)?$`)
	for _, asset := range required {
		if archiveLike.MatchString(asset) && !expected[asset] {
			return fmt.Errorf("release workflow asset %q is not produced by .goreleaser.yml", asset)
		}
	}
	return nil
}

func goreleaserArchives(repoRoot string) ([]string, error) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, ".goreleaser.yml"))
	if err != nil {
		return nil, fmt.Errorf("read .goreleaser.yml: %w", err)
	}
	text := string(raw)
	const supportedNameTemplate = `name_template: >-
      {{ .ProjectName }}_
      {{- title .Os }}_
      {{- if eq .Arch "amd64" }}x86_64
      {{- else if eq .Arch "386" }}i386
      {{- else }}{{ .Arch }}{{ end }}`
	if !strings.Contains(text, supportedNameTemplate) {
		return nil, fmt.Errorf(".goreleaser.yml archive name_template is unsupported; update docgen plan parsing")
	}
	if !regexp.MustCompile(`(?m)^\s*-\s+formats:\s*\[tar\.gz\]\s*$`).MatchString(text) ||
		!regexp.MustCompile(`(?m)^\s*-\s+goos:\s*windows\s*\n\s+formats:\s*\[zip\]\s*$`).MatchString(text) {
		return nil, fmt.Errorf(".goreleaser.yml archive formats are unsupported; update docgen plan parsing")
	}
	project := goreleaserProjectName(repoRoot, text)
	oses := yamlList(text, "goos")
	arches := yamlList(text, "goarch")
	if len(oses) == 0 || len(arches) == 0 {
		return nil, fmt.Errorf("could not derive goos/goarch matrix from .goreleaser.yml")
	}
	ignored := map[string]bool{}
	for _, match := range regexp.MustCompile(`(?ms)^\s*- goos:\s*(\S+)\s*\n\s*goarch:\s*(\S+)`).FindAllStringSubmatch(text, -1) {
		ignored[match[1]+"/"+match[2]] = true
	}
	var archives []string
	for _, goos := range oses {
		for _, arch := range arches {
			if ignored[goos+"/"+arch] {
				continue
			}
			nameArch := arch
			if arch == "amd64" {
				nameArch = "x86_64"
			}
			ext := ".tar.gz"
			if goos == "windows" {
				ext = ".zip"
			}
			archives = append(archives, fmt.Sprintf("%s_%s_%s%s", project, titleOS(goos), nameArch, ext))
		}
	}
	sort.Strings(archives)
	return archives, nil
}

func goreleaserProjectName(repoRoot, config string) string {
	if match := regexp.MustCompile(`(?m)^project_name:\s*([A-Za-z0-9._-]+)\s*$`).FindStringSubmatch(config); len(match) == 2 {
		return match[1]
	}
	return filepath.Base(repoRoot)
}

func yamlList(text, key string) []string {
	var values []string
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		trimmedKey := strings.TrimSpace(line)
		if trimmedKey != key+":" && strings.TrimPrefix(trimmedKey, "- ") != key+":" {
			continue
		}
		keyIndent := len(line) - len(strings.TrimLeft(line, " "))
		for _, itemLine := range lines[i+1:] {
			trimmed := strings.TrimSpace(itemLine)
			if trimmed == "" {
				continue
			}
			indent := len(itemLine) - len(strings.TrimLeft(itemLine, " "))
			if indent <= keyIndent {
				break
			}
			if !strings.HasPrefix(trimmed, "- ") {
				break
			}
			value := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			if strings.ContainsAny(value, " \t#[]{}") {
				break
			}
			values = append(values, value)
		}
		break
	}
	return values
}

func titleOS(goos string) string {
	if goos == "darwin" {
		return "Darwin"
	}
	return strings.ToUpper(goos[:1]) + goos[1:]
}

func verifyPublicContracts(repoRoot string, stats docStats) error {
	var problems []string
	read := func(name string) string {
		raw, err := os.ReadFile(filepath.Join(repoRoot, name))
		if err != nil {
			problems = append(problems, fmt.Sprintf("read %s: %v", name, err))
			return ""
		}
		return string(raw)
	}

	readme := read("README.md")
	for _, fact := range []string{"configured OPNsense address", "--exporter.instance-use-hostname"} {
		if !strings.Contains(readme, fact) {
			problems = append(problems, "README.md missing instance-label fact: "+fact)
		}
	}
	if strings.Contains(readme, "defaults to the hostname") {
		problems = append(problems, "README.md describes hostname as the default instance label")
	}

	gettingStarted := read("docs/getting-started.md")
	if !strings.Contains(gettingStarted, "[compatibility policy](compatibility.md)") || strings.Contains(gettingStarted, "tested with 24.x and 25.x") {
		problems = append(problems, "docs/getting-started.md must use the canonical compatibility policy")
	}

	manifest := read("deploy/k8s/deployment.yaml")
	doc := read("docs/deployment/kubernetes.md")
	if rendered, err := injectRegion(doc, "kubernetes-deployment",
		renderKubernetesDeploymentRegion(manifest)); err != nil || rendered != doc {
		problems = append(problems, "docs/deployment/kubernetes.md deployment example differs from deploy/k8s/deployment.yaml")
	}
	if copyable, err := extractKubernetesDeploymentYAML(doc); err != nil {
		problems = append(problems, err.Error())
	} else if copyable != strings.TrimSpace(manifest) {
		problems = append(problems, "copyable Kubernetes deployment YAML differs from deploy/k8s/deployment.yaml")
	}

	assets, err := mandatoryReleaseAssets(repoRoot)
	if err != nil {
		problems = append(problems, err.Error())
	} else {
		release := read("docs/development/release-process.md")
		if err := validateDocumentedReleaseAssets(release, assets); err != nil {
			problems = append(problems, err.Error())
		}
		if leadingVContainerTag(release) {
			problems = append(problems, "release-process.md shows a leading-v container tag")
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("public documentation contracts failed:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}

func leadingVContainerTag(doc string) bool {
	tableTag := regexp.MustCompile("(?mi)^\\|\\s*`v\\d+\\.\\d+\\.\\d+[^`]*`\\s*\\|\\s*Specific version")
	imageRef := regexp.MustCompile(`(?i)ghcr\.io/rknightion/opnsense2otel:v\d+\.\d+\.\d+`)
	return tableTag.MatchString(doc) || imageRef.MatchString(doc)
}
