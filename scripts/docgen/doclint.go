package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// doclint validates that every CLI-flag-shaped and exporter-env-var-shaped
// token in prose documentation refers to a real flag/env var from the kingpin
// model. Renaming a flag without updating an example becomes a build failure.

var flagTokenRe = regexp.MustCompile(`--((?:opnsense|web|log|exporter|otlp|pyroscope|runtime)\.[A-Za-z0-9.-]+)`)
var envTokenRe = regexp.MustCompile(`\b(OPNSENSE_EXPORTER_[A-Z0-9_]+|OPS_API_(?:KEY|SECRET)_FILE|PYROSCOPE_AUTH_(?:USER|PASSWORD)_FILE)\b`)

// fileSecretEnvVars are env vars read via os.LookupEnv in internal/options
// (not part of the kingpin model).
var fileSecretEnvVars = []string{
	"OPS_API_KEY_FILE", "OPS_API_SECRET_FILE",
	"PYROSCOPE_AUTH_USER_FILE", "PYROSCOPE_AUTH_PASSWORD_FILE",
	"OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_INSTANCE_ID_FILE",
	"OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_TOKEN_FILE",
}

type knownSet struct{ flags, envs map[string]bool }

func knownTokens(flags []FlagDoc) knownSet {
	k := knownSet{flags: map[string]bool{}, envs: map[string]bool{}}
	for _, f := range flags {
		k.flags[f.Name] = true
		if f.Envar != "" {
			k.envs[f.Envar] = true
		}
	}
	for _, e := range fileSecretEnvVars {
		k.envs[e] = true
	}
	return k
}

func extractDocTokens(text string) (flags, envs map[string]bool) {
	flags, envs = map[string]bool{}, map[string]bool{}
	for _, m := range flagTokenRe.FindAllStringSubmatch(text, -1) {
		flags[strings.TrimRight(m[1], ".-")] = true
	}
	for _, m := range envTokenRe.FindAllStringSubmatch(text, -1) {
		envs[m[1]] = true
	}
	return flags, envs
}

func lintText(file, text string, known knownSet, allow map[string]bool) []string {
	var problems []string
	flags, envs := extractDocTokens(text)
	for f := range flags {
		if !known.flags[f] && !allow[f] {
			problems = append(problems, fmt.Sprintf("%s: unknown flag --%s", file, f))
		}
	}
	for e := range envs {
		if !known.envs[e] && !allow[e] {
			problems = append(problems, fmt.Sprintf("%s: unknown env var %s", file, e))
		}
	}
	return problems
}

func loadAllowlist(repoRoot string) map[string]bool {
	allow := map[string]bool{}
	raw, err := os.ReadFile(filepath.Join(repoRoot, "scripts", "docgen", "doclint_allow.txt"))
	if err != nil {
		return allow
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		allow[line] = true
	}
	return allow
}

// lintTargets returns every prose/config file that may mention flags/env vars.
func lintTargets(repoRoot string) []string {
	targets := []string{"README.md", "CONTRIBUTING.md", "Makefile", "grafana/README.md"}
	for _, dir := range []string{"docs", "deploy"} {
		_ = filepath.WalkDir(filepath.Join(repoRoot, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if d.Name() == "superpowers" {
					return filepath.SkipDir
				}
				return nil
			}
			switch filepath.Ext(path) {
			case ".md", ".yaml", ".yml":
				rel, relErr := filepath.Rel(repoRoot, path)
				if relErr == nil {
					targets = append(targets, rel)
				}
			}
			return nil
		})
	}
	return targets
}

func runDoclint(repoRoot string, flags []FlagDoc) []string {
	known := knownTokens(flags)
	allow := loadAllowlist(repoRoot)
	var problems []string
	for _, rel := range lintTargets(repoRoot) {
		raw, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			continue // optional files (e.g. grafana/README.md) may not exist
		}
		problems = append(problems, lintText(rel, string(raw), known, allow)...)
	}
	return problems
}
