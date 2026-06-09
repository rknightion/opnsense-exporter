package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/internal/collector"
)

var fqNameRe = regexp.MustCompile(`fqName: "([^"]+)"`)

func descFQName(s string) string {
	m := fqNameRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

// verifyMetricsAgainstRegistry registers every collector and walks Describe(),
// then checks that each runtime metric name appears in the AST-parsed docs
// set. A runtime metric missing from the docs is a hard error (docgen's AST
// parser failed to see it). Docs-only names are reported as warnings, since
// some descriptors may be registered conditionally.
func verifyMetricsAgainstRegistry(astCollectors []CollectorInfo) error {
	astNames := map[string]bool{}
	for _, c := range astCollectors {
		for _, m := range c.Metrics {
			astNames[m.FullName] = true
		}
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runtimeNames := map[string]bool{}
	var missing []string
	for _, inst := range collector.AllCollectors() {
		inst.Register("opnsense", "docgen", logger)
		ch := make(chan *prometheus.Desc, 4096)
		inst.Describe(ch)
		close(ch)
		for d := range ch {
			name := descFQName(d.String())
			if name == "" {
				continue
			}
			runtimeNames[name] = true
			if !astNames[name] {
				missing = append(missing, fmt.Sprintf("%s (collector %s)", name, inst.Name()))
			}
		}
	}

	var docsOnly []string
	for name := range astNames {
		if !runtimeNames[name] {
			docsOnly = append(docsOnly, name)
		}
	}
	sort.Strings(docsOnly)
	if len(docsOnly) > 0 {
		fmt.Fprintf(os.Stderr, "docgen: WARNING: %d metrics documented but not described at registration (conditional descriptors?):\n  %s\n",
			len(docsOnly), strings.Join(docsOnly, "\n  "))
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("metrics described by collectors but missing from generated docs (AST parser gap):\n  %s",
			strings.Join(missing, "\n  "))
	}
	return nil
}
