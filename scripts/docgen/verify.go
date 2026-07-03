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
	"github.com/rknightion/opnsense-exporter/internal/options"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

var fqNameRe = regexp.MustCompile(`fqName: "([^"]+)"`)
var varLabelsRe = regexp.MustCompile(`variableLabels: \{([^}]*)\}`)

func descFQName(s string) string {
	m := fqNameRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

// descVariableLabels extracts the variable-label names from a Desc.String(), dropping the universal
// opnsense_instance label that buildPrometheusDesc appends to every metric (docgen omits it from the
// docs on purpose). Returns them sorted for order-independent set comparison.
func descVariableLabels(s string) []string {
	m := varLabelsRe.FindStringSubmatch(s)
	if m == nil {
		return nil
	}
	var out []string
	for l := range strings.SplitSeq(m[1], ",") {
		l = strings.TrimSpace(l)
		if l == "" || l == "opnsense_instance" {
			continue
		}
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// sortedCopy returns a sorted copy of labels (docgen omits opnsense_instance already), for
// order-independent comparison against the runtime label set.
func sortedCopy(labels []string) []string {
	out := append([]string(nil), labels...)
	sort.Strings(out)
	return out
}

// verifyMetricsAgainstRegistry registers every collector and walks Describe(),
// then checks that each runtime metric name appears in the AST-parsed docs
// set. A runtime metric missing from the docs is a hard error (docgen's AST
// parser failed to see it). Docs-only names are reported as warnings, since
// some descriptors may be registered conditionally.
func verifyMetricsAgainstRegistry(astCollectors []CollectorInfo, topLevel []MetricInfo) error {
	astNames := map[string]bool{}
	astLabels := map[string][]string{}
	for _, c := range astCollectors {
		for _, m := range c.Metrics {
			astNames[m.FullName] = true
			astLabels[m.FullName] = sortedCopy(m.Labels)
		}
	}
	// Top-level Collector metrics (opnsense_up, exporter_*) are documented via parseTopLevelMetrics,
	// not AllCollectors(); include their names so the top-level Describe() cross-check below can
	// verify them too (#119).
	for _, m := range topLevel {
		astNames[m.FullName] = true
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runtimeNames := map[string]bool{}
	var missing []string
	var labelMismatches []string
	for _, inst := range collector.AllCollectors() {
		inst.Register("opnsense", "docgen", logger)
		ch := make(chan *prometheus.Desc, 4096)
		inst.Describe(ch)
		close(ch)
		for d := range ch {
			s := d.String()
			name := descFQName(s)
			if name == "" {
				continue
			}
			runtimeNames[name] = true
			if !astNames[name] {
				missing = append(missing, fmt.Sprintf("%s (collector %s)", name, inst.Name()))
				continue
			}
			// Compare the documented label set against the runtime Desc's variable labels so a
			// label the AST parser couldn't resolve (e.g. an append(...) chain, #118) is caught.
			runtimeLbls := descVariableLabels(s)
			if !equalStrings(runtimeLbls, astLabels[name]) {
				labelMismatches = append(labelMismatches, fmt.Sprintf(
					"%s: docs labels %v, runtime labels %v", name, astLabels[name], runtimeLbls))
			}
		}
	}

	// Cross-check the top-level Collector's own Describe() output, closing the asymmetry where
	// opnsense_up / exporter_* had no runtime coverage at all (#119). New() reads the client's
	// endpoint map (to seed endpoint-error series), so build a throwaway client — NewClient does no
	// network I/O, it just initialises config + the endpoint table.
	client, err := opnsense.NewClient(
		options.OPNSenseConfig{Protocol: "https", Host: "docgen.invalid"}, "docgen", logger)
	if err != nil {
		return fmt.Errorf("constructing throwaway client for top-level verification: %w", err)
	}
	topC, err := collector.New(&client, logger, "docgen")
	if err != nil {
		return fmt.Errorf("constructing top-level Collector for verification: %w", err)
	}
	topCh := make(chan *prometheus.Desc, 4096)
	topC.Describe(topCh)
	close(topCh)
	for d := range topCh {
		name := descFQName(d.String())
		if name == "" {
			continue
		}
		runtimeNames[name] = true
		if !astNames[name] {
			missing = append(missing, fmt.Sprintf("%s (top-level Collector)", name))
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
	if len(labelMismatches) > 0 {
		sort.Strings(labelMismatches)
		return fmt.Errorf("metrics whose documented label set differs from the runtime Desc (AST label-extraction gap):\n  %s",
			strings.Join(labelMismatches, "\n  "))
	}
	return nil
}

// equalStrings reports whether two sorted string slices are element-wise equal.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
