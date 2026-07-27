package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePkg lays out a throwaway package under a temp repo root and returns the root.
func writePkg(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, src := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	return root
}

func names(ms []SelfMetric) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.FullName)
	}
	return out
}

func collect(t *testing.T, root string) []SelfMetric {
	t.Helper()
	got, err := collectSelfMetrics(root, filepath.Join(root, "internal"))
	if err != nil {
		t.Fatalf("collectSelfMetrics: %v", err)
	}
	return got
}

// TestSelfMetricScan_NameComposition covers every way a metric name is spelled in this
// tree. The Subsystem case is a REGRESSION TEST, not a completeness flourish:
// internal/collector declares its meta family as Namespace "opnsense" + Subsystem
// "exporter", which composes to the self-metric prefix. An early version of the scanner
// ruled a literal out by comparing the NAMESPACE field alone to "opnsense_exporter",
// and silently lost all seven of those metrics — scrapes_total, endpoint_errors_total
// and the whole api_* family — from an inventory whose entire purpose is completeness.
// Rule out on the composed prefix, never on one field.
func TestSelfMetricScan_NameComposition(t *testing.T) {
	root := writePkg(t, map[string]string{
		"internal/a/a.go": `package a

import "github.com/prometheus/client_golang/prometheus"

const namespace = "opnsense"

func build() {
	const ns = "opnsense_exporter"
	_ = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "logs_shipped_total",
	}, []string{"source"})
	_ = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "opnsense_exporter_annotations_written_total",
	})
	_ = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "exporter", Name: "scrapes_total",
	}, nil)
	_ = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace, Subsystem: "gateways", Name: "status",
	})
	_ = prometheus.NewDesc("opnsense_exporter_build_info", "help", nil, nil)
	_ = prometheus.NewDesc(prometheus.BuildFQName(namespace, "exporter", "collector_enabled"),
		"help", nil, nil)
}
`,
	})

	want := []string{
		"opnsense_exporter_annotations_written_total",
		"opnsense_exporter_build_info",
		"opnsense_exporter_collector_enabled",
		"opnsense_exporter_logs_shipped_total",
		"opnsense_exporter_scrapes_total",
	}
	got := names(collect(t, root))
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("scanned names:\n got %v\nwant %v", got, want)
	}
}

// TestSelfMetricScan_FirewallMetricsExcluded pins the other half of the boundary: a
// metric in the "opnsense" namespace that is NOT under the exporter subsystem is
// firewall data, already covered by the collector catalogue, and must not appear here.
func TestSelfMetricScan_FirewallMetricsExcluded(t *testing.T) {
	root := writePkg(t, map[string]string{
		"internal/a/a.go": `package a

import "github.com/prometheus/client_golang/prometheus"

const namespace = "opnsense"

func build() {
	_ = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace, Subsystem: "interfaces", Name: "bytes_total",
	})
}
`,
	})
	if got := collect(t, root); len(got) != 0 {
		t.Errorf("firewall metric leaked into the self-metric inventory: %v", names(got))
	}
}

// TestSelfMetricScan_ConstScopeIsPerPackage is a REGRESSION TEST for a real failure.
// The first version resolved constants per FILE. `namespace` is declared once in
// internal/collector/collector.go and used by the shared descriptor helper in
// internal/collector/utils.go, so the helper's namespace looked unresolvable and the
// hard-error rule failed docgen outright on the most ordinary declaration in the tree.
func TestSelfMetricScan_ConstScopeIsPerPackage(t *testing.T) {
	root := writePkg(t, map[string]string{
		"internal/a/consts.go": `package a

const ns = "opnsense_exporter"
`,
		"internal/a/metrics.go": `package a

import "github.com/prometheus/client_golang/prometheus"

func build() {
	_ = prometheus.NewCounter(prometheus.CounterOpts{Namespace: ns, Name: "logs_dropped_total"})
}
`,
	})
	got := names(collect(t, root))
	if len(got) != 1 || got[0] != "opnsense_exporter_logs_dropped_total" {
		t.Errorf("constant declared in a sibling file did not resolve: got %v", got)
	}
}

// TestSelfMetricScan_UnresolvableNameIsFatal is the property that gives the whole gate
// its teeth. If a declaration's name cannot be resolved to a constant, the scan must
// FAIL rather than omit the metric — omitting it would leave an easy bypass: build the
// name from a variable and the coverage gate stops seeing you.
func TestSelfMetricScan_UnresolvableNameIsFatal(t *testing.T) {
	root := writePkg(t, map[string]string{
		"internal/a/a.go": `package a

import "github.com/prometheus/client_golang/prometheus"

func build(suffix string) {
	const ns = "opnsense_exporter"
	_ = prometheus.NewCounter(prometheus.CounterOpts{Namespace: ns, Name: "logs_" + suffix})
}
`,
	})
	_, err := collectSelfMetrics(root, filepath.Join(root, "internal"))
	if err == nil {
		t.Fatal("a metric name built from a variable was silently skipped; it must be fatal")
	}
	if !strings.Contains(err.Error(), "internal/a/a.go") {
		t.Errorf("error should name the offending file, got: %v", err)
	}
}

// TestSelfMetricScan_DynamicNameNeedsAnAllowlistEntry pins the counterweight and its
// price. Sub-collectors build descriptors through a shared helper whose subsystem and
// name are function parameters by design, and namespace "opnsense" cannot be ruled out
// because "opnsense" + "exporter" reaches us. So the strict rule fires on it, and the
// ONLY way past is an explicit entry in dynamicNameSites.
//
// That is the intended design, not a wart: an accidental hole would be a metric that
// quietly vanishes from the inventory, whereas this hole is a line of code someone has
// to add and justify. The test asserts both halves — unlisted is fatal, and the one
// real listed site is the collector's descriptor helper and nothing else.
func TestSelfMetricScan_DynamicNameNeedsAnAllowlistEntry(t *testing.T) {
	root := writePkg(t, map[string]string{
		"internal/a/a.go": `package a

import "github.com/prometheus/client_golang/prometheus"

const namespace = "opnsense"

func buildDesc(subsystem, name string) *prometheus.Desc {
	return prometheus.NewDesc(prometheus.BuildFQName(namespace, subsystem, name), "h", nil, nil)
}
`,
	})
	if _, err := collectSelfMetrics(root, filepath.Join(root, "internal")); err == nil {
		t.Error("an unlisted dynamic declaration site was tolerated; it must be fatal")
	}

	want := map[string]bool{"internal/collector/utils.go": true}
	if len(dynamicNameSites) != len(want) {
		t.Fatalf("dynamicNameSites has %d entries, want %d — every addition is a hole in the "+
			"inventory guarantee and needs justifying in the comment above it: %v",
			len(dynamicNameSites), len(want), dynamicNameSites)
	}
	for site := range want {
		if !dynamicNameSites[site] {
			t.Errorf("expected %s to be the allowlisted dynamic site", site)
		}
	}
}

// TestSelfMetricScan_TestFilesIgnored keeps fixture metric names — several of which
// deliberately end in _test — out of the shipped inventory.
func TestSelfMetricScan_TestFilesIgnored(t *testing.T) {
	root := writePkg(t, map[string]string{
		"internal/a/a_test.go": `package a

import "github.com/prometheus/client_golang/prometheus"

func build() {
	_ = prometheus.NewCounter(prometheus.CounterOpts{Name: "opnsense_exporter_scrapes_total_test"})
}
`,
	})
	if got := collect(t, root); len(got) != 0 {
		t.Errorf("a _test.go declaration entered the inventory: %v", names(got))
	}
}

// TestSelfMetricScan_TypesAndDedupe pins the reported type per constructor and the
// collapse of a name declared more than once (pre-initialisation helpers and
// per-source constructors legitimately repeat a name).
func TestSelfMetricScan_TypesAndDedupe(t *testing.T) {
	root := writePkg(t, map[string]string{
		"internal/a/a.go": `package a

import "github.com/prometheus/client_golang/prometheus"

func build() {
	const ns = "opnsense_exporter"
	_ = prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: ns, Name: "logs_latency_seconds"})
	_ = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "logs_queue_length"})
	_ = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "logs_queue_length"})
}
`,
	})
	got := collect(t, root)
	if len(got) != 2 {
		t.Fatalf("expected 2 deduplicated metrics, got %d: %v", len(got), names(got))
	}
	byName := map[string]string{}
	for _, m := range got {
		byName[m.FullName] = m.Type
	}
	if byName["opnsense_exporter_logs_latency_seconds"] != "Histogram" {
		t.Errorf("histogram type: got %q", byName["opnsense_exporter_logs_latency_seconds"])
	}
	if byName["opnsense_exporter_logs_queue_length"] != "Gauge" {
		t.Errorf("gauge type: got %q", byName["opnsense_exporter_logs_queue_length"])
	}
}

func TestCouldNameSelfMetric(t *testing.T) {
	cases := []struct {
		prefix string
		want   bool
	}{
		{"", true},                       // nothing resolved yet, rule nothing out
		{"opnsense", true},               // + Subsystem "exporter" reaches us
		{"opnsense_exporter", true},      // exactly us
		{"opnsense_exporter_logs", true}, // already inside us
		{"opnsense_interfaces", false},   // firewall data, settled
		{"go", false},                    // client-library family
		{"opnsense_exporterish", false},  // near-miss must not count
	}
	for _, c := range cases {
		if got := couldNameSelfMetric(c.prefix); got != c.want {
			t.Errorf("couldNameSelfMetric(%q) = %v, want %v", c.prefix, got, c.want)
		}
	}
}

// TestSelfMetricInventoryIsCurrent guards the real tree: every self-metric declared in
// internal/ must be in the generated page. It is a cheap second opinion on
// `make docs-check`'s staleness diff, and it fails with the metric NAME rather than
// "file differs", which is what a reader actually needs.
func TestSelfMetricInventoryIsCurrent(t *testing.T) {
	root := findRepoRoot()
	metrics, err := collectSelfMetrics(root, filepath.Join(root, "internal"))
	if err != nil {
		t.Fatalf("scanning the real tree: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("scanned the real tree and found no self-metrics at all; the scanner is broken")
	}
	doc, err := os.ReadFile(filepath.Join(root, "docs", "metrics", "self-metrics.md"))
	if err != nil {
		t.Fatalf("reading the generated inventory: %v", err)
	}
	for _, m := range metrics {
		if !strings.Contains(string(doc), "| "+m.FullName+" |") {
			t.Errorf("%s is declared at %s:%d but missing from docs/metrics/self-metrics.md; run `make docs`",
				m.FullName, m.File, m.Line)
		}
	}
}
