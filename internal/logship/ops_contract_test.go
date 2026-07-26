package logship

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestOperationsSurfaceContract is deliberately a source-level guard. The metrics
// package is not the whole surface: receiver, enrichment, debug-capture, and
// Zenarmor constructors each own metrics too. A new logs_* constructor, closed
// reason/stage, or top-level flag therefore has to be given an explicit operator
// disposition here rather than quietly missing the hand-maintained dashboard/docs.
func TestOperationsSurfaceContract(t *testing.T) {
	root := repositoryRoot(t)
	doc := readContractFile(t, filepath.Join(root, "docs", "log-shipping.md"))
	dashboard := readContractFile(t, filepath.Join(root, "grafana", "tabs", "logs.py"))
	derivedDashboard := readContractFile(t, filepath.Join(root, "grafana", "tabs", "log_events.py"))

	for _, flag := range topLevelLogFlags(t, filepath.Join(root, "internal", "options", "logs.go")) {
		mustContain(t, doc, "--"+flag, "top-level log pipeline flag")
	}

	for _, reason := range dropReasons(t, filepath.Join(root, "internal", "logship", "metrics.go")) {
		mustContain(t, doc, "`"+reason+"`", "drop reason")
	}

	for _, path := range []string{
		filepath.Join(root, "internal", "logship", "syslog", "source.go"),
		filepath.Join(root, "internal", "logship", "zenarmor", "source.go"),
	} {
		for _, reason := range stringSliceVar(t, path, "RejectReasons") {
			mustContain(t, doc, "`"+reason+"`", "receiver reject reason")
		}
		for _, stage := range stringSliceVar(t, path, "ParseStages") {
			mustContain(t, doc, "`"+stage+"`", "receiver parse stage")
		}
	}

	// These are process timestamps, not source event times. Keep their admission vs
	// acknowledgement stages explicit because the old single last_event gauge made
	// a queued/retrying record look delivered.
	mustContain(t, doc, "opnsense_exporter_logs_last_received_timestamp_seconds", "receive timestamp metric")
	mustContain(t, doc, "opnsense_exporter_logs_last_exported_timestamp_seconds", "export timestamp metric")
	mustContain(t, doc, "admitted", "receive timestamp stage")
	mustContain(t, doc, "acknowledged", "export timestamp stage")
	mustContain(t, doc, "`opnsense_instance`", "stable instance label")

	// #393's bounded receiver-to-collector handoff is deliberately routed separately:
	// it belongs to the Log-derived Events collector, not the Log Shipping pipeline
	// tab. Its generated metric reference documents the metric itself and the derived
	// events tab exposes receiver-side saturation.
	mustContain(t, doc, "opnsense_log_events_observation_dropped_total", "#393 ops disposition")
	mustContain(t, strings.Join(strings.Fields(doc), " "), "not a Log Shipping pipeline self-metric", "#393 routing decision")
	mustContain(t, derivedDashboard, "opnsense_log_events_observation_dropped_total", "#393 dashboard disposition")

	for metric, disposition := range logMetricDispositions() {
		mustContain(t, doc, metric, "documented logship metric")
		if disposition == "dashboard" {
			mustContain(t, dashboard, metric, "dashboarded logship metric")
		}
	}
	for _, metric := range logMetricNames(t, filepath.Join(root, "internal", "logship")) {
		if _, ok := logMetricDispositions()[metric]; !ok {
			t.Fatalf("%s has no explicit dashboard/docs disposition; add it to logMetricDispositions", metric)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate ops_contract_test.go")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func readContractFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustContain(t *testing.T, text, want, what string) {
	t.Helper()
	if !strings.Contains(text, want) {
		t.Fatalf("%s %q is absent", what, want)
	}
}

func topLevelLogFlags(t *testing.T, path string) []string {
	t.Helper()
	text := readContractFile(t, path)
	matches := regexp.MustCompile(`kingpin\.Flag\(\s*"(logs\.[^"]+)"`).FindAllStringSubmatch(text, -1)
	flags := make([]string, 0, len(matches))
	for _, match := range matches {
		flags = append(flags, match[1])
	}
	return flags
}

func dropReasons(t *testing.T, path string) []string {
	t.Helper()
	text := readContractFile(t, path)
	matches := regexp.MustCompile(`dropReason\w+\s*=\s*"([^"]+)"`).FindAllStringSubmatch(text, -1)
	reasons := make([]string, 0, len(matches))
	for _, match := range matches {
		reasons = append(reasons, match[1])
	}
	return reasons
}

func stringSliceVar(t *testing.T, path, name string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || value.Names[0].Name != name || len(value.Values) != 1 {
				continue
			}
			lit, ok := value.Values[0].(*ast.CompositeLit)
			if !ok {
				t.Fatalf("%s is no longer a string slice", name)
			}
			values := make([]string, 0, len(lit.Elts))
			for _, elt := range lit.Elts {
				basic, ok := elt.(*ast.BasicLit)
				if !ok || basic.Kind != token.STRING {
					t.Fatalf("%s has a non-string vocabulary value", name)
				}
				parsed, err := strconv.Unquote(basic.Value)
				if err != nil {
					t.Fatal(err)
				}
				values = append(values, parsed)
			}
			return values
		}
	}
	t.Fatalf("could not find %s in %s", name, path)
	return nil
}

func logMetricNames(t *testing.T, dir string) []string {
	t.Helper()
	set := map[string]struct{}{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(node ast.Node) bool {
			kv, ok := node.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "Name" {
				return true
			}
			value, ok := kv.Value.(*ast.BasicLit)
			if !ok || value.Kind != token.STRING {
				return true
			}
			name, err := strconv.Unquote(value.Value)
			if err == nil && strings.HasPrefix(name, "logs_") {
				set["opnsense_exporter_"+name] = struct{}{}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	metrics := make([]string, 0, len(set))
	for metric := range set {
		metrics = append(metrics, metric)
	}
	sort.Strings(metrics)
	return metrics
}

func logMetricDispositions() map[string]string {
	return map[string]string{
		"opnsense_exporter_logs_shipped_total":                         "dashboard",
		"opnsense_exporter_logs_dropped_total":                         "dashboard",
		"opnsense_exporter_logs_ship_errors_total":                     "dashboard",
		"opnsense_exporter_logs_poll_errors_total":                     "dashboard",
		"opnsense_exporter_logs_last_received_timestamp_seconds":       "dashboard",
		"opnsense_exporter_logs_last_exported_timestamp_seconds":       "dashboard",
		"opnsense_exporter_logs_queue_length":                          "dashboard",
		"opnsense_exporter_logs_queue_capacity":                        "dashboard",
		"opnsense_exporter_logs_queue_bytes":                           "dashboard",
		"opnsense_exporter_logs_queue_max_bytes":                       "dashboard",
		"opnsense_exporter_logs_possible_gap_total":                    "dashboard",
		"opnsense_exporter_logs_resource_capped_total":                 "dashboard",
		"opnsense_exporter_logs_parse_errors_total":                    "dashboard",
		"opnsense_exporter_logs_rejected_total":                        "dashboard",
		"opnsense_exporter_logs_enrich_misses_total":                   "dashboard",
		"opnsense_exporter_logs_enrich_refresh_errors_total":           "dashboard",
		"opnsense_exporter_logs_enrich_last_refresh_timestamp_seconds": "dashboard",
		"opnsense_exporter_logs_debug_captured_total":                  "docs",
		"opnsense_exporter_logs_debug_capture_dropped_total":           "docs",
		"opnsense_exporter_logs_zenarmor_excluded_total":               "docs",
		"opnsense_exporter_logs_zenarmor_bulk_requests_total":          "docs",
		"opnsense_exporter_logs_zenarmor_bulk_bytes_total":             "docs",
	}
}
