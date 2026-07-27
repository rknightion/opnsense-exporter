package main

// Self-metric inventory (#428).
//
// WHY THIS EXISTS. The Grafana coverage gate reads its catalogue from
// docs/metrics/metrics.md, which docgen fills by walking the COLLECTOR registry.
// Every metric the exporter emits about ITSELF from outside internal/collector is
// therefore invisible to that gate: the whole opnsense_exporter_logs_* family (with
// its enrich/, capture/, zenarmor/ and receiver sub-families), the four
// opnsense_exporter_annotations_* metrics, and the opnsense_exporter_otlp_* delivery
// series. Thirty metrics could ship with no panel, no alert and no complaint from CI,
// while grafana/README.md claimed coverage of "every metric the exporter emits".
//
// WHY A SOURCE SCAN RATHER THAN A REGISTRY GATHER. The obvious alternative is to
// construct the self-metrics registry the way main.go does and read Describe() off it.
// That was rejected: it reproduces the composition root, and a self-metric registered
// through a path the reproduction happens not to build is silently absent from the
// inventory — which is precisely the failure mode this file exists to end. A
// declaration cannot hide from an AST walk, however it is later wired.
//
// WHY UNRESOLVABLE IS A HARD ERROR. The scan resolves Namespace/Subsystem/Name to
// constant strings. If it cannot, and the resolvable parts do not rule out the
// opnsense_exporter namespace, docgen FAILS rather than omitting the metric. Skipping
// what it cannot understand would leave a bypass: build the name from a variable and
// the gate stops seeing you. The error names the file and line so the fix is either to
// use a constant or to widen this resolver deliberately.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// selfMetricNamespace is the prefix that makes a metric the EXPORTER's own rather than
// the firewall's. internal/collector uses namespace "opnsense" for firewall data and
// this prefix for its own meta metrics; everything else in internal/ that registers a
// metric at all registers a self-metric.
const selfMetricNamespace = "opnsense_exporter"

// SelfMetric is one metric the exporter emits about itself, as declared in source.
type SelfMetric struct {
	FullName string
	Type     string // Counter, Gauge, Histogram, Summary, or Desc
	Package  string // repo-relative directory of the declaring file
	File     string // repo-relative path
	Line     int
}

// constScope maps a constant identifier to its string value. It is per-PACKAGE and
// flat: package-level and function-local consts share one namespace here.
//
// Per-package rather than per-file is load-bearing, not tidiness. `namespace` is
// declared once in internal/collector/collector.go and used by the shared descriptor
// helper in internal/collector/utils.go; scoped per file, that helper's namespace
// looked unresolvable and the hard-error rule below failed the build on the exporter's
// most ordinary metric declaration. Flattening function-local consts in is imprecise
// under shadowing but cannot produce a WRONG name — it would take two different string
// constants sharing an identifier in one package, and every namespace constant in this
// tree is the literal "opnsense_exporter".
type constScope map[string]string

// collectSelfMetrics walks dir for non-test Go files and returns every declared metric
// in the exporter's own namespace, sorted by name.
func collectSelfMetrics(repoRoot, dir string) ([]SelfMetric, error) {
	var found []SelfMetric
	fset := token.NewFileSet()

	// Group by directory so each package's constants are resolved together.
	byDir := map[string][]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		pkgDir := filepath.Dir(path)
		byDir[pkgDir] = append(byDir[pkgDir], path)
		return nil
	})
	if err != nil {
		return nil, err
	}

	dirs := make([]string, 0, len(byDir))
	for d := range byDir {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)

	for _, pkgDir := range dirs {
		paths := byDir[pkgDir]
		sort.Strings(paths)

		parsed := make([]*ast.File, 0, len(paths))
		scope := constScope{}
		for _, path := range paths {
			file, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil, fmt.Errorf("parsing %s: %w", path, perr)
			}
			parsed = append(parsed, file)
			collectStringConsts(file, scope)
		}

		for i, file := range parsed {
			rel, rerr := filepath.Rel(repoRoot, paths[i])
			if rerr != nil {
				rel = paths[i]
			}
			metrics, serr := scanFileForSelfMetrics(fset, file, rel, scope)
			if serr != nil {
				return nil, serr
			}
			found = append(found, metrics...)
		}
	}

	sort.Slice(found, func(i, j int) bool {
		if found[i].FullName != found[j].FullName {
			return found[i].FullName < found[j].FullName
		}
		return found[i].File < found[j].File
	})
	return dedupeSelfMetrics(found), nil
}

// dedupeSelfMetrics collapses repeat declarations of the same name. A name declared
// twice is not an error here: pre-initialisation helpers and per-source constructors
// legitimately name the same metric more than once, and the inventory cares about the
// SET of names the process can emit.
func dedupeSelfMetrics(in []SelfMetric) []SelfMetric {
	out := make([]SelfMetric, 0, len(in))
	for _, m := range in {
		if len(out) > 0 && out[len(out)-1].FullName == m.FullName {
			continue
		}
		out = append(out, m)
	}
	return out
}

func scanFileForSelfMetrics(fset *token.FileSet, file *ast.File, rel string, scope constScope) ([]SelfMetric, error) {
	pkgDir := filepath.ToSlash(filepath.Dir(rel))

	var found []SelfMetric
	var scanErr error

	record := func(name, typ string, pos token.Pos) {
		if !strings.HasPrefix(name, selfMetricNamespace+"_") {
			return
		}
		found = append(found, SelfMetric{
			FullName: name,
			Type:     typ,
			Package:  pkgDir,
			File:     filepath.ToSlash(rel),
			Line:     fset.Position(pos).Line,
		})
	}

	ast.Inspect(file, func(n ast.Node) bool {
		if scanErr != nil {
			return false
		}
		switch node := n.(type) {
		case *ast.CompositeLit:
			typ, ok := prometheusOptsKind(node.Type)
			if !ok {
				return true
			}
			name, err := resolveOptsName(node, scope, fset, rel)
			if err != nil {
				scanErr = err
				return false
			}
			if name != "" {
				record(name, typ, node.Pos())
			}
		case *ast.CallExpr:
			if !isPrometheusCall(node.Fun, "NewDesc") || len(node.Args) == 0 {
				return true
			}
			name, ok := resolveString(node.Args[0], scope)
			if !ok {
				// Only an error if the exporter namespace is still in play. A desc
				// built by a generic helper from function parameters names a
				// FIREWALL metric (namespace "opnsense"), and those already reach
				// the catalogue through docgen's collector walk.
				if mayBeSelfMetric(node.Args[0], scope) && !dynamicNameSites[filepath.ToSlash(rel)] {
					scanErr = fmt.Errorf(
						"%s:%d: prometheus.NewDesc name does not resolve to a constant string; "+
							"the self-metric inventory (#428) cannot see it. Use a constant, or widen "+
							"resolveString in scripts/docgen/selfmetrics.go deliberately",
						rel, fset.Position(node.Args[0].Pos()).Line)
					return false
				}
				return true
			}
			record(name, "Desc", node.Pos())
		}
		return true
	})

	return found, scanErr
}

// resolveOptsName builds the fully-qualified name from a prometheus.XxxOpts literal.
// It returns "" for a literal that provably belongs to another namespace, and an error
// for one whose name cannot be determined but might be a self-metric.
func resolveOptsName(lit *ast.CompositeLit, scope constScope, fset *token.FileSet, rel string) (string, error) {
	var ns, sub, name string
	nsOK, subOK, nameOK := true, true, true
	sawNS := false

	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "Namespace":
			sawNS = true
			ns, nsOK = resolveString(kv.Value, scope)
		case "Subsystem":
			sub, subOK = resolveString(kv.Value, scope)
		case "Name":
			name, nameOK = resolveString(kv.Value, scope)
		}
	}

	// Only a resolved prefix that CANNOT extend into our namespace settles it. The
	// naive test — namespace != "opnsense_exporter" — was wrong and silently lost
	// seven metrics: internal/collector declares its meta family as
	// Namespace "opnsense" + Subsystem "exporter", which composes to exactly the
	// self-metric prefix. Rule out on the composed prefix, never on one field.
	if sawNS && nsOK && !couldNameSelfMetric(joinNonEmpty(ns, sub)) {
		return "", nil
	}
	if !nsOK || !subOK || !nameOK {
		return "", fmt.Errorf(
			"%s:%d: prometheus metric Opts has a Namespace/Subsystem/Name that does not resolve "+
				"to a constant string; the self-metric inventory (#428) cannot see it. Use a "+
				"constant, or widen resolveString in scripts/docgen/selfmetrics.go deliberately",
			rel, fset.Position(lit.Pos()).Line)
	}

	return joinNonEmpty(ns, sub, name), nil
}

func joinNonEmpty(parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, "_")
}

// couldNameSelfMetric reports whether a metric name beginning with the given resolved
// prefix could still land in the exporter's own namespace once its remaining parts are
// appended. An empty prefix rules nothing out.
func couldNameSelfMetric(prefix string) bool {
	if prefix == "" {
		return true
	}
	full := selfMetricNamespace + "_"
	p := prefix + "_"
	// Either the prefix is a step along the way to our namespace ("opnsense_"), or it
	// is already inside it ("opnsense_exporter_logs_").
	return strings.HasPrefix(full, p) || strings.HasPrefix(p, full)
}

// dynamicNameSites are the declaration sites permitted to build a metric name from
// values this scan cannot resolve. Keep this list at zero or one entry and justify
// every addition: each one is a hole in the guarantee that a declared metric cannot
// hide from the inventory.
//
// internal/collector/utils.go is the shared descriptor helper every SUB-COLLECTOR uses,
// so its subsystem and name arrive as function parameters by design. Those metrics are
// firewall metrics, and they already reach the coverage gate through the collector
// catalogue in docs/metrics/metrics.md — the registry walk in verify.go additionally
// cross-checks that catalogue against the real Describe() output, so nothing declared
// through this helper can go undocumented either.
var dynamicNameSites = map[string]bool{
	"internal/collector/utils.go": true,
}

// mayBeSelfMetric reports whether an unresolvable NewDesc argument could still name a
// metric in the exporter's namespace.
func mayBeSelfMetric(arg ast.Expr, scope constScope) bool {
	call, ok := arg.(*ast.CallExpr)
	if !ok || !isPrometheusCall(call.Fun, "BuildFQName") || len(call.Args) == 0 {
		return true
	}
	ns, ok := resolveString(call.Args[0], scope)
	if !ok {
		return true
	}
	return couldNameSelfMetric(ns)
}

// resolveString evaluates an expression to a compile-time string. It handles string
// literals, identifiers bound to string constants in the same file, concatenation of
// those, and prometheus.BuildFQName over resolvable arguments — which together cover
// every metric declaration in this tree. Anything else returns false, and the caller
// decides whether that is fatal.
func resolveString(expr ast.Expr, scope constScope) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		v, err := strconv.Unquote(e.Value)
		if err != nil {
			return "", false
		}
		return v, true
	case *ast.Ident:
		v, ok := scope[e.Name]
		return v, ok
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		l, lok := resolveString(e.X, scope)
		r, rok := resolveString(e.Y, scope)
		if !lok || !rok {
			return "", false
		}
		return l + r, true
	case *ast.ParenExpr:
		return resolveString(e.X, scope)
	case *ast.CallExpr:
		if !isPrometheusCall(e.Fun, "BuildFQName") || len(e.Args) != 3 {
			return "", false
		}
		parts := make([]string, 0, 3)
		for _, a := range e.Args {
			v, ok := resolveString(a, scope)
			if !ok {
				return "", false
			}
			if v != "" {
				parts = append(parts, v)
			}
		}
		return strings.Join(parts, "_"), true
	}
	return "", false
}

// collectStringConsts gathers every string-valued const in the file, including those
// declared inside function bodies — `const ns = "opnsense_exporter"` at the top of a
// constructor is the dominant form in internal/logship.
func collectStringConsts(file *ast.File, scope constScope) {
	ast.Inspect(file, func(n ast.Node) bool {
		decl, ok := n.(*ast.GenDecl)
		if !ok || decl.Tok != token.CONST {
			return true
		}
		for _, spec := range decl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				// Resolve against what is already known so a const defined in terms
				// of an earlier one still lands.
				if v, ok := resolveString(vs.Values[i], scope); ok {
					scope[ident.Name] = v
				}
			}
		}
		return true
	})
}

// prometheusOptsKind maps a prometheus.XxxOpts type expression to the metric type it
// declares. Vec constructors take the same Opts type as their scalar counterparts, so
// one table covers both.
func prometheusOptsKind(expr ast.Expr) (string, bool) {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "prometheus" {
		return "", false
	}
	switch sel.Sel.Name {
	case "CounterOpts":
		return "Counter", true
	case "GaugeOpts":
		return "Gauge", true
	case "HistogramOpts":
		return "Histogram", true
	case "SummaryOpts":
		return "Summary", true
	}
	return "", false
}

func isPrometheusCall(fun ast.Expr, name string) bool {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "prometheus"
}

// renderSelfMetrics produces docs/metrics/self-metrics.md. The Grafana coverage gate
// parses the same leading-pipe table shape it parses in metrics.md, so the first
// column must stay the bare metric name.
func renderSelfMetrics(metrics []SelfMetric) []byte {
	var b strings.Builder
	b.WriteString("# Exporter Self-Metrics\n\n")
	b.WriteString("<!-- Generated by scripts/docgen. Do not edit by hand; run `make docs`. -->\n\n")
	b.WriteString("Metrics the exporter emits about **itself** rather than about the firewall.\n\n")
	b.WriteString("This page is generated by scanning the source for Prometheus metric declarations, not by\n")
	b.WriteString("gathering a registry, so a metric appears here as soon as it is declared — whether or not\n")
	b.WriteString("the composition root happens to wire it up. The Grafana coverage gate\n")
	b.WriteString("(`make grafana-check`) reads this table alongside the collector catalogue, so a new\n")
	b.WriteString("self-metric fails CI until it is charted on the dashboard or given a justified\n")
	b.WriteString("exemption in `grafana/build_dashboard.py`.\n\n")
	b.WriteString("`go_*` and `process_*` are **not** listed: they come from the Prometheus client\n")
	b.WriteString("library's own collectors rather than from this codebase, they carry no\n")
	b.WriteString("`opnsense_instance` label, and they are charted from the Exporter Runtime row behind\n")
	b.WriteString("the `has_go_runtime` sentinel.\n\n")
	fmt.Fprintf(&b, "Total: %d self-metrics.\n\n", len(metrics))
	b.WriteString("| Metric | Type | Declared in |\n")
	b.WriteString("| --- | --- | --- |\n")
	for _, m := range metrics {
		fmt.Fprintf(&b, "| %s | %s | `%s` |\n", m.FullName, m.Type, m.Package)
	}
	return []byte(b.String())
}

// generateSelfMetrics writes the self-metric inventory page.
func generateSelfMetrics(out *output, repoRoot string) []SelfMetric {
	metrics, err := collectSelfMetrics(repoRoot, filepath.Join(repoRoot, "internal"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "docgen: self-metric inventory: %v\n", err)
		os.Exit(1)
	}
	out.write(filepath.Join(repoRoot, "docs", "metrics", "self-metrics.md"), renderSelfMetrics(metrics))
	return metrics
}
