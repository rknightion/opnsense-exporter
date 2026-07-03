package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rknightion/opnsense-exporter/internal/collector"
)

// output collects generated file contents. In check mode nothing is written;
// any difference from disk is recorded and reported as drift.
type output struct {
	checkMode bool
	repoRoot  string
	stale     []string
}

func (o *output) write(path string, content []byte) {
	if !o.checkMode {
		if err := os.WriteFile(path, content, 0o644); err != nil {
			fatal("writing %s: %v", path, err)
		}
		fmt.Fprintf(os.Stderr, "docgen: wrote %s\n", path)
		return
	}
	existing, err := os.ReadFile(path)
	if err != nil || string(existing) != string(content) {
		rel, relErr := filepath.Rel(o.repoRoot, path)
		if relErr != nil {
			rel = path
		}
		o.stale = append(o.stale, rel)
	}
}

// MetricInfo holds parsed information about a single Prometheus metric.
type MetricInfo struct {
	FullName  string
	Name      string // short name (without namespace/subsystem)
	Subsystem string
	Help      string
	Labels    []string
	Type      string // "Gauge" or "Counter"
}

// CollectorInfo holds information about a collector.
type CollectorInfo struct {
	Subsystem   string
	DisplayName string
	Metrics     []MetricInfo
	Flag        string // e.g., "--exporter.disable-arp-table"
	EnvVar      string // e.g., "OPNSENSE_EXPORTER_DISABLE_ARP_TABLE"
	Default     string // "Enabled" or "Disabled"
}

// FlagInfo holds parsed flag information from collectors.go.
type FlagInfo struct {
	FlagName string
	EnvVar   string
	Default  string // "Enabled" or "Disabled"
}

func main() {
	checkMode := flag.Bool("check", false, "verify generated docs are current; write nothing, exit non-zero on drift")
	flag.Parse()

	repoRoot := findRepoRoot()
	out := &output{checkMode: *checkMode, repoRoot: repoRoot}

	fmt.Fprintf(os.Stderr, "docgen: repo root = %s\n", repoRoot)

	collectorDir := filepath.Join(repoRoot, "internal", "collector")

	// Step 1: Parse subsystem constants from collector.go
	subsystemConstants := parseSubsystemConstants(filepath.Join(collectorDir, "collector.go"))
	fmt.Fprintf(os.Stderr, "docgen: parsed %d subsystem constants\n", len(subsystemConstants))

	// Step 2: Derive flag mappings from kingpin model + options.CollectorFlags.
	allFlags := collectAllFlags()
	flagsBySubsystem := collectorFlagInfo(allFlags)
	fmt.Fprintf(os.Stderr, "docgen: parsed %d flag mappings\n", len(flagsBySubsystem))

	// Step 3: Parse top-level metrics from collector.go
	topLevelMetrics := parseTopLevelMetrics(filepath.Join(collectorDir, "collector.go"))
	fmt.Fprintf(os.Stderr, "docgen: parsed %d top-level metrics\n", len(topLevelMetrics))

	// Step 4: Parse all collector files for buildPrometheusDesc calls
	collectors := parseAllCollectors(collectorDir, subsystemConstants)
	fmt.Fprintf(os.Stderr, "docgen: parsed %d collectors\n", len(collectors))

	// Gate: every metric the live collectors describe must be present in the
	// AST-parsed set, or the generated docs are missing real metrics.
	if err := verifyMetricsAgainstRegistry(collectors); err != nil {
		fatal("%v", err)
	}
	fmt.Fprintf(os.Stderr, "docgen: registry verification passed\n")

	// Attach flag info to collectors
	for i, c := range collectors {
		if fi, ok := flagsBySubsystem[c.Subsystem]; ok {
			collectors[i].Flag = fi.FlagName
			collectors[i].EnvVar = fi.EnvVar
			collectors[i].Default = fi.Default
		}
	}

	// Sort collectors alphabetically by display name
	sort.Slice(collectors, func(i, j int) bool {
		return collectors[i].DisplayName < collectors[j].DisplayName
	})

	// Count totals
	totalMetrics := len(topLevelMetrics)
	totalGauges := 0
	totalCounters := 0
	for _, m := range topLevelMetrics {
		if m.Type == "Counter" {
			totalCounters++
		} else {
			totalGauges++
		}
	}
	for _, c := range collectors {
		totalMetrics += len(c.Metrics)
		for _, m := range c.Metrics {
			if m.Type == "Counter" {
				totalCounters++
			} else {
				totalGauges++
			}
		}
	}

	// Step 5: Generate output files
	if err := os.MkdirAll(filepath.Join(repoRoot, "docs", "metrics"), 0o755); err != nil {
		fatal("creating docs/metrics dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(repoRoot, "docs", "collectors"), 0o755); err != nil {
		fatal("creating docs/collectors dir: %v", err)
	}

	generateMetricsDoc(out, filepath.Join(repoRoot, "docs", "metrics", "metrics.md"),
		topLevelMetrics, collectors, totalMetrics, totalGauges, totalCounters)

	generateCollectorReference(out, filepath.Join(repoRoot, "docs", "collectors", "reference.md"),
		collectors)

	// Step 6: Inject generated flag tables into docs/configuration.md.
	injectConfigurationDoc(out, allFlags)

	// Step 7: Inject the generated dashboard tab-name list into prose that enumerates tabs.
	dashMetrics, dashTabs, tabNames := loadDashboardStats(repoRoot)
	injectDashboardTabs(out, tabNames)

	// Step 8: Pin metric/collector/dashboard/rule counts across prose and config.
	alerts, recording := loadRulesStats(repoRoot)
	applyStatRules(out, statRules(docStats{
		Metrics:     totalMetrics,
		Collectors:  len(collectors),
		DashMetrics: dashMetrics,
		DashTabs:    dashTabs,
		Alerts:      alerts,
		Recording:   recording,
	}))

	// Step 8: Lint every flag/env-var token in prose docs against the model.
	if problems := runDoclint(repoRoot, allFlags); len(problems) > 0 {
		fatal("doclint found %d problems:\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	fmt.Fprintf(os.Stderr, "docgen: doclint passed\n")

	if *checkMode {
		if len(out.stale) > 0 {
			fatal("generated docs are stale, run 'make docs':\n  %s", strings.Join(out.stale, "\n  "))
		}
		fmt.Fprintf(os.Stderr, "docgen: check passed — all generated docs current\n")
	}

	fmt.Fprintf(os.Stderr, "docgen: done! Total metrics: %d (Gauges: %d, Counters: %d)\n",
		totalMetrics, totalGauges, totalCounters)
}

// injectConfigurationDoc fills every docgen marker region in
// docs/configuration.md with tables rendered from the kingpin model.
func injectConfigurationDoc(out *output, allFlags []FlagDoc) {
	tables := renderFlagTables(allFlags)
	configPath := filepath.Join(out.repoRoot, "docs", "configuration.md")
	raw, err := os.ReadFile(configPath)
	if err != nil {
		fatal("reading %s: %v", configPath, err)
	}
	doc := string(raw)
	for _, region := range []string{
		"flags-connection", "flags-exporter", "flags-pyroscope", "flags-otlp",
		"flags-collectors-default-on", "flags-collectors-opt-in",
		"flags-collectors-details", "flags-full-reference",
	} {
		doc, err = injectRegion(doc, region, tables[region])
		if err != nil {
			fatal("%v", err)
		}
	}
	out.write(configPath, []byte(doc))
}

// injectDashboardTabs fills the docgen:dashboard-tabs marker region in grafana/README.md and
// docs/integration-dashboards.md with the ordered tab-name list from the dashboard build, so the
// hand-typed enumerations can't drift from the actual tabs (#116).
func injectDashboardTabs(out *output, tabNames []string) {
	content := strings.Join(tabNames, ", ")
	for _, file := range []string{"grafana/README.md", "docs/integration-dashboards.md"} {
		path := filepath.Join(out.repoRoot, file)
		raw, err := os.ReadFile(path)
		if err != nil {
			fatal("reading %s: %v", path, err)
		}
		doc, err := injectRegion(string(raw), "dashboard-tabs", content)
		if err != nil {
			fatal("%s: %v", file, err)
		}
		out.write(path, []byte(doc))
	}
}

func findRepoRoot() string {
	// Walk up from cwd looking for go.mod
	dir, err := os.Getwd()
	if err != nil {
		fatal("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			fatal("could not find repo root (no go.mod found)")
		}
		dir = parent
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "docgen: FATAL: "+format+"\n", args...)
	os.Exit(1)
}

// parseSubsystemConstants parses collector.go and extracts all XxxSubsystem = "value" constants.
func parseSubsystemConstants(filePath string) map[string]string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filePath, nil, 0)
	if err != nil {
		fatal("parsing %s: %v", filePath, err)
	}

	result := make(map[string]string)
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if !strings.HasSuffix(name.Name, "Subsystem") {
					continue
				}
				if i < len(vs.Values) {
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						result[name.Name] = strings.Trim(lit.Value, `"`)
					}
				}
			}
		}
	}
	return result
}

// parseTopLevelMetrics parses collector.go New() function for prometheus.NewGauge and NewCounterVec calls.
func parseTopLevelMetrics(filePath string) []MetricInfo {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filePath, nil, 0)
	if err != nil {
		fatal("parsing %s: %v", filePath, err)
	}

	var metrics []MetricInfo

	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "New" {
			return true
		}

		// Walk through the function body looking for assignments
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}

			for _, rhs := range assign.Rhs {
				var call *ast.CallExpr

				switch v := rhs.(type) {
				case *ast.CallExpr:
					call = v
				case *ast.StarExpr:
					// Handle *prometheus.NewCounterVec(...)
					if c, ok := v.X.(*ast.CallExpr); ok {
						call = c
					}
				}

				if call == nil {
					continue
				}

				funcName := callExprFuncName(call)
				if funcName == "" {
					continue
				}

				switch funcName {
				case "prometheus.NewGauge", "NewGauge":
					m := parseGaugeOpts(call)
					if m != nil {
						m.Type = "Gauge"
						metrics = append(metrics, *m)
					}
				case "prometheus.NewCounterVec", "NewCounterVec":
					m := parseCounterVecOpts(call)
					if m != nil {
						m.Type = "Counter"
						metrics = append(metrics, *m)
					}
				case "prometheus.NewDesc", "NewDesc":
					// Const-metric descriptors (e.g. exporter build_info,
					// collector_enabled) emitted via MustNewConstMetric. These are
					// gauges by construction.
					m := parseNewDescOpts(call)
					if m != nil {
						m.Type = "Gauge"
						metrics = append(metrics, *m)
					}
				}
			}
			return true
		})

		return false
	})

	return metrics
}

func callExprFuncName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		if ident, ok := fn.X.(*ast.Ident); ok {
			return ident.Name + "." + fn.Sel.Name
		}
	case *ast.Ident:
		return fn.Name
	}
	return ""
}

func parseGaugeOpts(call *ast.CallExpr) *MetricInfo {
	if len(call.Args) < 1 {
		return nil
	}
	comp, ok := call.Args[0].(*ast.CompositeLit)
	if !ok {
		return nil
	}
	return parsePrometheusOpts(comp, nil)
}

func parseCounterVecOpts(call *ast.CallExpr) *MetricInfo {
	if len(call.Args) < 2 {
		return nil
	}
	comp, ok := call.Args[0].(*ast.CompositeLit)
	if !ok {
		return nil
	}

	// Parse labels from second argument
	var labels []string
	if compLit, ok := call.Args[1].(*ast.CompositeLit); ok {
		for _, elt := range compLit.Elts {
			if lit, ok := elt.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				l := strings.Trim(lit.Value, `"`)
				if l != "opnsense_instance" {
					labels = append(labels, l)
				}
			}
		}
	}

	return parsePrometheusOpts(comp, labels)
}

// parseNewDescOpts parses a prometheus.NewDesc(fqName, help, variableLabels, constLabels)
// call. The fqName is typically prometheus.BuildFQName(namespace, subsystem, name). Only
// string-literal label elements are captured; the trailing instanceLabelName identifier is
// naturally skipped (matching the convention used elsewhere in the exporter).
func parseNewDescOpts(call *ast.CallExpr) *MetricInfo {
	if len(call.Args) < 3 {
		return nil
	}

	fullName := extractFQName(call.Args[0])
	if fullName == "" {
		return nil
	}

	m := &MetricInfo{
		FullName: fullName,
		Help:     stringLitValue(call.Args[1]),
	}

	if compLit, ok := call.Args[2].(*ast.CompositeLit); ok {
		for _, elt := range compLit.Elts {
			if lit, ok := elt.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				l := strings.Trim(lit.Value, `"`)
				if l != "opnsense_instance" {
					m.Labels = append(m.Labels, l)
				}
			}
		}
	}

	return m
}

// extractFQName resolves a metric fully-qualified name from either a string literal or a
// prometheus.BuildFQName(namespace, subsystem, name) call.
func extractFQName(expr ast.Expr) string {
	if s := stringLitValue(expr); s != "" {
		return s
	}

	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return ""
	}
	switch callExprFuncName(call) {
	case "prometheus.BuildFQName", "BuildFQName":
	default:
		return ""
	}

	var parts []string
	for _, a := range call.Args {
		s := stringLitValue(a)
		if s == "" {
			return ""
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "_")
}

func parsePrometheusOpts(comp *ast.CompositeLit, extraLabels []string) *MetricInfo {
	m := &MetricInfo{}
	var ns, name string

	for _, elt := range comp.Elts {
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
			ns = stringLitValue(kv.Value)
		case "Name":
			name = stringLitValue(kv.Value)
		case "Help":
			m.Help = stringLitValue(kv.Value)
		}
	}

	if ns == "" {
		ns = "opnsense"
	}
	m.Name = name
	m.FullName = ns + "_" + name
	m.Labels = extraLabels

	return m
}

func stringLitValue(expr ast.Expr) string {
	if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		return strings.Trim(lit.Value, `"`)
	}
	// Could be an identifier reference
	if ident, ok := expr.(*ast.Ident); ok {
		if ident.Name == "namespace" {
			return "opnsense"
		}
	}
	return ""
}

// parseAllCollectors parses all collector Go files and extracts metrics.
func parseAllCollectors(dir string, subsystemConstants map[string]string) []CollectorInfo {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fatal("reading collector dir: %v", err)
	}

	var collectors []CollectorInfo
	skip := map[string]bool{
		"collector.go": true,
		"utils.go":     true,
	}

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		if skip[name] {
			continue
		}

		filePath := filepath.Join(dir, name)
		ci := parseCollectorFile(filePath, subsystemConstants)
		if ci != nil {
			collectors = append(collectors, *ci)
			fmt.Fprintf(os.Stderr, "docgen:   %s -> subsystem=%q metrics=%d\n",
				name, ci.Subsystem, len(ci.Metrics))
		}
	}

	return collectors
}

// parseCollectorFile parses a single collector Go file.
func parseCollectorFile(filePath string, subsystemConstants map[string]string) *CollectorInfo {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filePath, nil, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "docgen: warning: failed to parse %s: %v\n", filePath, err)
		return nil
	}

	// Find the subsystem from init() function
	subsystem := findSubsystem(f, subsystemConstants)
	if subsystem == "" {
		fmt.Fprintf(os.Stderr, "docgen: warning: no subsystem found in %s\n", filePath)
		return nil
	}

	// Find all buildPrometheusDesc calls
	metrics := findBuildPrometheusDescCalls(f, subsystem, fset)

	displayName, ok := collector.SubsystemDisplayNames[subsystem]
	if !ok {
		fatal("subsystem %q has no entry in collector.SubsystemDisplayNames", subsystem)
	}

	return &CollectorInfo{
		Subsystem:   subsystem,
		DisplayName: displayName,
		Metrics:     metrics,
	}
}

// findSubsystem walks the init() function looking for `subsystem: XxxSubsystem`.
func findSubsystem(f *ast.File, subsystemConstants map[string]string) string {
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "init" {
			continue
		}

		var subsystem string
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if subsystem != "" {
				return false
			}

			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}

			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "subsystem" {
				return true
			}

			// Value should be an identifier like GatewaysSubsystem
			if ident, ok := kv.Value.(*ast.Ident); ok {
				if val, exists := subsystemConstants[ident.Name]; exists {
					subsystem = val
				}
			}

			return true
		})

		if subsystem != "" {
			return subsystem
		}
	}
	return ""
}

// collectLocalStringSliceVars collects local variable definitions that are []string{...} literals.
// This handles patterns like: certLabels := []string{"description", "commonname", ...}
func collectLocalStringSliceVars(f *ast.File) map[string][]string {
	result := make(map[string][]string)

	ast.Inspect(f, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			ident, ok := lhs.(*ast.Ident)
			if !ok || i >= len(assign.Rhs) {
				continue
			}
			labels := extractLabelsFromComposite(assign.Rhs[i])
			if labels != nil {
				result[ident.Name] = labels
			}
		}
		return true
	})

	return result
}

// extractLabelsFromComposite extracts string slice elements from a composite literal.
func extractLabelsFromComposite(expr ast.Expr) []string {
	comp, ok := expr.(*ast.CompositeLit)
	if !ok {
		return nil
	}
	var labels []string
	for _, elt := range comp.Elts {
		if lit, ok := elt.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			labels = append(labels, strings.Trim(lit.Value, `"`))
		}
	}
	if len(labels) > 0 {
		return labels
	}
	return nil
}

// findBuildPrometheusDescCalls walks the AST for `<field> = buildPrometheusDesc(...)`
// assignments, deriving each metric's Prometheus type from the prometheus.{Counter,Gauge}Value
// argument at its MustNewConstMetric/NewConstMetric emission call site (#100). The desc field
// (e.g. c.servicesRunning) links the assignment to the emission. The historical `_total`-suffix
// heuristic is retained only as a fallback for descs whose emission site cannot be resolved
// statically (e.g. table-driven collectors that emit through a loop/local desc variable).
func findBuildPrometheusDescCalls(f *ast.File, subsystem string, fset *token.FileSet) []MetricInfo {
	var metrics []MetricInfo

	// Pre-collect local variable definitions for string slices
	localVars := collectLocalStringSliceVars(f)
	// Map desc-field name -> emitted Prometheus type, from this file's emission call sites.
	emittedTypes := collectEmittedValueTypes(f)

	ast.Inspect(f, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}

		for i, rhs := range assign.Rhs {
			call, ok := rhs.(*ast.CallExpr)
			if !ok {
				continue
			}
			// Check if this is a call to buildPrometheusDesc
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != "buildPrometheusDesc" {
				continue
			}
			if len(call.Args) < 4 {
				continue
			}

			// arg 0: subsystem (skip, we know it)
			// arg 1: name (string literal)
			name := extractStringArg(call.Args[1], fset)
			// arg 2: help (string literal, possibly multiline concatenation)
			help := extractStringArg(call.Args[2], fset)
			// arg 3: labels — []string{...}, nil, a local var, or an append(...) chain.
			labels := resolveLabelSlice(call.Args[3], localVars)

			fullName := "opnsense_" + subsystem + "_" + name

			// Resolve type from the emission ValueType via the LHS desc-field name; fall back to
			// the _total-suffix heuristic when the field/emission can't be resolved.
			metricType := ""
			if i < len(assign.Lhs) {
				if field := descFieldName(assign.Lhs[i]); field != "" {
					metricType = emittedTypes[field]
				}
			}
			if metricType == "" {
				metricType = "Gauge"
				if strings.HasSuffix(name, "_total") {
					metricType = "Counter"
				}
			}

			metrics = append(metrics, MetricInfo{
				FullName:  fullName,
				Name:      name,
				Subsystem: subsystem,
				Help:      help,
				Labels:    labels,
				Type:      metricType,
			})
		}

		return true
	})

	return metrics
}

// collectEmittedValueTypes maps a desc-field name (e.g. "servicesRunning", from `c.servicesRunning`)
// to the Prometheus type ("Counter"/"Gauge") of the prometheus.{Counter,Gauge}Value argument passed
// alongside it at a MustNewConstMetric/NewConstMetric call site. Descs emitted with UntypedValue, or
// with a conflicting type across call sites, are omitted so the caller falls back to the suffix
// heuristic.
func collectEmittedValueTypes(f *ast.File) map[string]string {
	out := map[string]string{}
	conflict := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name != "MustNewConstMetric" && sel.Sel.Name != "NewConstMetric" {
			return true
		}
		if len(call.Args) < 2 {
			return true
		}
		field := descFieldName(call.Args[0])
		if field == "" {
			return true
		}
		vt := valueTypeName(call.Args[1])
		if vt == "" {
			return true
		}
		if existing, seen := out[field]; seen && existing != vt {
			conflict[field] = true
		} else {
			out[field] = vt
		}
		return true
	})
	for field := range conflict {
		delete(out, field)
	}
	return out
}

// descFieldName returns the field/identifier name a desc expression refers to:
// c.servicesRunning -> "servicesRunning", or a bare local ident -> its name. Anything else -> "".
func descFieldName(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.SelectorExpr:
		return v.Sel.Name
	case *ast.Ident:
		return v.Name
	}
	return ""
}

// valueTypeName maps a prometheus.{Counter,Gauge}Value argument to "Counter"/"Gauge".
// prometheus.UntypedValue (and anything unrecognised) returns "".
func valueTypeName(expr ast.Expr) string {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	switch sel.Sel.Name {
	case "CounterValue":
		return "Counter"
	case "GaugeValue":
		return "Gauge"
	}
	return ""
}

// resolveLabelSlice statically evaluates a label-slice expression to its string values, folding the
// three shapes collectors use: a []string{...} literal, a local var reference (resolved via
// localVars), and append(...) chains such as append(append([]string{}, srcLabels...), "window")
// (#118). Returns nil for a nil argument or anything unresolvable, so the caller documents no labels.
func resolveLabelSlice(expr ast.Expr, localVars map[string][]string) []string {
	switch v := expr.(type) {
	case *ast.Ident:
		if v.Name == "nil" {
			return nil
		}
		return localVars[v.Name]
	case *ast.CompositeLit:
		var out []string
		for _, elt := range v.Elts {
			if lit, ok := elt.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				out = append(out, strings.Trim(lit.Value, `"`))
			}
		}
		return out
	case *ast.CallExpr:
		ident, ok := v.Fun.(*ast.Ident)
		if !ok || ident.Name != "append" {
			return nil
		}
		var out []string
		for i, arg := range v.Args {
			if i == 0 {
				out = append(out, resolveLabelSlice(arg, localVars)...) // base slice
				continue
			}
			// Later args: a string literal element, or a spread (srcLabels...) of a slice.
			if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				out = append(out, strings.Trim(lit.Value, `"`))
			} else {
				out = append(out, resolveLabelSlice(arg, localVars)...)
			}
		}
		return out
	}
	return nil
}

// extractStringArg extracts a string value from an AST expression.
// Handles basic literals, binary concatenation, and identifier references.
func extractStringArg(expr ast.Expr, fset *token.FileSet) string {
	switch v := expr.(type) {
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			return strings.Trim(v.Value, `"`)
		}
	case *ast.BinaryExpr:
		if v.Op == token.ADD {
			return extractStringArg(v.X, fset) + extractStringArg(v.Y, fset)
		}
	case *ast.Ident:
		// handle references to const identifiers if needed
		return ""
	}
	return ""
}

func formatLabels(labels []string) string {
	if len(labels) == 0 {
		return "---"
	}
	return strings.Join(labels, ", ")
}

func generateMetricsDoc(out *output, path string, topLevel []MetricInfo, collectors []CollectorInfo, totalMetrics, totalGauges, totalCounters int) {
	var b strings.Builder

	b.WriteString("<!-- This file is auto-generated by scripts/docgen. Do not edit manually. Run 'make docgen' to regenerate. -->\n\n")
	b.WriteString("# Complete Metrics Reference\n\n")
	b.WriteString("This page provides a complete reference of all Prometheus metrics exposed by the OPNsense Exporter.\n")
	b.WriteString("The `opnsense_instance` label is applied to all metrics.\n\n")

	b.WriteString("## Summary\n\n")
	fmt.Fprintf(&b, "- **Total metrics:** %d\n", totalMetrics)
	fmt.Fprintf(&b, "- **Gauges:** %d\n", totalGauges)
	fmt.Fprintf(&b, "- **Counters:** %d\n", totalCounters)
	b.WriteString("\n")

	// General section
	b.WriteString("## General\n\n")
	b.WriteString("| Metric Name | Type | Labels | Description |\n")
	b.WriteString("|-------------|------|--------|-------------|\n")
	for _, m := range topLevel {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
			m.FullName, m.Type, formatLabels(m.Labels), m.Help)
	}
	b.WriteString("\n")

	// Each collector section
	for _, c := range collectors {
		fmt.Fprintf(&b, "## %s\n\n", c.DisplayName)

		flagCol := "Disable Flag"
		if c.Default == "Disabled" {
			flagCol = "Enable Flag"
		}

		fmt.Fprintf(&b, "| Metric Name | Type | Labels | Description | %s |\n", flagCol)
		b.WriteString("|-------------|------|--------|-------------|")
		b.WriteString(strings.Repeat("-", len(flagCol)+2))
		b.WriteString("|\n")

		for _, m := range c.Metrics {
			flag := c.Flag
			if flag == "" {
				flag = "---"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
				m.FullName, m.Type, formatLabels(m.Labels), m.Help, flag)
		}
		b.WriteString("\n")
	}

	out.write(path, []byte(b.String()))
}

func generateCollectorReference(out *output, path string, collectors []CollectorInfo) {
	var b strings.Builder

	b.WriteString("<!-- This file is auto-generated by scripts/docgen. Do not edit manually. Run 'make docgen' to regenerate. -->\n\n")
	b.WriteString("# Collector Reference\n\n")
	b.WriteString("This page provides a summary of all collectors in the OPNsense Exporter.\n\n")
	b.WriteString("| Collector | Subsystem | Metrics | Default | Flag | Environment Variable |\n")
	b.WriteString("|-----------|-----------|---------|---------|------|---------------------|\n")

	for _, c := range collectors {
		flag := c.Flag
		if flag == "" {
			flag = "---"
		}
		envVar := c.EnvVar
		if envVar == "" {
			envVar = "---"
		}
		def := c.Default
		if def == "" {
			def = "Enabled"
		}
		fmt.Fprintf(&b, "| %s | %s | %d | %s | %s | %s |\n",
			c.DisplayName, c.Subsystem, len(c.Metrics), def, flag, envVar)
	}
	b.WriteString("\n")

	out.write(path, []byte(b.String()))
}
