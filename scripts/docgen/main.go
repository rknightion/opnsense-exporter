package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

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
	repoRoot := findRepoRoot()

	fmt.Fprintf(os.Stderr, "docgen: repo root = %s\n", repoRoot)

	collectorDir := filepath.Join(repoRoot, "internal", "collector")
	optionsFile := filepath.Join(repoRoot, "internal", "options", "collectors.go")

	// Step 1: Parse subsystem constants from collector.go
	subsystemConstants := parseSubsystemConstants(filepath.Join(collectorDir, "collector.go"))
	fmt.Fprintf(os.Stderr, "docgen: parsed %d subsystem constants\n", len(subsystemConstants))

	// Step 2: Parse flags from options/collectors.go
	flagsBySubsystem := parseFlagInfo(optionsFile, subsystemConstants)
	fmt.Fprintf(os.Stderr, "docgen: parsed %d flag mappings\n", len(flagsBySubsystem))

	// Step 3: Parse top-level metrics from collector.go
	topLevelMetrics := parseTopLevelMetrics(filepath.Join(collectorDir, "collector.go"))
	fmt.Fprintf(os.Stderr, "docgen: parsed %d top-level metrics\n", len(topLevelMetrics))

	// Step 4: Parse all collector files for buildPrometheusDesc calls
	collectors := parseAllCollectors(collectorDir, subsystemConstants)
	fmt.Fprintf(os.Stderr, "docgen: parsed %d collectors\n", len(collectors))

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

	generateMetricsDoc(filepath.Join(repoRoot, "docs", "metrics", "metrics.md"),
		topLevelMetrics, collectors, totalMetrics, totalGauges, totalCounters)

	generateCollectorReference(filepath.Join(repoRoot, "docs", "collectors", "reference.md"),
		collectors)

	fmt.Fprintf(os.Stderr, "docgen: done! Total metrics: %d (Gauges: %d, Counters: %d)\n",
		totalMetrics, totalGauges, totalCounters)
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

	return &CollectorInfo{
		Subsystem:   subsystem,
		DisplayName: subsystemToDisplayName(subsystem),
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

// findBuildPrometheusDescCalls walks the AST for calls to buildPrometheusDesc.
func findBuildPrometheusDescCalls(f *ast.File, subsystem string, fset *token.FileSet) []MetricInfo {
	var metrics []MetricInfo

	// Pre-collect local variable definitions for string slices
	localVars := collectLocalStringSliceVars(f)

	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Check if this is a call to buildPrometheusDesc
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || ident.Name != "buildPrometheusDesc" {
			return true
		}

		if len(call.Args) < 4 {
			return true
		}

		// arg 0: subsystem (skip, we know it)
		// arg 1: name (string literal)
		name := extractStringArg(call.Args[1], fset)
		// arg 2: help (string literal, possibly multiline concatenation)
		help := extractStringArg(call.Args[2], fset)
		// arg 3: labels ([]string{...} or nil or variable reference)
		labels := extractLabelsArg(call.Args[3])
		// If labels is nil and arg is an identifier, try resolving from local vars
		if labels == nil {
			if varIdent, ok := call.Args[3].(*ast.Ident); ok && varIdent.Name != "nil" {
				if resolved, exists := localVars[varIdent.Name]; exists {
					labels = resolved
				}
			}
		}

		fullName := "opnsense_" + subsystem + "_" + name

		metricType := "Gauge"
		if strings.HasSuffix(name, "_total") {
			metricType = "Counter"
		}

		metrics = append(metrics, MetricInfo{
			FullName:  fullName,
			Name:      name,
			Subsystem: subsystem,
			Help:      help,
			Labels:    labels,
			Type:      metricType,
		})

		return true
	})

	return metrics
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

// extractLabelsArg extracts labels from a []string{...} composite literal or nil.
func extractLabelsArg(expr ast.Expr) []string {
	// Check for nil
	if ident, ok := expr.(*ast.Ident); ok && ident.Name == "nil" {
		return nil
	}

	// Check for variable reference (e.g. certLabels)
	if _, ok := expr.(*ast.Ident); ok {
		// We can't resolve this statically, but we handle known cases
		return nil
	}

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
	return labels
}

// parseFlagInfo parses internal/options/collectors.go to extract flag names and env vars.
func parseFlagInfo(filePath string, subsystemConstants map[string]string) map[string]FlagInfo {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filePath, nil, 0)
	if err != nil {
		fatal("parsing %s: %v", filePath, err)
	}

	result := make(map[string]FlagInfo)

	// We need to manually map flag names to subsystems since the code doesn't
	// directly reference subsystem constants. We'll build the mapping from the
	// known patterns.
	flagToSubsystem := map[string]string{
		"exporter.disable-arp-table":              "arp_table",
		"exporter.disable-cron-table":             "cron",
		"exporter.disable-wireguard":              "wireguard",
		"exporter.disable-ipsec":                  "ipsec",
		"exporter.disable-unbound":                "unbound_dns",
		"exporter.disable-openvpn":                "openvpn",
		"exporter.disable-firewall":               "firewall",
		"exporter.disable-firmware":               "firmware",
		"exporter.disable-system":                 "system",
		"exporter.disable-temperature":            "temperature",
		"exporter.disable-dnsmasq":                "dnsmasq",
		"exporter.disable-firewall-rules":         "firewall_rule",
		"exporter.disable-mbuf":                   "mbuf",
		"exporter.disable-ntp":                    "ntp",
		"exporter.disable-certificates":           "certificate",
		"exporter.disable-carp":                   "carp",
		"exporter.disable-activity":               "activity",
		"exporter.disable-kea":                    "kea",
		"exporter.enable-network-diagnostics":     "network_diag",
		"exporter.enable-netflow":                 "netflow",
		"exporter.disable-pf-stats":               "pf_stats",
		"exporter.disable-ndp":                    "ndp",
		"exporter.enable-dnsmasq-details":         "dnsmasq",
		"exporter.enable-kea-details":             "kea",
		"exporter.enable-firewall-rules-details":  "firewall_rule",
	}

	// Parse all var declarations to find kingpin.Flag chains
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, val := range vs.Values {
				// The value is the outermost call like .Bool()
				flagName, envVar, defaultVal := extractFlagChain(val)
				if flagName == "" {
					continue
				}

				subsystem, ok := flagToSubsystem[flagName]
				if !ok {
					continue
				}

				// Skip detail flags - they don't represent the collector enable/disable
				if strings.Contains(flagName, "-details") {
					continue
				}

				isEnable := strings.Contains(flagName, "enable-")

				var def string
				if isEnable {
					// enable-xxx defaults to false -> Disabled by default
					if defaultVal == "false" {
						def = "Disabled"
					} else {
						def = "Enabled"
					}
				} else {
					// disable-xxx defaults to false -> Enabled by default
					if defaultVal == "false" {
						def = "Enabled"
					} else {
						def = "Disabled"
					}
				}

				result[subsystem] = FlagInfo{
					FlagName: "--" + flagName,
					EnvVar:   envVar,
					Default:  def,
				}
			}
		}
	}

	// Also add entries for gateways, interfaces, services, protocol which have no disable flag
	// (they are always enabled)
	for _, constName := range []string{"GatewaysSubsystem", "InterfacesSubsystem", "ServicesSubsystem", "ProtocolSubsystem"} {
		if val, ok := subsystemConstants[constName]; ok {
			if _, exists := result[val]; !exists {
				result[val] = FlagInfo{
					FlagName: "",
					EnvVar:   "",
					Default:  "Enabled",
				}
			}
		}
	}

	return result
}

// extractFlagChain walks a chained method call to find kingpin.Flag("name", "desc").Envar("ENV").Default("val")
func extractFlagChain(expr ast.Expr) (flagName, envVar, defaultVal string) {
	// The expression is the outermost call in a chain like:
	// kingpin.Flag("name", "desc").Envar("ENV").Default("false").Bool()
	// Walk down the chain to find all method calls.
	type chainLink struct {
		method string
		args   []ast.Expr
	}

	var chain []chainLink
	current, ok := expr.(*ast.CallExpr)
	if !ok {
		return "", "", ""
	}

	for {
		sel, ok := current.Fun.(*ast.SelectorExpr)
		if !ok {
			break
		}

		chain = append(chain, chainLink{
			method: sel.Sel.Name,
			args:   current.Args,
		})

		// Move to the receiver
		innerCall, ok := sel.X.(*ast.CallExpr)
		if !ok {
			break
		}
		current = innerCall
	}

	// Now check if current is kingpin.Flag(...)
	if sel, ok := current.Fun.(*ast.SelectorExpr); ok {
		if ident, ok := sel.X.(*ast.Ident); ok {
			if ident.Name == "kingpin" && sel.Sel.Name == "Flag" {
				if len(current.Args) >= 1 {
					flagName = extractStringLit(current.Args[0])
				}
			}
		}
	}

	if flagName == "" {
		return "", "", ""
	}

	// Extract Envar and Default from the chain
	for _, link := range chain {
		switch link.method {
		case "Envar":
			if len(link.args) >= 1 {
				envVar = extractStringLit(link.args[0])
			}
		case "Default":
			if len(link.args) >= 1 {
				defaultVal = extractStringLit(link.args[0])
			}
		}
	}

	return flagName, envVar, defaultVal
}

func extractStringLit(expr ast.Expr) string {
	if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		return strings.Trim(lit.Value, `"`)
	}
	return ""
}

func subsystemToDisplayName(subsystem string) string {
	displayNames := map[string]string{
		"arp_table":    "ARP Table",
		"gateways":     "Gateways",
		"cron":         "Cron",
		"wireguard":    "Wireguard",
		"ipsec":        "IPsec",
		"unbound_dns":  "Unbound DNS",
		"interfaces":   "Interfaces",
		"protocol":     "Protocol Statistics",
		"openvpn":      "OpenVPN",
		"services":     "Services",
		"firewall":     "Firewall",
		"firmware":     "Firmware",
		"dnsmasq":      "Dnsmasq DHCP",
		"system":       "System",
		"temperature":  "Temperature",
		"firewall_rule": "Firewall Rules",
		"mbuf":         "Mbuf",
		"ntp":          "NTP",
		"certificate":  "Certificates",
		"carp":         "CARP",
		"activity":     "Activity",
		"kea":          "Kea DHCP",
		"network_diag": "Network Diagnostics",
		"netflow":      "NetFlow",
		"pf_stats":     "PF Statistics",
		"ndp":          "NDP",
	}

	if name, ok := displayNames[subsystem]; ok {
		return name
	}
	return subsystem
}

func formatLabels(labels []string) string {
	if len(labels) == 0 {
		return "---"
	}
	return strings.Join(labels, ", ")
}

func generateMetricsDoc(path string, topLevel []MetricInfo, collectors []CollectorInfo, totalMetrics, totalGauges, totalCounters int) {
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

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		fatal("writing %s: %v", path, err)
	}
	fmt.Fprintf(os.Stderr, "docgen: wrote %s\n", path)
}

func generateCollectorReference(path string, collectors []CollectorInfo) {
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

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		fatal("writing %s: %v", path, err)
	}
	fmt.Fprintf(os.Stderr, "docgen: wrote %s\n", path)
}
