// Package metriclint checks the naming contracts for Prometheus metrics declared
// by this repository.
//
// The exporter has two ways to declare a metric. Most collector metrics are
// descriptors created by buildPrometheusDesc and typed at a later
// MustNewConstMetric call. The receiver and telemetry packages use the
// prometheus.NewGauge/NewCounter option types directly. The scanner understands
// both forms and deliberately gets the type from that declaration/emission
// rather than guessing from a name suffix: Prometheus counters are expected to
// end in _total, even though their wire name is canonicalised by some bridges.
package metriclint

import (
	"errors"
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

// MetricKind is the source-level Prometheus type of a metric declaration.
type MetricKind string

const (
	KindUnknown   MetricKind = "Unknown"
	KindGauge     MetricKind = "Gauge"
	KindCounter   MetricKind = "Counter"
	KindHistogram MetricKind = "Histogram"
	KindSummary   MetricKind = "Summary"
	KindUntyped   MetricKind = "Untyped"
)

const (
	ruleGaugeTotal       = "gauge_total"
	ruleTimestamp        = "timestamp_suffix"
	legacyRuleMarker     = "OPN-0033"
	legacyGaugeTotalNote = "legacy current-count gauge"
	legacyTimestampNote  = "legacy Unix timestamp gauge"
)

// Metric is one source declaration found by ScanRepository.
type Metric struct {
	// Name is the fully-qualified name when the source makes it resolvable. For
	// a descriptor built by the collector helper it may contain just the local
	// name; LocalName is always the name passed to that helper when available.
	Name      string
	LocalName string
	Help      string
	Kind      MetricKind
	File      string
	Line      int

	// UnixTimestamp is set when the descriptor/help or its emission identifies
	// an absolute Unix timestamp rather than a duration or age.
	UnixTimestamp bool
}

// Violation is one naming-contract failure.
type Violation struct {
	Rule   string
	Metric Metric
}

func (v Violation) Error() string {
	name := v.Metric.Name
	if name == "" {
		name = v.Metric.LocalName
	}
	return fmt.Sprintf("%s:%d: %s metric %q (%s) violates %s",
		v.Metric.File, v.Metric.Line, v.Metric.Kind, name, v.Metric.Help, v.Rule)
}

// ReportError contains all violations found in one repository scan.
type ReportError struct {
	Violations []Violation
}

func (e *ReportError) Error() string {
	if len(e.Violations) == 0 {
		return "metric naming lint failed"
	}
	var b strings.Builder
	b.WriteString("metric naming lint found violations:")
	for _, violation := range e.Violations {
		b.WriteString("\n  ")
		b.WriteString(violation.Error())
	}
	return b.String()
}

// legacyAllowlist is intentionally keyed by source file and local metric name,
// not by a broad filename or a suffix. Every entry is a named compatibility
// debt item whose removal trigger is the breaking rename task OPN-0033.
//
// The initial entries are populated from the repository's pre-existing metric
// declarations. Keeping the list explicit makes a newly added declaration fail
// until somebody makes the compatibility decision in the same place.
var legacyAllowlist = map[string]string{
	"internal/collector/acme.go:certificates_total":                         "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/activity.go:threads_total":                          "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/alias.go:tables_total":                              "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/arp_table.go:entries_total":                         "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/bpf.go:listeners_total":                             "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/captiveportal.go:zones_total":                       "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/captiveportal.go:sessions_total":                    "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/captiveportal.go:voucher_group_next_expiry_seconds": "OPN-0033 removal trigger: legacy Unix timestamp gauge",
	"internal/collector/carp.go:vips_total":                                 "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/certificates.go:valid_from_seconds":                 "OPN-0033 removal trigger: legacy Unix timestamp gauge",
	"internal/collector/certificates.go:valid_to_seconds":                   "OPN-0033 removal trigger: legacy Unix timestamp gauge",
	"internal/collector/certificates.go:ca_valid_from_seconds":              "OPN-0033 removal trigger: legacy Unix timestamp gauge",
	"internal/collector/certificates.go:ca_valid_to_seconds":                "OPN-0033 removal trigger: legacy Unix timestamp gauge",
	"internal/collector/certificates.go:ca_total":                           "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/chrony.go:sources_total":                            "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/collector.go:series_total":                          "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/crowdsec.go:alerts_total":                           "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/crowdsec.go:decisions_total":                        "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/crowdsec.go:bouncers_total":                         "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/crowdsec.go:machines_total":                         "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/dhcpv4.go:leases_total":                             "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/dhcpv4.go:leases_reserved_total":                    "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/dhcpv4.go:leases_dynamic_total":                     "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/dhcpv6.go:leases_total":                             "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/dhcpv6.go:leases_reserved_total":                    "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/dhcpv6.go:leases_dynamic_total":                     "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/dhcpv6.go:pd_prefixes_total":                        "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/dnsmasq.go:leases_total":                            "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/dnsmasq.go:leases_reserved_total":                   "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/dnsmasq.go:leases_dynamic_total":                    "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/dyndns.go:accounts_total":                           "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/firewall_rules.go:rules_total":                      "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/frr.go:bgp_peers_total":                             "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/frr.go:ospf_neighbors_total":                        "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/frr.go:bfd_peers_total":                             "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/hasync.go:remote_services_total":                    "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/ids.go:installed_rules_total":                       "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/kea.go:dhcp4_leases_total":                          "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/kea.go:dhcp4_leases_reserved_total":                 "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/kea.go:dhcp4_leases_dynamic_total":                  "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/kea.go:dhcp6_leases_total":                          "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/kea.go:dhcp6_leases_reserved_total":                 "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/kea.go:dhcp6_leases_dynamic_total":                  "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/mbuf.go:cluster_total":                              "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/mbuf.go:pool_total":                                 "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/mbuf.go:bytes_total":                                "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/monit.go:checks_total":                              "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/ndp.go:entries_total":                               "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/netbird.go:relays_total":                            "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/netbird.go:peers_total":                             "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/network_diag.go:sockets_unix_total":                 "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/network_diag.go:routes_total":                       "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/network_diag.go:pfsync_nodes_total":                 "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/ntp.go:peers_total":                                 "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/openvpn.go:sessions_total":                          "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/qfeeds.go:feeds_total":                              "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/services.go:running_total":                          "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/services.go:stopped_total":                          "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/smart.go:devices_total":                             "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/system.go:config_last_change":                       "OPN-0033 removal trigger: legacy Unix timestamp gauge",
	"internal/collector/tailscale.go:peers_total":                           "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/trafficshaper.go:pipes_total":                       "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/trafficshaper.go:queues_total":                      "OPN-0033 removal trigger: legacy current-count gauge",
	"internal/collector/unbound_dns.go:qstats_start_time_seconds":           "OPN-0033 removal trigger: legacy Unix timestamp gauge",
	"internal/collector/wireguard.go:peer_last_handshake_seconds":           "OPN-0033 removal trigger: legacy Unix timestamp gauge",
}

// LegacyAllowlist returns a copy of the compatibility ledger. It is exposed so
// tests can verify that every exception carries the OPN-0033 removal trigger
// without allowing callers to mutate the guard's policy.
func LegacyAllowlist() map[string]string {
	out := make(map[string]string, len(legacyAllowlist))
	for key, note := range legacyAllowlist {
		out[key] = note
	}
	return out
}

// FindRepositoryRoot walks upward from start until it finds the module's go.mod.
func FindRepositoryRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	if info, statErr := os.Stat(dir); statErr == nil && !info.IsDir() {
		dir = filepath.Dir(dir)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no go.mod found above " + start)
		}
		dir = parent
	}
}

// ScanRepository parses first-party, non-test Go source below root and returns
// metric declarations in deterministic source order. Nested Go modules (such
// as tools/promqlcheck) and vendored/development trees are outside this
// repository's production metric surface and are not scanned.
func ScanRepository(root string) ([]Metric, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return nil, fmt.Errorf("metric lint root %q has no go.mod: %w", root, err)
	}

	byPackage := map[string][]string{}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root {
				base := entry.Name()
				if base == ".git" || base == ".tools" || base == ".superpowers" || base == "vendor" {
					return filepath.SkipDir
				}
				if _, statErr := os.Stat(filepath.Join(path, "go.mod")); statErr == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".go") &&
			!strings.HasSuffix(entry.Name(), "_test.go") {
			byPackage[filepath.Dir(path)] = append(byPackage[filepath.Dir(path)], path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	packageDirs := make([]string, 0, len(byPackage))
	for dir := range byPackage {
		packageDirs = append(packageDirs, dir)
	}
	sort.Strings(packageDirs)

	fset := token.NewFileSet()
	var metrics []Metric
	for _, packageDir := range packageDirs {
		paths := byPackage[packageDir]
		sort.Strings(paths)
		files := make([]sourceFile, 0, len(paths))
		constExprs := map[string]ast.Expr{}
		for _, path := range paths {
			file, parseErr := parser.ParseFile(fset, path, nil, 0)
			if parseErr != nil {
				return nil, fmt.Errorf("parsing %s: %w", path, parseErr)
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			files = append(files, sourceFile{path: path, rel: filepath.ToSlash(rel), file: file, fset: fset})
			collectConstExprs(file, constExprs)
		}

		scope := resolveConstScope(constExprs)
		declarations := scanDeclarations(files, scope)
		evidence := scanTypeEvidence(files)
		for i := range declarations {
			decl := &declarations[i]
			if decl.metric.Kind == KindUnknown {
				decl.metric.Kind = evidence.kind(decl.key)
			}
			decl.metric.UnixTimestamp = decl.metric.UnixTimestamp || evidence.timestamp[decl.key]
			metrics = append(metrics, decl.metric)
		}
	}

	sort.Slice(metrics, func(i, j int) bool {
		if metrics[i].File != metrics[j].File {
			return metrics[i].File < metrics[j].File
		}
		if metrics[i].Line != metrics[j].Line {
			return metrics[i].Line < metrics[j].Line
		}
		return metrics[i].LocalName < metrics[j].LocalName
	})
	return dedupeMetrics(metrics), nil
}

// CheckRepository runs the same source scan used by the command and the
// repository-scan test. It returns nil only when all declarations obey the
// naming rules or are individually present in the legacy ledger.
func CheckRepository(root string) error {
	metrics, err := ScanRepository(root)
	if err != nil {
		return err
	}
	violations := CheckMetrics(metrics)
	if len(violations) > 0 {
		return &ReportError{Violations: violations}
	}
	return nil
}

// CheckMetrics applies the naming rules to source-level metric records. It is
// deliberately separate from ScanRepository so fixture tests can pin the rule
// without constructing a whole collector or registry.
func CheckMetrics(metrics []Metric) []Violation {
	violations := make([]Violation, 0)
	for _, metric := range metrics {
		key := metricKey(metric)
		if strings.HasSuffix(metricName(metric), "_total") && metric.Kind != KindCounter &&
			!allowlisted(key, ruleGaugeTotal) {
			violations = append(violations, Violation{Rule: ruleGaugeTotal, Metric: metric})
		}
		if metric.UnixTimestamp && !strings.HasSuffix(metricName(metric), "_timestamp_seconds") &&
			!allowlisted(key, ruleTimestamp) {
			violations = append(violations, Violation{Rule: ruleTimestamp, Metric: metric})
		}
	}
	sort.Slice(violations, func(i, j int) bool {
		if violations[i].Metric.File != violations[j].Metric.File {
			return violations[i].Metric.File < violations[j].Metric.File
		}
		if violations[i].Metric.Line != violations[j].Metric.Line {
			return violations[i].Metric.Line < violations[j].Metric.Line
		}
		return violations[i].Rule < violations[j].Rule
	})
	return violations
}

type sourceFile struct {
	path string
	rel  string
	file *ast.File
	fset *token.FileSet
}

type metricDecl struct {
	key    string
	metric Metric
}

type typeEvidence struct {
	kinds     map[string]map[MetricKind]bool
	timestamp map[string]bool
}

func (e *typeEvidence) addKind(key string, kind MetricKind) {
	if key == "" || kind == KindUnknown {
		return
	}
	if e.kinds == nil {
		e.kinds = map[string]map[MetricKind]bool{}
	}
	if e.kinds[key] == nil {
		e.kinds[key] = map[MetricKind]bool{}
	}
	e.kinds[key][kind] = true
}

func (e typeEvidence) kind(key string) MetricKind {
	kinds := e.kinds[key]
	if len(kinds) != 1 {
		return KindUnknown
	}
	for kind := range kinds {
		return kind
	}
	return KindUnknown
}

func collectConstExprs(file *ast.File, out map[string]ast.Expr) {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok || len(valueSpec.Values) == 0 {
				continue
			}
			for i, name := range valueSpec.Names {
				if i < len(valueSpec.Values) {
					out[name.Name] = valueSpec.Values[i]
				}
			}
		}
	}
}

func resolveConstScope(exprs map[string]ast.Expr) map[string]string {
	scope := map[string]string{}
	for pass := 0; pass <= len(exprs); pass++ {
		changed := false
		for name, expr := range exprs {
			if _, exists := scope[name]; exists {
				continue
			}
			if value, ok := resolveString(expr, scope); ok {
				scope[name] = value
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return scope
}

func scanDeclarations(files []sourceFile, scope map[string]string) []metricDecl {
	var declarations []metricDecl
	for _, source := range files {
		options := collectOptionLiterals(source.file)
		ast.Inspect(source.file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.AssignStmt:
				for i, rhs := range n.Rhs {
					call, ok := rhs.(*ast.CallExpr)
					if !ok || i >= len(n.Lhs) {
						continue
					}
					key := scopedDescriptorKey(source.rel, n.Lhs[i])
					switch callName(call) {
					case "buildPrometheusDesc":
						if len(call.Args) < 3 {
							continue
						}
						local, ok := resolveString(call.Args[1], scope)
						if !ok || local == "" {
							continue
						}
						help, _ := resolveString(call.Args[2], scope)
						declarations = append(declarations, metricDecl{
							key: key,
							metric: Metric{
								Name:          local,
								LocalName:     local,
								Help:          help,
								Kind:          KindUnknown,
								File:          source.rel,
								Line:          lineOf(source.fset, call.Pos()),
								UnixTimestamp: isUnixTimestamp(local, help),
							},
						})
					case "NewDesc":
						if len(call.Args) < 2 {
							continue
						}
						name, local, ok := resolveMetricName(call.Args[0], scope)
						if !ok || local == "" {
							continue
						}
						help, _ := resolveString(call.Args[1], scope)
						declarations = append(declarations, metricDecl{
							key: key,
							metric: Metric{
								Name:          name,
								LocalName:     local,
								Help:          help,
								Kind:          KindUnknown,
								File:          source.rel,
								Line:          lineOf(source.fset, call.Pos()),
								UnixTimestamp: isUnixTimestamp(local, help),
							},
						})
					}
				}
			case *ast.CallExpr:
				kind, ok := constructorKind(callName(n))
				if !ok || len(n.Args) == 0 {
					return true
				}
				name, local, help, resolved := resolveOpts(n.Args[0], options, scope)
				if !resolved || local == "" {
					return true
				}
				declarations = append(declarations, metricDecl{
					metric: Metric{
						Name:          name,
						LocalName:     local,
						Help:          help,
						Kind:          kind,
						File:          source.rel,
						Line:          lineOf(source.fset, n.Pos()),
						UnixTimestamp: isUnixTimestamp(local, help),
					},
				})
			}
			return true
		})
	}
	return declarations
}

func collectOptionLiterals(file *ast.File) map[string]*ast.CompositeLit {
	options := map[string]*ast.CompositeLit{}
	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.AssignStmt:
			for i, rhs := range n.Rhs {
				if i >= len(n.Lhs) {
					continue
				}
				ident, ok := n.Lhs[i].(*ast.Ident)
				if !ok {
					continue
				}
				if literal, ok := rhs.(*ast.CompositeLit); ok && isPrometheusOpts(literal.Type) {
					options[ident.Name] = literal
				}
			}
		case *ast.ValueSpec:
			for i, rhs := range n.Values {
				if i >= len(n.Names) {
					continue
				}
				if literal, ok := rhs.(*ast.CompositeLit); ok && isPrometheusOpts(literal.Type) {
					options[n.Names[i].Name] = literal
				}
			}
		}
		return true
	})
	return options
}

func resolveOpts(expr ast.Expr, options map[string]*ast.CompositeLit, scope map[string]string) (name, local, help string, ok bool) {
	literal, isLiteral := expr.(*ast.CompositeLit)
	if !isLiteral {
		ident, isIdent := expr.(*ast.Ident)
		if !isIdent {
			return "", "", "", false
		}
		literal = options[ident.Name]
		if literal == nil {
			return "", "", "", false
		}
	}
	fields := map[string]ast.Expr{}
	for _, elt := range literal.Elts {
		pair, ok := elt.(*ast.KeyValueExpr)
		if ok {
			if key, ok := pair.Key.(*ast.Ident); ok {
				fields[key.Name] = pair.Value
			}
		}
	}
	nameExpr, exists := fields["Name"]
	if !exists {
		return "", "", "", false
	}
	local, ok = resolveMetricLocalName(nameExpr, scope)
	if !ok || local == "" {
		return "", "", "", false
	}
	help, _ = resolveString(fields["Help"], scope)
	parts := make([]string, 0, 3)
	for _, field := range []string{"Namespace", "Subsystem"} {
		if value, exists := fields[field]; exists {
			if resolved, resolvedOK := resolveString(value, scope); resolvedOK && resolved != "" {
				parts = append(parts, resolved)
			}
		}
	}
	parts = append(parts, local)
	return strings.Join(parts, "_"), local, help, true
}

func resolveMetricLocalName(expr ast.Expr, scope map[string]string) (string, bool) {
	if name, ok := resolveString(expr, scope); ok {
		return name, true
	}
	_, local, ok := resolveMetricName(expr, scope)
	return local, ok
}

func scanTypeEvidence(files []sourceFile) typeEvidence {
	evidence := typeEvidence{timestamp: map[string]bool{}}
	for _, source := range files {
		ast.Inspect(source.file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || !isMetricEmission(callName(call)) || len(call.Args) < 2 {
				return true
			}
			key := scopedDescriptorKey(source.rel, call.Args[0])
			if kind, ok := valueType(call.Args[1]); ok {
				evidence.addKind(key, kind)
			}
			if key != "" && len(call.Args) > 2 && expressionLooksUnix(call.Args[2]) {
				evidence.timestamp[key] = true
			}
			return true
		})

		// A few collectors put descriptors and their value types in a small
		// table, then emit the table row through m.desc/m.vt (or m.kind).
		// The table is still source-level type evidence even though the
		// emission call's arguments are identifiers.
		scanTableTypeEvidence(source, &evidence)

		// Helpers may be named functions, methods, or function literals held in
		// a local variable. Resolve their descriptor/type parameter bindings at
		// definition time and apply those bindings at each call site.
		helpers := collectHelpers(source)
		ast.Inspect(source.file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := callName(call)
			for _, helper := range helpers[name] {
				for _, binding := range helper.bindings {
					if binding.descParam < 0 || binding.descParam >= len(call.Args) {
						continue
					}
					key := scopedDescriptorKey(source.rel, call.Args[binding.descParam])
					kind := binding.fixedKind
					if binding.typeParam >= 0 {
						if binding.typeParam >= len(call.Args) {
							continue
						}
						var ok bool
						kind, ok = valueType(call.Args[binding.typeParam])
						if !ok {
							continue
						}
					}
					evidence.addKind(key, kind)
					if key != "" && binding.valueParam >= 0 && binding.valueParam < len(call.Args) &&
						expressionLooksUnix(call.Args[binding.valueParam]) {
						evidence.timestamp[key] = true
					}
				}
			}
			return true
		})
	}
	return evidence
}

// helperDef describes every metric emission in a helper whose descriptor is a
// function parameter. A helper can emit several descriptors (Kea's shared lease
// emitter is one example), so this is intentionally a slice rather than one
// descriptor/type tuple.
type helperDef struct {
	bindings []helperBinding
}

type helperBinding struct {
	descParam  int
	typeParam  int
	valueParam int
	fixedKind  MetricKind
}

func findHelperDef(params *ast.FieldList, body *ast.BlockStmt) (helperDef, bool) {
	paramNames := parameterNames(params)
	var found helperDef
	if body == nil {
		return found, false
	}
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || !isMetricEmission(callName(call)) || len(call.Args) < 2 {
			return true
		}
		desc, descOK := call.Args[0].(*ast.Ident)
		if !descOK {
			return true
		}
		descParam := indexOf(paramNames, desc.Name)
		if descParam < 0 {
			return true
		}

		binding := helperBinding{descParam: descParam, typeParam: -1, valueParam: -1, fixedKind: KindUnknown}
		if kind, fixed := valueType(call.Args[1]); fixed {
			binding.fixedKind = kind
		} else if typ, typeOK := call.Args[1].(*ast.Ident); typeOK {
			binding.typeParam = indexOf(paramNames, typ.Name)
			if binding.typeParam < 0 {
				return true
			}
		} else {
			return true
		}
		if len(call.Args) > 2 {
			if value, valueOK := call.Args[2].(*ast.Ident); valueOK {
				binding.valueParam = indexOf(paramNames, value.Name)
			}
		}
		found.bindings = append(found.bindings, binding)
		return true
	})
	return found, len(found.bindings) > 0
}

// collectHelpers returns helper definitions in one source file. A helper's
// local name is enough here because source files are scanned independently and
// Go does not permit two package-level functions with the same name. Local
// function literals are picked up from assignments and value declarations.
func collectHelpers(source sourceFile) map[string][]helperDef {
	helpers := map[string][]helperDef{}
	for _, decl := range source.file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if def, ok := findHelperDef(fn.Type.Params, fn.Body); ok {
			helpers[fn.Name.Name] = append(helpers[fn.Name.Name], def)
		}
	}
	ast.Inspect(source.file, func(node ast.Node) bool {
		var names []*ast.Ident
		var values []ast.Expr
		switch n := node.(type) {
		case *ast.AssignStmt:
			for i, rhs := range n.Rhs {
				if i >= len(n.Lhs) {
					continue
				}
				if _, ok := rhs.(*ast.FuncLit); ok {
					if ident, ok := n.Lhs[i].(*ast.Ident); ok {
						names = append(names, ident)
						values = append(values, rhs)
					}
				}
			}
		case *ast.ValueSpec:
			for i, rhs := range n.Values {
				if i < len(n.Names) {
					if _, ok := rhs.(*ast.FuncLit); ok {
						names = append(names, n.Names[i])
						values = append(values, rhs)
					}
				}
			}
		}
		for i, name := range names {
			lit, ok := values[i].(*ast.FuncLit)
			if !ok {
				continue
			}
			if def, ok := findHelperDef(lit.Type.Params, lit.Body); ok {
				helpers[name.Name] = append(helpers[name.Name], def)
			}
		}
		return true
	})
	return helpers
}

// scanTableTypeEvidence handles rows such as
// []struct{desc *prometheus.Desc; vt prometheus.ValueType}{...}. The field
// names are deliberately constrained to the small table idiom used by this
// repository; a row must carry a resolvable descriptor and a concrete
// prometheus value type before it contributes evidence.
func scanTableTypeEvidence(source sourceFile, evidence *typeEvidence) {
	ast.Inspect(source.file, func(node ast.Node) bool {
		literal, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		fieldIndexes := tableFieldIndexes(literal.Type)
		for _, elt := range literal.Elts {
			row, ok := elt.(*ast.CompositeLit)
			if !ok {
				continue
			}
			var descExpr, typeExpr ast.Expr
			for _, rowElt := range row.Elts {
				if field, ok := rowElt.(*ast.KeyValueExpr); ok {
					name, ok := field.Key.(*ast.Ident)
					if !ok {
						continue
					}
					switch name.Name {
					case "desc":
						descExpr = field.Value
					case "vt", "kind":
						typeExpr = field.Value
					}
				}
			}
			// The table rows in apcupsd and network_diag are positional
			// literals. Their enclosing struct type gives us the exact field
			// indexes without relying on a filename or a hard-coded row shape.
			if fieldIndexes != nil {
				if descExpr == nil {
					if index, ok := fieldIndexes["desc"]; ok && index < len(row.Elts) {
						descExpr = row.Elts[index]
					}
				}
				if typeExpr == nil {
					index, ok := fieldIndexes["vt"]
					if !ok {
						index, ok = fieldIndexes["kind"]
					}
					if ok && index < len(row.Elts) {
						typeExpr = row.Elts[index]
					}
				}
			}
			if descExpr == nil || typeExpr == nil {
				continue
			}
			kind, ok := valueType(typeExpr)
			if ok {
				evidence.addKind(scopedDescriptorKey(source.rel, descExpr), kind)
			}
		}
		return true
	})
}

// tableFieldIndexes returns field positions for an inline slice/array of
// structs. A nil result means the literal is not a table with a visible struct
// element type.
func tableFieldIndexes(expr ast.Expr) map[string]int {
	array, ok := expr.(*ast.ArrayType)
	if !ok {
		return nil
	}
	structType, ok := array.Elt.(*ast.StructType)
	if !ok || structType.Fields == nil {
		return nil
	}
	indexes := map[string]int{}
	index := 0
	for _, field := range structType.Fields.List {
		if len(field.Names) == 0 {
			index++
			continue
		}
		for _, name := range field.Names {
			indexes[name.Name] = index
			index++
		}
	}
	return indexes
}

func parameterNames(fields *ast.FieldList) []string {
	if fields == nil {
		return nil
	}
	var names []string
	for _, field := range fields.List {
		for _, name := range field.Names {
			names = append(names, name.Name)
		}
	}
	return names
}

func indexOf(values []string, want string) int {
	for i, value := range values {
		if value == want {
			return i
		}
	}
	return -1
}

func constructorKind(name string) (MetricKind, bool) {
	switch name {
	case "NewGauge", "NewGaugeVec":
		return KindGauge, true
	case "NewCounter", "NewCounterVec":
		return KindCounter, true
	case "NewHistogram", "NewHistogramVec":
		return KindHistogram, true
	case "NewSummary", "NewSummaryVec":
		return KindSummary, true
	default:
		return KindUnknown, false
	}
}

func isPrometheusOpts(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	case "GaugeOpts", "CounterOpts", "HistogramOpts", "SummaryOpts":
		return true
	default:
		return false
	}
}

func isMetricEmission(name string) bool {
	return name == "MustNewConstMetric" || name == "NewConstMetric"
}

func valueType(expr ast.Expr) (MetricKind, bool) {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return KindUnknown, false
	}
	switch sel.Sel.Name {
	case "GaugeValue":
		return KindGauge, true
	case "CounterValue":
		return KindCounter, true
	case "UntypedValue":
		return KindUntyped, true
	default:
		return KindUnknown, false
	}
}

func descriptorKey(expr ast.Expr) string {
	switch n := expr.(type) {
	case *ast.Ident:
		return n.Name
	case *ast.SelectorExpr:
		return n.Sel.Name
	case *ast.ParenExpr:
		return descriptorKey(n.X)
	default:
		return ""
	}
}

// scopedDescriptorKey keeps source-level descriptor identities local to the
// file that declares them. Collector structs commonly reuse field names such
// as bytesTotal; combining those fields would make otherwise independent
// GaugeValue and CounterValue evidence appear ambiguous.
func scopedDescriptorKey(file string, expr ast.Expr) string {
	key := descriptorKey(expr)
	if key == "" {
		return ""
	}
	return filepath.ToSlash(file) + ":" + key
}

func callName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	default:
		return ""
	}
}

func resolveMetricName(expr ast.Expr, scope map[string]string) (name, local string, ok bool) {
	call, isCall := expr.(*ast.CallExpr)
	if !isCall || callName(call) != "BuildFQName" || len(call.Args) == 0 {
		value, valueOK := resolveString(expr, scope)
		return value, value, valueOK
	}
	parts := make([]string, 0, len(call.Args))
	all := true
	for _, arg := range call.Args {
		value, valueOK := resolveString(arg, scope)
		if !valueOK {
			all = false
			parts = append(parts, "")
			continue
		}
		parts = append(parts, value)
	}
	last := parts[len(parts)-1]
	if last == "" {
		return "", "", false
	}
	if !all {
		parts = compactStrings(parts)
	}
	return strings.Join(parts, "_"), last, true
}

func resolveString(expr ast.Expr, scope map[string]string) (string, bool) {
	if expr == nil {
		return "", false
	}
	switch n := expr.(type) {
	case *ast.BasicLit:
		if n.Kind != token.STRING {
			return "", false
		}
		value, err := strconv.Unquote(n.Value)
		return value, err == nil
	case *ast.Ident:
		value, ok := scope[n.Name]
		return value, ok
	case *ast.ParenExpr:
		return resolveString(n.X, scope)
	case *ast.BinaryExpr:
		if n.Op != token.ADD {
			return "", false
		}
		left, leftOK := resolveString(n.X, scope)
		right, rightOK := resolveString(n.Y, scope)
		return left + right, leftOK && rightOK
	default:
		return "", false
	}
}

func compactStrings(parts []string) []string {
	compact := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			compact = append(compact, part)
		}
	}
	return compact
}

func isUnixTimestamp(name, help string) bool {
	text := strings.ToLower(name + " " + help)
	if strings.Contains(text, "unix timestamp") || strings.Contains(text, "unix time") ||
		strings.Contains(text, "seconds since epoch") || strings.Contains(text, "absolute timestamp") {
		return true
	}
	// This is the one historical metric whose source intentionally predates the
	// project's timestamp suffix convention and whose help text says only
	// "handshake ... in seconds". Keep the semantic exception narrow; a generic
	// *_handshake_age_seconds duration must not be classified as an epoch value.
	return strings.Contains(strings.ToLower(name), "last_handshake") && strings.HasSuffix(name, "_seconds")
}

func expressionLooksUnix(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return sel.Sel.Name == "Unix" || sel.Sel.Name == "UnixNano"
}

func lineOf(fset *token.FileSet, pos token.Pos) int {
	if fset == nil || pos == token.NoPos {
		return 0
	}
	return fset.Position(pos).Line
}

func metricName(metric Metric) string {
	if metric.Name != "" {
		return metric.Name
	}
	return metric.LocalName
}

func metricKey(metric Metric) string {
	name := metric.LocalName
	if name == "" {
		name = metric.Name
	}
	return filepath.ToSlash(metric.File) + ":" + name
}

func allowlisted(key, rule string) bool {
	note, ok := legacyAllowlist[key]
	if !ok || !strings.Contains(note, legacyRuleMarker) {
		return false
	}
	switch rule {
	case ruleGaugeTotal:
		return strings.Contains(note, legacyGaugeTotalNote)
	case ruleTimestamp:
		return strings.Contains(note, legacyTimestampNote)
	default:
		return false
	}
}

func dedupeMetrics(metrics []Metric) []Metric {
	seen := map[string]bool{}
	out := make([]Metric, 0, len(metrics))
	for _, metric := range metrics {
		key := fmt.Sprintf("%s:%d:%s:%s", metric.File, metric.Line, metric.LocalName, metric.Kind)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, metric)
	}
	return out
}
