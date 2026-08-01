package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/prometheus/prometheus/promql/parser"
)

var (
	grafanaTokens = strings.NewReplacer(
		"$__rate_interval", "5m",
		"$opnsense_instance", "fixture",
		// $__from / $__to interpolate to epoch MILLISECONDS. They appear only in
		// the value-as-time annotation idiom `<expr> * 1000 > $__from < $__to`,
		// whose comparison chain must still parse once they are numbers (#421).
		"$__from", "1700000000000",
		"$__to", "1700003600000",
		"$__interval", "5m",
		"$device", "fixture",
		"$interface", "fixture",
	)
	unknownGrafanaToken = regexp.MustCompile(
		`\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)`,
	)
)

type dashboard struct {
	Spec struct {
		Elements    map[string]element `json:"elements"`
		Variables   []variable         `json:"variables"`
		Annotations []annotation       `json:"annotations"`
		// Layout is raw and walked generically (#619). Variables no longer live
		// only at spec.variables: a RowsLayoutRow and a TabsLayoutTab may each
		// declare their own, and a variable declared on a tab exists ONLY inside
		// that tab. Decoding this into typed layout kinds would be the quiet
		// failure mode — an unknown kind deserialises to an empty struct, every
		// panel underneath drops out of the check, and the tool still reports
		// success.
		Layout json.RawMessage `json:"layout"`
	} `json:"spec"`

	// raw is the undecoded document, kept so the scoping walk can look at whole
	// elements rather than the narrow typed view the query checks use.
	raw []byte
}

// A v2 AnnotationQuery keeps its expression in legacyOptions rather than in
// query.spec, so neither the panel walk nor the variable walk reaches it. An
// annotation that fails to parse renders an empty timeline and reports nothing,
// which is the quietest possible failure on the dashboard (#421).
type annotation struct {
	Spec struct {
		Name          string `json:"name"`
		LegacyOptions struct {
			Expression string `json:"expr"`
		} `json:"legacyOptions"`
		Query struct {
			Group string `json:"group"`
		} `json:"query"`
	} `json:"spec"`
}

// `query` is deliberately json.RawMessage rather than a struct: only a
// QueryVariable holds a datasource query object there. A TextVariable's `query` is
// a plain STRING (its textbox value), so a typed field made the whole document fail
// to decode — the tool reported nothing about 975 valid targets because one textbox
// existed (#435). Decoding is now per-kind, and an unknown kind is skipped rather
// than fatal.
type variable struct {
	Kind string `json:"kind"`
	Spec struct {
		Name  string          `json:"name"`
		Query json.RawMessage `json:"query"`
	} `json:"spec"`
}

// variableQuery is the QueryVariable shape of `spec.query`.
type variableQuery struct {
	Group string `json:"group"`
	Spec  struct {
		Query string `json:"query"`
	} `json:"spec"`
}

type element struct {
	Kind string `json:"kind"`
	Spec struct {
		ID    int    `json:"id"`
		Title string `json:"title"`
		Data  struct {
			Spec struct {
				Queries []panelQuery `json:"queries"`
			} `json:"spec"`
		} `json:"data"`
	} `json:"spec"`
}

type panelQuery struct {
	Spec struct {
		RefID      string `json:"refId"`
		Datasource struct {
			Type string `json:"type"`
		} `json:"datasource"`
		Query struct {
			Group string `json:"group"`
			Spec  struct {
				Expression string `json:"expr"`
			} `json:"spec"`
		} `json:"query"`
	} `json:"spec"`
}

type target struct {
	PanelID       int
	PanelTitle    string
	RefID         string
	Datasource    string
	QueryGroup    string
	Expression    string
	ElementSortID string
}

type validationErrors []string

func (e validationErrors) Error() string {
	return strings.Join(e, "\n")
}

// A Grafana QueryVariable never holds bare PromQL: it holds one of the Prometheus
// datasource's variable functions, with the expression inside. Unwrap the forms
// this dashboard uses so the real parser sees the expression — the panel walk
// above never reaches a variable, so a malformed variable query used to ship
// silently and fail only in the operator's browser, taking the picker (and every
// panel filtering on it) with it (#424).
var (
	labelValuesQuery = regexp.MustCompile(`^label_values\((.*)\)$`)
	queryResultQuery = regexp.MustCompile(`^query_result\((.*)\)$`)
)

// splitLastTopLevelComma splits on the final comma outside quotes and outside any
// bracket, which is how Grafana separates label_values' series selector from its
// label argument. Returns ok=false when there is no such comma.
func splitLastTopLevelComma(text string) (string, string, bool) {
	depth, quoted, at := 0, false, -1
	for i, r := range text {
		switch {
		case quoted:
			if r == '"' {
				quoted = false
			}
		case r == '"':
			quoted = true
		case r == '(' || r == '{' || r == '[':
			depth++
		case r == ')' || r == '}' || r == ']':
			depth--
		case r == ',' && depth == 0:
			at = i
		}
	}
	if at < 0 {
		return "", "", false
	}
	return text[:at], text[at+1:], true
}

// unwrapVariableQuery returns the PromQL inside a Grafana variable function, and
// whether there is any expression to validate at all.
func unwrapVariableQuery(query string) (string, bool, error) {
	query = strings.TrimSpace(query)
	if match := queryResultQuery.FindStringSubmatch(query); match != nil {
		return strings.TrimSpace(match[1]), true, nil
	}
	if match := labelValuesQuery.FindStringSubmatch(query); match != nil {
		selector, _, ok := splitLastTopLevelComma(match[1])
		if !ok {
			// label_values(<label>) — no series selector, nothing to parse.
			return "", false, nil
		}
		return strings.TrimSpace(selector), true, nil
	}
	return "", false, fmt.Errorf(
		"not a label_values(...) or query_result(...) query; Grafana would send it verbatim")
}

func validateExpression(normalized string) error {
	if token := unknownGrafanaToken.FindString(normalized); token != "" {
		return fmt.Errorf("unknown Grafana token %q", token)
	}
	p := parser.NewParser(parser.Options{})
	_, err := p.ParseExpr(normalized)
	return err
}

// --- grouping-level variable scoping (#619) ---------------------------------
//
// Two things break quietly the moment a variable stops living at spec.variables,
// and they are opposite failures:
//
//   - UNDER-COVERAGE. Reading only spec.variables means every variable that moved
//     onto a tab stops being query-checked. The tool keeps passing and simply
//     validates less — it went from 119 variable queries to 21 the first time
//     placement moved, with a green exit.
//   - UNDER-STRICTNESS. Checking that a name exists SOMEWHERE on the dashboard is
//     too weak once scoping exists. A row gating on a sibling tab's variable
//     passes that check, then renders permanently hidden — on screen identical to
//     a row correctly hidden for want of data. A walker that simply unions every
//     declaration in the document passes the obvious test and accepts exactly this
//     bug, so resolution is tracked positionally instead.
//
// The walk therefore carries a VISIBLE SET down the tree rather than collecting
// paths: a level's own declarations are added before descending into it, and a
// level's own conditionalRendering is checked BEFORE they are added, because a tab
// cannot gate itself on a variable scoped to itself.

// variableReference matches both spellings Grafana accepts.
var variableReference = regexp.MustCompile(
	`\$\{([A-Za-z_][A-Za-z0-9_]*)[:}]|\$([A-Za-z_][A-Za-z0-9_]*)`)

// referencedVariables returns the variable names interpolated anywhere in a blob
// of dashboard JSON, minus Grafana's own `__`-prefixed built-ins ($__rate_interval,
// $__from, $__field.labels.x and friends), which no dashboard declares.
func referencedVariables(blob string) []string {
	seen := map[string]bool{}
	var out []string
	for _, match := range variableReference.FindAllStringSubmatch(blob, -1) {
		name := match[1]
		if name == "" {
			name = match[2]
		}
		if name == "" || strings.HasPrefix(name, "__") || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// scopedVariable is one declaration plus where it was declared, so a diagnostic can
// say which level owns a broken query.
type scopedVariable struct {
	variable
	where string
}

type layoutWalk struct {
	elements    map[string]json.RawMessage
	variables   []scopedVariable
	panels      int
	rows        int
	diagnostics validationErrors
}

func specOf(node map[string]any) map[string]any {
	spec, _ := node["spec"].(map[string]any)
	return spec
}

// declaredVariables decodes a level's own `variables: [...]`.
func declaredVariables(spec map[string]any, where string) []scopedVariable {
	raw, ok := spec["variables"]
	if !ok {
		return nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var decoded []variable
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil
	}
	out := make([]scopedVariable, 0, len(decoded))
	for _, v := range decoded {
		out = append(out, scopedVariable{variable: v, where: where})
	}
	return out
}

// gateVariables reads a level's conditionalRendering variable names.
func gateVariables(spec map[string]any) []string {
	cond, ok := spec["conditionalRendering"].(map[string]any)
	if !ok {
		return nil
	}
	inner, ok := cond["spec"].(map[string]any)
	if !ok {
		return nil
	}
	items, ok := inner["items"].([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok || item["kind"] != "ConditionalRenderingVariable" {
			continue
		}
		if itemSpec, ok := item["spec"].(map[string]any); ok {
			if name, ok := itemSpec["variable"].(string); ok {
				out = append(out, name)
			}
		}
	}
	return out
}

func extend(visible map[string]bool, added []scopedVariable) map[string]bool {
	if len(added) == 0 {
		return visible
	}
	next := make(map[string]bool, len(visible)+len(added))
	for name := range visible {
		next[name] = true
	}
	for _, v := range added {
		next[v.Spec.Name] = true
	}
	return next
}

func (w *layoutWalk) require(names []string, visible map[string]bool, where, what string) {
	for _, name := range names {
		if !visible[name] {
			w.diagnostics = append(w.diagnostics, fmt.Sprintf(
				"%s: %s references $%s, which does not resolve here — it is not "+
					"declared at dashboard level nor by any enclosing tab or row. "+
					"A gate on an out-of-scope variable renders permanently hidden.",
				where, what, name))
		}
	}
}

func (w *layoutWalk) walk(node any, visible map[string]bool, where string) {
	switch typed := node.(type) {
	case map[string]any:
		kind, _ := typed["kind"].(string)
		switch kind {
		case "TabsLayoutTab":
			spec := specOf(typed)
			title, _ := spec["title"].(string)
			inner := where + " > tab " + strconv.Quote(title)
			// Checked against the PARENT's visible set, on purpose.
			w.require(gateVariables(spec), visible, inner, "its own visibility gate")
			own := declaredVariables(spec, inner)
			w.variables = append(w.variables, own...)
			w.walk(spec["layout"], extend(visible, own), inner)
			return
		case "RowsLayoutRow":
			spec := specOf(typed)
			title, _ := spec["title"].(string)
			inner := where + " > row " + strconv.Quote(title)
			w.require(gateVariables(spec), visible, inner, "its own visibility gate")
			own := declaredVariables(spec, inner)
			w.variables = append(w.variables, own...)
			before := w.panels
			w.walk(spec["layout"], extend(visible, own), inner)
			// A row the reader sees as empty is a reader bug, not a dashboard:
			// the generator cannot build one. This is the floor assertion that
			// stops a future layout kind silently emptying the walk (#619).
			if w.panels == before {
				w.diagnostics = append(w.diagnostics, fmt.Sprintf(
					"%s: read as having ZERO panels. The generator cannot build an "+
						"empty row, so this is a layout kind the walker does not "+
						"understand — every check below it has passed vacuously.",
					inner))
			}
			return
		case "GridLayoutItem", "AutoGridLayoutItem":
			spec := specOf(typed)
			name := ""
			if ref, ok := spec["element"].(map[string]any); ok {
				name, _ = ref["name"].(string)
			}
			w.panels++
			element, ok := w.elements[name]
			if !ok {
				w.diagnostics = append(w.diagnostics, fmt.Sprintf(
					"%s: references element %q, which is not in spec.elements",
					where, name))
				return
			}
			w.require(referencedVariables(string(element)), visible,
				where, "panel "+strconv.Quote(name))
			return
		}
		for _, value := range typed {
			w.walk(value, visible, where)
		}
	case []any:
		for _, value := range typed {
			w.walk(value, visible, where)
		}
	}
}

// collectScopedVariables walks the layout and returns every variable declared
// anywhere in the document, plus any resolution diagnostics.
func collectScopedVariables(document dashboard) ([]scopedVariable, validationErrors) {
	all := make([]scopedVariable, 0, len(document.Spec.Variables))
	visible := map[string]bool{}
	for _, v := range document.Spec.Variables {
		all = append(all, scopedVariable{variable: v, where: "dashboard"})
		visible[v.Spec.Name] = true
	}
	if len(document.Spec.Layout) == 0 {
		return all, nil
	}

	elements := map[string]json.RawMessage{}
	var rawSpec struct {
		Spec struct {
			Elements map[string]json.RawMessage `json:"elements"`
		} `json:"spec"`
	}
	// Re-decoding rather than reusing the typed elements map: the resolution check
	// has to see the WHOLE element (titles, legends, link URLs, transformations,
	// overrides), not just the query strings the typed reader keeps.
	if err := json.Unmarshal(document.raw, &rawSpec); err == nil {
		elements = rawSpec.Spec.Elements
	}

	var layout any
	if err := json.Unmarshal(document.Spec.Layout, &layout); err != nil {
		return all, validationErrors{fmt.Sprintf("decode spec.layout: %v", err)}
	}
	walk := &layoutWalk{elements: elements}
	walk.walk(layout, visible, "dashboard")
	if walk.panels == 0 {
		return all, validationErrors{
			"spec.layout yielded ZERO panels — the walker does not understand this " +
				"layout and every scoping check has passed vacuously"}
	}
	return append(all, walk.variables...), walk.diagnostics
}

func validateVariables(variables []scopedVariable) (int, validationErrors) {
	var (
		names       []string
		queries     = map[string]string{}
		wheres      = map[string]string{}
		diagnostics validationErrors
	)
	for _, sv := range variables {
		v := sv.variable
		if v.Kind != "QueryVariable" || len(v.Spec.Query) == 0 {
			continue
		}
		var query variableQuery
		if err := json.Unmarshal(v.Spec.Query, &query); err != nil {
			diagnostics = append(diagnostics, fmt.Sprintf(
				"variable %q: query is not a QueryVariable query object: %v",
				v.Spec.Name, err))
			continue
		}
		if query.Group != "prometheus" {
			continue
		}
		names = append(names, v.Spec.Name)
		queries[v.Spec.Name] = query.Spec.Query
		wheres[v.Spec.Name] = sv.where
	}
	sort.Strings(names)

	validated := 0
	for _, name := range names {
		query := queries[name]
		expression, present, err := unwrapVariableQuery(query)
		if err != nil {
			diagnostics = append(diagnostics, fmt.Sprintf(
				"variable %q (declared at %s): %v\nquery: %s",
				name, wheres[name], err, query))
			continue
		}
		if !present {
			continue
		}
		validated++
		if err := validateExpression(grafanaTokens.Replace(expression)); err != nil {
			diagnostics = append(diagnostics, fmt.Sprintf(
				"variable %q (declared at %s): %v\nquery: %s",
				name, wheres[name], err, query))
		}
	}
	return validated, diagnostics
}

// validateAnnotations parses every Prometheus annotation expression and returns how
// many were checked. Loki annotations are skipped, as Loki panel targets are.
func validateAnnotations(document dashboard) (int, validationErrors) {
	var (
		validated   int
		diagnostics validationErrors
	)
	for _, a := range document.Spec.Annotations {
		if a.Spec.Query.Group != "prometheus" {
			continue
		}
		expression := a.Spec.LegacyOptions.Expression
		if strings.TrimSpace(expression) == "" {
			diagnostics = append(diagnostics, fmt.Sprintf(
				"annotation %q: prometheus annotation has no expression", a.Spec.Name))
			continue
		}
		validated++
		if err := validateExpression(grafanaTokens.Replace(expression)); err != nil {
			diagnostics = append(diagnostics, fmt.Sprintf(
				"annotation %q: %v\nexpression: %s", a.Spec.Name, err, expression))
		}
	}
	return validated, diagnostics
}

func validateDashboard(data []byte) (int, int, int, error) {
	var document dashboard
	if err := json.Unmarshal(data, &document); err != nil {
		return 0, 0, 0, fmt.Errorf("decode dashboard JSON: %w", err)
	}
	document.raw = data

	var targets []target
	for elementID, dashboardElement := range document.Spec.Elements {
		if dashboardElement.Kind != "Panel" {
			continue
		}
		for _, query := range dashboardElement.Spec.Data.Spec.Queries {
			targets = append(targets, target{
				PanelID:       dashboardElement.Spec.ID,
				PanelTitle:    dashboardElement.Spec.Title,
				RefID:         query.Spec.RefID,
				Datasource:    query.Spec.Datasource.Type,
				QueryGroup:    query.Spec.Query.Group,
				Expression:    query.Spec.Query.Spec.Expression,
				ElementSortID: elementID,
			})
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].PanelID != targets[j].PanelID {
			return targets[i].PanelID < targets[j].PanelID
		}
		if targets[i].RefID != targets[j].RefID {
			return targets[i].RefID < targets[j].RefID
		}
		return targets[i].ElementSortID < targets[j].ElementSortID
	})

	prometheusTargets := 0
	var diagnostics validationErrors
	for _, query := range targets {
		if query.Datasource == "loki" && query.QueryGroup == "loki" {
			continue
		}
		if query.Datasource != "prometheus" || query.QueryGroup != "prometheus" {
			diagnostics = append(diagnostics, fmt.Sprintf(
				"panel %d %q ref %s: datasource type %q does not match query group %q",
				query.PanelID,
				query.PanelTitle,
				query.RefID,
				query.Datasource,
				query.QueryGroup,
			))
			continue
		}

		prometheusTargets++
		if err := validateExpression(grafanaTokens.Replace(query.Expression)); err != nil {
			diagnostics = append(diagnostics, fmt.Sprintf(
				"panel %d %q ref %s: %v\nexpression: %s",
				query.PanelID,
				query.PanelTitle,
				query.RefID,
				err,
				query.Expression,
			))
		}
	}

	scopedVariables, scopeDiagnostics := collectScopedVariables(document)
	diagnostics = append(diagnostics, scopeDiagnostics...)

	prometheusVariables, variableDiagnostics := validateVariables(scopedVariables)
	diagnostics = append(diagnostics, variableDiagnostics...)

	prometheusAnnotations, annotationDiagnostics := validateAnnotations(document)
	diagnostics = append(diagnostics, annotationDiagnostics...)

	if len(diagnostics) > 0 {
		return prometheusTargets, prometheusVariables, prometheusAnnotations, diagnostics
	}
	return prometheusTargets, prometheusVariables, prometheusAnnotations, nil
}

// Rule manifest paths are optional and additive (#429): the tool still works exactly
// as before against a dashboard alone, and gains rule-expression coverage only when
// grafana/alerts/grafana-managed/*.json is passed too - the shell expands that glob
// into the argument list, so this program never needs to know the directory itself.
// manifestKind reads the top-level `kind` of any manifest this tool accepts, so an
// argument is routed by what it IS rather than by where it sits on the command line.
// Positional routing broke the moment #431 made the dashboard family plural: the
// second dashboard reached validateRuleManifest and was rejected as an unrecognized
// rule kind, which is a confusing way to report "you passed two dashboards".
func manifestKind(data []byte) (string, error) {
	var head struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return "", fmt.Errorf("decode manifest JSON: %w", err)
	}
	return head.Kind, nil
}

// validatePaths validates every path, routing each by its manifest kind. Returns the
// four counts the summary line reports, plus any diagnostics. A read error is fatal
// and returned as an error rather than a diagnostic: it means the caller's arguments
// are wrong, not that the content is.
func validatePaths(paths []string) (targets, variables, annotations, ruleExpressions int,
	diagnostics validationErrors, err error) {
	dashboards := 0
	for _, path := range paths {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return 0, 0, 0, 0, nil, fmt.Errorf("read %s: %w", path, readErr)
		}
		kind, kindErr := manifestKind(data)
		if kindErr != nil {
			return 0, 0, 0, 0, nil, fmt.Errorf("%s: %w", path, kindErr)
		}
		if kind == "Dashboard" {
			dashboards++
			t, v, a, dashErr := validateDashboard(data)
			if dashErr != nil {
				diagnostics = append(diagnostics, fmt.Sprintf("%s: %s", path, dashErr))
				continue
			}
			targets += t
			variables += v
			annotations += a
			continue
		}
		count, errs := validateRuleManifest(data)
		ruleExpressions += count
		for _, e := range errs {
			diagnostics = append(diagnostics, fmt.Sprintf("%s: %s", path, e))
		}
	}
	if dashboards == 0 {
		return 0, 0, 0, 0, nil, fmt.Errorf(
			"no dashboard manifest among %d argument(s); this tool exists to check the "+
				"dashboard family and passing only rule manifests silently skips it", len(paths))
	}
	return targets, variables, annotations, ruleExpressions, diagnostics, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: promqlcheck <dashboard.json ...> [rule-manifest.json ...]")
		os.Exit(2)
	}

	targets, variables, annotations, ruleExpressions, diagnostics, err := validatePaths(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(diagnostics) > 0 {
		fmt.Fprintln(os.Stderr, diagnostics.Error())
		os.Exit(1)
	}

	fmt.Printf(
		"validated %d Prometheus targets, %d variable queries, %d annotation queries and %d rule expressions\n",
		targets, variables, annotations, ruleExpressions)
}
