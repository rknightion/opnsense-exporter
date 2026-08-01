package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withKind stamps a top-level `kind` onto a fixture, which is what validatePaths
// routes on. The panel/variable fixtures omit it because validateDashboard itself
// never looks at it.
func withKind(fixture []byte, kind string) string {
	var doc map[string]any
	if err := json.Unmarshal(fixture, &doc); err != nil {
		panic(err)
	}
	doc["kind"] = kind
	out, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return string(out)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func dashboardFixture(
	panelID int,
	title string,
	datasourceType string,
	queryGroup string,
	refID string,
	expression string,
) []byte {
	return []byte(fmt.Sprintf(`{
		"spec": {
			"elements": {
				"panel-fixture": {
					"kind": "Panel",
					"spec": {
						"id": %d,
						"title": %q,
						"data": {
							"spec": {
								"queries": [{
									"kind": "PanelQuery",
									"spec": {
										"refId": %q,
										"datasource": {"type": %q},
										"query": {
											"group": %q,
											"spec": {"expr": %q}
										}
									}
								}]
							}
						}
					}
				}
			}
		}
	}`, panelID, title, refID, datasourceType, queryGroup, expression))
}

// variableFixture is a dashboard carrying one Prometheus QueryVariable and no
// panels. A variable query is a Grafana variable FUNCTION, not bare PromQL.
func variableFixture(name, group, query string) []byte {
	return []byte(fmt.Sprintf(`{
		"spec": {
			"elements": {},
			"variables": [{
				"kind": "QueryVariable",
				"spec": {
					"name": %q,
					"query": {
						"kind": "DataQuery",
						"group": %q,
						"spec": {"query": %q}
					}
				}
			}]
		}
	}`, name, group, query))
}

func TestValidateDashboardAcceptsKnownGrafanaTokens(t *testing.T) {
	expression := `rate(opnsense_packets_total{` +
		`opnsense_instance=~"$opnsense_instance",` +
		`device=~"$device",interface=~"$interface"}[$__rate_interval])`

	count, _, _, err := validateDashboard(
		dashboardFixture(1, "Valid", "prometheus", "prometheus", "A", expression),
	)

	if err != nil {
		t.Fatalf("validateDashboard() error = %v", err)
	}
	if count != 1 {
		t.Fatalf("validateDashboard() count = %d, want 1", count)
	}
}

// The #424 $device union: the one variable query in this dashboard that is a
// composed expression rather than a bare selector, so it is the one that could
// ship unparseable. Kept byte-identical to build_dashboard.device_variable_query().
const deviceVariableQuery = `query_result(group by (opnsense_instance, device) (` +
	`label_join(opnsense_firewall_in_ipv4_pass_packets_total{opnsense_instance=~"$opnsense_instance"}, "device", "", "interface")` +
	` or label_join(opnsense_netflow_cache_packets_total{opnsense_instance=~"$opnsense_instance"}, "device", "", "interface")` +
	` or label_join(opnsense_vnstat_bytes_total{opnsense_instance=~"$opnsense_instance"}, "device", "", "interface")` +
	` or opnsense_interfaces_info{opnsense_instance=~"$opnsense_instance",device!=""}` +
	` or opnsense_flow_interface_info{opnsense_instance=~"$opnsense_instance",device!=""}))`

func TestValidateDashboardParsesTheDeviceVariableUnion(t *testing.T) {
	targets, variables, _, err := validateDashboard(
		variableFixture("device", "prometheus", deviceVariableQuery),
	)

	if err != nil {
		t.Fatalf("validateDashboard() error = %v", err)
	}
	if targets != 0 {
		t.Fatalf("validateDashboard() targets = %d, want 0", targets)
	}
	if variables != 1 {
		t.Fatalf("validateDashboard() variables = %d, want 1", variables)
	}
}

func TestValidateDashboardUnwrapsLabelValuesSelectors(t *testing.T) {
	// The selector's own commas must not be mistaken for label_values' argument
	// separator, and __name__ regex selectors must survive unwrapping.
	for _, query := range []string{
		`label_values(opnsense_up, opnsense_instance)`,
		`label_values(opnsense_interfaces_link_state{opnsense_instance=~"$opnsense_instance"}, interface)`,
		`label_values({__name__=~"opnsense_flow_.+",opnsense_instance=~"$opnsense_instance"}, __name__)`,
	} {
		_, variables, _, err := validateDashboard(variableFixture("v", "prometheus", query))
		if err != nil {
			t.Errorf("validateDashboard(%q) error = %v", query, err)
		}
		if variables != 1 {
			t.Errorf("validateDashboard(%q) variables = %d, want 1", query, variables)
		}
	}
}

func TestValidateDashboardReportsMalformedVariablePromQLWithVariableName(t *testing.T) {
	query := `query_result(group by (opnsense_instance, device) (opnsense_thing{a="1"}{b="2"}))`

	_, _, _, err := validateDashboard(variableFixture("device", "prometheus", query))

	if err == nil {
		t.Fatal("validateDashboard() error = nil, want malformed variable PromQL error")
	}
	for _, want := range []string{`variable "device"`, query, "unexpected"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("validateDashboard() error = %q, want substring %q", err, want)
		}
	}
}

func TestValidateDashboardRejectsAVariableThatIsNotAGrafanaVariableFunction(t *testing.T) {
	// Bare PromQL in a variable is not a syntax error, it is a variable Grafana
	// sends verbatim to an endpoint that cannot answer it - so the picker is
	// empty with nothing malformed to find.
	_, _, _, err := validateDashboard(
		variableFixture("device", "prometheus", `group by (device) (opnsense_interfaces_info)`),
	)

	if err == nil {
		t.Fatal("validateDashboard() error = nil, want unwrapping error")
	}
	if !strings.Contains(err.Error(), "not a label_values(...) or query_result(...) query") {
		t.Fatalf("validateDashboard() error = %q, want unwrapping context", err)
	}
}

func TestValidateDashboardSkipsLokiVariables(t *testing.T) {
	_, variables, _, err := validateDashboard(
		variableFixture("has_syslog_logs", "loki", `label_values({service_name="x"}, level)`),
	)

	if err != nil {
		t.Fatalf("validateDashboard() error = %v", err)
	}
	if variables != 0 {
		t.Fatalf("validateDashboard() variables = %d, want 0", variables)
	}
}

func TestValidateDashboardReportsMalformedPromQLWithPanelContext(t *testing.T) {
	expression := `opnsense_metric{one="1"}{two="2"}`

	count, _, _, err := validateDashboard(
		dashboardFixture(
			665,
			"Zenarmor Blocks by Category (rate)",
			"prometheus",
			"prometheus",
			"A",
			expression,
		),
	)

	if count != 1 {
		t.Fatalf("validateDashboard() count = %d, want 1", count)
	}
	if err == nil {
		t.Fatal("validateDashboard() error = nil, want malformed PromQL error")
	}
	for _, want := range []string{
		`panel 665 "Zenarmor Blocks by Category (rate)"`,
		"ref A",
		expression,
		"unexpected",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("validateDashboard() error = %q, want substring %q", err, want)
		}
	}
}

func TestValidateDashboardSkipsExactLokiTargets(t *testing.T) {
	count, _, _, err := validateDashboard(
		dashboardFixture(2, "Loki", "loki", "loki", "A", "this is not PromQL {"),
	)

	if err != nil {
		t.Fatalf("validateDashboard() error = %v", err)
	}
	if count != 0 {
		t.Fatalf("validateDashboard() count = %d, want 0", count)
	}
}

func TestValidateDashboardRejectsDatasourceMetadataMismatch(t *testing.T) {
	_, _, _, err := validateDashboard(
		dashboardFixture(3, "Mismatch", "prometheus", "loki", "B", "up"),
	)

	if err == nil {
		t.Fatal("validateDashboard() error = nil, want datasource mismatch error")
	}
	if !strings.Contains(err.Error(), `datasource type "prometheus" does not match query group "loki"`) {
		t.Fatalf("validateDashboard() error = %q, want datasource mismatch context", err)
	}
}

func TestValidateDashboardRejectsUnknownGrafanaToken(t *testing.T) {
	expression := `rate(opnsense_metric_total[$unknown_macro])`

	_, _, _, err := validateDashboard(
		dashboardFixture(4, "Unknown token", "prometheus", "prometheus", "C", expression),
	)

	if err == nil {
		t.Fatal("validateDashboard() error = nil, want unknown token error")
	}
	if !strings.Contains(err.Error(), `unknown Grafana token "$unknown_macro"`) {
		t.Fatalf("validateDashboard() error = %q, want unknown token context", err)
	}
}

func TestValidateDashboardRejectsInvalidJSON(t *testing.T) {
	_, _, _, err := validateDashboard([]byte(`{"spec":`))

	if err == nil {
		t.Fatal("validateDashboard() error = nil, want JSON decoding error")
	}
	if !strings.Contains(err.Error(), "decode dashboard JSON") {
		t.Fatalf("validateDashboard() error = %q, want JSON decoding context", err)
	}
}

// annotationFixture is a dashboard carrying one annotation query and no panels. A
// v2 AnnotationQuery keeps its real expression in `legacyOptions`, not in
// `query.spec` — the panel and variable walks never reach it, so before #421 an
// annotation could ship a malformed expression that failed only in a browser, with
// the timeline silently empty rather than erroring.
func annotationFixture(name, group, expression string) []byte {
	return []byte(fmt.Sprintf(`{
		"spec": {
			"elements": {},
			"annotations": [{
				"kind": "AnnotationQuery",
				"spec": {
					"name": %q,
					"legacyOptions": {"expr": %q},
					"query": {"kind": "DataQuery", "group": %q, "spec": {}}
				}
			}]
		}
	}`, name, expression, group))
}

func TestValidateDashboardValidatesPrometheusAnnotations(t *testing.T) {
	// The value-as-time idiom: scaled to milliseconds and bounded to the visible
	// window. `$__from`/`$__to` are epoch-millisecond numbers, so the comparison
	// chain has to parse as PromQL once they are substituted.
	expression := `opnsense_system_boot_timestamp_seconds{opnsense_instance=~"$opnsense_instance"}` +
		` * 1000 > $__from < $__to`

	_, _, annotations, err := validateDashboard(annotationFixture("Reboot", "prometheus", expression))
	if err != nil {
		t.Fatalf("validateDashboard() error = %v", err)
	}
	if annotations != 1 {
		t.Fatalf("validated %d annotation queries, want 1", annotations)
	}
}

func TestValidateDashboardRejectsMalformedAnnotation(t *testing.T) {
	_, _, _, err := validateDashboard(
		annotationFixture("Broken", "prometheus", `sum(opnsense_up{`),
	)
	if err == nil {
		t.Fatal("expected a malformed annotation expression to be rejected")
	}
	if !strings.Contains(err.Error(), "annotation \"Broken\"") {
		t.Errorf("diagnostic should name the annotation, got: %v", err)
	}
}

func TestValidateDashboardSkipsLokiAnnotations(t *testing.T) {
	// LogQL is not PromQL. A Loki annotation must be skipped rather than parsed,
	// exactly as Loki panel targets are.
	_, _, annotations, err := validateDashboard(annotationFixture(
		"Gateway alarm", "loki",
		`{service_instance_id=~"$opnsense_instance"} | gateway_event="alarm_started"`))
	if err != nil {
		t.Fatalf("validateDashboard() error = %v", err)
	}
	if annotations != 0 {
		t.Fatalf("counted %d annotation queries, want 0 for a Loki annotation", annotations)
	}
}

// A TextVariable's `spec.query` is a plain string, not a query object. When the
// variable type was decoded with a typed `query` struct, ONE textbox made the whole
// document fail to decode, so the tool validated nothing at all and said so only as a
// json error (#435). Any variable kind whose query is not a Prometheus query object
// must be skipped, and the real targets must still be validated.
func TestTextVariableDoesNotBreakTheDocument(t *testing.T) {
	document := `{"spec":{"elements":{"panel-1":{"kind":"Panel","spec":{"id":1,
      "title":"p","data":{"spec":{"queries":[{"spec":{"refId":"A","query":{
      "group":"prometheus","spec":{"expr":"up"}}}}]}}}}},
      "variables":[
        {"kind":"TextVariable","spec":{"name":"free","query":".*"}},
        {"kind":"QueryVariable","spec":{"name":"real","query":{"group":"prometheus",
          "spec":{"query":"label_values(up, job)"}}}}],
      "annotations":[]}}`

	var parsed dashboard
	if err := json.Unmarshal([]byte(document), &parsed); err != nil {
		t.Fatalf("a TextVariable must not break decoding: %v", err)
	}
	collected, _ := collectScopedVariables(parsed)
	count, diagnostics := validateVariables(collected)
	if len(diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %v", diagnostics)
	}
	if count != 1 {
		t.Fatalf("validated %d variable queries, want 1 (the textbox is not a query)", count)
	}
}

// --- argument routing (#431) ------------------------------------------------
// The dashboard family became plural, so an argument is routed by its manifest
// `kind` rather than by position. These pin the two ways that can go wrong: a
// second dashboard being fed to the rule validator (which rejects it with a
// misleading "unrecognized rule manifest kind"), and a run that checks no
// dashboard at all reporting success.

func TestValidatePathsValidatesEveryDashboardRegardlessOfPosition(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "a.json")
	writeFile(t, first, withKind(dashboardFixture(1, "p", "prometheus", "prometheus", "A", "up"), "Dashboard"))
	second := filepath.Join(dir, "b.json")
	writeFile(t, second, withKind(dashboardFixture(2, "q", "prometheus", "prometheus", "A", "go_goroutines"), "Dashboard"))

	targets, _, _, _, diagnostics, err := validatePaths([]string{first, second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %v", diagnostics)
	}
	if targets != 2 {
		t.Fatalf("validated %d targets across two dashboards, want 2", targets)
	}
}

func TestValidatePathsRejectsARunWithNoDashboard(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "folder.json")
	writeFile(t, folder, `{"kind":"Folder","spec":{"title":"x"}}`)

	if _, _, _, _, _, err := validatePaths([]string{folder}); err == nil {
		t.Fatal("a run that checked no dashboard reported success")
	}
}

// --- grouping-level variable scoping (#619) ---------------------------------
//
// These are the checks that stop the scoping migration from being a silent
// downgrade. Several fail against a NAIVE implementation that unions every
// declaration in the document, which is the shape a reasonable person writes
// first and which passes every positive test.
//
// Fixtures are built from Go maps rather than JSON string literals: these
// documents nest four levels deep, and hand-assembled JSON produced fixtures that
// failed to decode while the tests still LOOKED like they were exercising the
// walker.

type jsonObject = map[string]any

func queryVariable(name string) jsonObject {
	return jsonObject{"kind": "QueryVariable", "spec": jsonObject{
		"name": name,
		"query": jsonObject{"group": "prometheus",
			"spec": jsonObject{"query": "label_values(up, job)"}}}}
}

func gatedOn(name string) jsonObject {
	return jsonObject{"kind": "ConditionalRenderingGroup", "spec": jsonObject{
		"visibility": "show", "condition": "and",
		"items": []any{jsonObject{"kind": "ConditionalRenderingVariable",
			"spec": jsonObject{"variable": name, "operator": "matches", "value": ".+"}}}}}
}

func panelElement(title string) jsonObject {
	return jsonObject{"kind": "Panel", "spec": jsonObject{
		"id": 1, "title": title,
		"data": jsonObject{"spec": jsonObject{"queries": []any{}}}}}
}

func gridRow(title string, gate jsonObject, elementName string) jsonObject {
	spec := jsonObject{"title": title, "layout": jsonObject{
		"kind": "GridLayout", "spec": jsonObject{"items": []any{
			jsonObject{"kind": "GridLayoutItem",
				"spec": jsonObject{"element": jsonObject{"name": elementName}}}}}}}
	if gate != nil {
		spec["conditionalRendering"] = gate
	}
	return jsonObject{"kind": "RowsLayoutRow", "spec": spec}
}

func tabOf(title string, variables []any, gate jsonObject, rows ...any) jsonObject {
	spec := jsonObject{"title": title,
		"layout": jsonObject{"kind": "RowsLayout", "spec": jsonObject{"rows": rows}}}
	if variables != nil {
		spec["variables"] = variables
	}
	if gate != nil {
		spec["conditionalRendering"] = gate
	}
	return jsonObject{"kind": "TabsLayoutTab", "spec": spec}
}

func documentOf(t *testing.T, elements jsonObject, variables []any, tabs ...any) dashboard {
	t.Helper()
	raw, err := json.Marshal(jsonObject{"spec": jsonObject{
		"elements": elements, "variables": variables, "annotations": []any{},
		"layout": jsonObject{"kind": "TabsLayout", "spec": jsonObject{"tabs": tabs}}}})
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	var parsed dashboard
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("fixture does not decode: %v", err)
	}
	parsed.raw = raw
	return parsed
}

// twoDomains builds a dashboard where Network and Security each declare a
// variable of their own, so a sibling reference has somewhere wrong to point.
func twoDomains(t *testing.T, networkGate jsonObject, networkPanelTitle string) dashboard {
	t.Helper()
	return documentOf(t,
		jsonObject{"panel-net": panelElement(networkPanelTitle),
			"panel-sec": panelElement("s")},
		[]any{},
		tabOf("Network", []any{queryVariable("has_net")}, nil,
			gridRow("r", networkGate, "panel-net")),
		tabOf("Security", []any{queryVariable("has_sec")}, nil,
			gridRow("r", nil, "panel-sec")))
}

// A row gating on its OWN tab's variable is the normal, correct case.
func TestRowResolvesItsOwnTabsVariable(t *testing.T) {
	_, diagnostics := collectScopedVariables(twoDomains(t, gatedOn("has_net"), "n"))
	if len(diagnostics) != 0 {
		t.Fatalf("a row must resolve its own tab's variable: %v", diagnostics)
	}
}

// THE test. A row in Network gating on Security's variable is exactly what a
// naive union accepts and what renders permanently hidden in the browser.
func TestRowCannotResolveASiblingTabsVariable(t *testing.T) {
	_, diagnostics := collectScopedVariables(twoDomains(t, gatedOn("has_sec"), "n"))
	if len(diagnostics) == 0 {
		t.Fatal("a row gating on a SIBLING tab's variable was accepted; " +
			"it resolves to nothing and the row is hidden forever")
	}
	if !strings.Contains(diagnostics[0], "has_sec") {
		t.Fatalf("diagnostic does not name the offending variable: %v", diagnostics)
	}
}

// Same rule for a panel, not just a gate: a panel borrowing a sibling tab's
// variable filters on an empty string rather than erroring.
func TestPanelCannotResolveASiblingTabsVariable(t *testing.T) {
	_, diagnostics := collectScopedVariables(twoDomains(t, nil, "$has_sec"))
	if len(diagnostics) == 0 {
		t.Fatal("a panel referencing a SIBLING tab's variable was accepted")
	}
}

// A dashboard-level variable resolves everywhere, which is the case that must
// keep working or the whole artifact fails.
func TestDashboardLevelVariableResolvesInEveryTab(t *testing.T) {
	document := documentOf(t,
		jsonObject{"panel-net": panelElement("$global")},
		[]any{queryVariable("global")},
		tabOf("Network", nil, nil, gridRow("r", gatedOn("global"), "panel-net")))
	if _, diagnostics := collectScopedVariables(document); len(diagnostics) != 0 {
		t.Fatalf("a dashboard-level variable must resolve inside a tab: %v", diagnostics)
	}
}

// A tab cannot gate ITSELF on a variable it declares: the variable does not exist
// until the tab renders, so the gate evaluates against nothing and the tab never
// appears. This is exactly why placement hoists a gate to the parent.
func TestTabCannotGateItselfOnItsOwnVariable(t *testing.T) {
	document := documentOf(t,
		jsonObject{"panel-1": panelElement("p")},
		[]any{},
		tabOf("Self", []any{queryVariable("has_self")}, gatedOn("has_self"),
			gridRow("r", nil, "panel-1")))
	_, diagnostics := collectScopedVariables(document)
	if len(diagnostics) == 0 {
		t.Fatal("a tab gating on a variable scoped to itself was accepted; " +
			"the tab would be permanently hidden")
	}
}

// The legal counterpart: the gate lives on the PARENT, the tab it gates is
// nested inside. This must pass, or placement has nowhere to put the 27
// leaf-gates.
func TestParentScopedGateOnANestedTabResolves(t *testing.T) {
	inner := tabOf("DHCP", nil, gatedOn("has_kea"), gridRow("r", nil, "panel-1"))
	outer := jsonObject{"kind": "TabsLayoutTab", "spec": jsonObject{
		"title":     "Network",
		"variables": []any{queryVariable("has_kea")},
		"layout": jsonObject{"kind": "TabsLayout",
			"spec": jsonObject{"tabs": []any{inner}}}}}
	document := documentOf(t, jsonObject{"panel-1": panelElement("p")}, []any{}, outer)
	if _, diagnostics := collectScopedVariables(document); len(diagnostics) != 0 {
		t.Fatalf("a nested tab must resolve its PARENT's variable: %v", diagnostics)
	}
}

// Coverage, not just strictness: a variable that moved onto a tab must still be
// query-checked. Reading only spec.variables took this from 119 to 21 with a
// green exit, which is the failure mode that matters most here.
func TestTabScopedVariablesAreStillQueryChecked(t *testing.T) {
	collected, diagnostics := collectScopedVariables(twoDomains(t, gatedOn("has_net"), "n"))
	if len(diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %v", diagnostics)
	}
	count, variableDiagnostics := validateVariables(collected)
	if len(variableDiagnostics) != 0 {
		t.Fatalf("unexpected variable diagnostics: %v", variableDiagnostics)
	}
	if count != 2 {
		t.Fatalf("validated %d variable queries, want 2 (both live on tabs, "+
			"neither at dashboard level)", count)
	}
}

// A broken query on a TAB-scoped variable must be reported, and the diagnostic
// must say where it lives — otherwise the reader cannot find it.
func TestTabScopedVariableQueryErrorNamesItsLevel(t *testing.T) {
	broken := jsonObject{"kind": "QueryVariable", "spec": jsonObject{
		"name":  "broken",
		"query": jsonObject{"group": "prometheus", "spec": jsonObject{"query": "sum(up)"}}}}
	document := documentOf(t,
		jsonObject{"panel-1": panelElement("p")},
		[]any{},
		tabOf("Network", []any{broken}, nil, gridRow("r", nil, "panel-1")))
	collected, _ := collectScopedVariables(document)
	_, diagnostics := validateVariables(collected)
	if len(diagnostics) == 0 {
		t.Fatal("a malformed query on a tab-scoped variable was not reported")
	}
	if !strings.Contains(diagnostics[0], `tab "Network"`) {
		t.Fatalf("diagnostic does not say where the variable lives: %v", diagnostics)
	}
}

// The floor assertion. A layout kind the walker does not understand yields no
// panels, and every per-panel check below it then passes vacuously — success
// with less coverage, the hardest failure to notice. The generator cannot build
// an empty row, so zero panels in a row is a reader bug by definition.
func TestUnknownLayoutKindInARowIsAFailureNotSilence(t *testing.T) {
	row := jsonObject{"kind": "RowsLayoutRow", "spec": jsonObject{
		"title":  "r",
		"layout": jsonObject{"kind": "SomeFutureLayout", "spec": jsonObject{"panels": []any{}}}}}
	document := documentOf(t, jsonObject{}, []any{}, tabOf("Network", nil, nil, row))
	if _, diagnostics := collectScopedVariables(document); len(diagnostics) == 0 {
		t.Fatal("a row the walker read as empty was accepted; that is a reader bug " +
			"and every check under it passed vacuously")
	}
}

// AutoGridLayout must be UNDERSTOOD, not merely tolerated: it is a real layout
// this generator emits, and the vacuous pass above is exactly what happens if it
// is not (#619 item 3).
func TestAutoGridLayoutItemsAreWalked(t *testing.T) {
	row := jsonObject{"kind": "RowsLayoutRow", "spec": jsonObject{
		"title": "r",
		"layout": jsonObject{"kind": "AutoGridLayout", "spec": jsonObject{
			"items": []any{jsonObject{"kind": "AutoGridLayoutItem",
				"spec": jsonObject{"element": jsonObject{"name": "panel-1"}}}}}}}}
	document := documentOf(t,
		jsonObject{"panel-1": panelElement("$has_missing")},
		[]any{}, tabOf("Network", nil, nil, row))
	_, diagnostics := collectScopedVariables(document)
	if len(diagnostics) == 0 {
		t.Fatal("an AutoGridLayout panel was not walked; its variable reference " +
			"went unchecked and the row read as empty")
	}
	for _, diagnostic := range diagnostics {
		if strings.Contains(diagnostic, "ZERO panels") {
			t.Fatalf("AutoGridLayout read as an empty row: %v", diagnostics)
		}
	}
}

// Built-in tokens are not declarations and must never be reported as unresolved.
func TestGrafanaBuiltinsAreNotTreatedAsVariables(t *testing.T) {
	for _, blob := range []string{
		"$__rate_interval", "${__from}", "$__field.labels.instance", "$__interval",
	} {
		if got := referencedVariables(blob); len(got) != 0 {
			t.Errorf("referencedVariables(%q) = %v, want none", blob, got)
		}
	}
}

// A prefix must not match a longer name, or a variable gets pinned to the union
// of two unrelated tabs and quietly hoisted to the dashboard.
func TestVariableReferenceRespectsWordBoundaries(t *testing.T) {
	got := referencedVariables("$has_dhcpv6_isc and ${has_kea} and $has_dhcp")
	want := []string{"has_dhcp", "has_dhcpv6_isc", "has_kea"}
	if len(got) != len(want) {
		t.Fatalf("referencedVariables = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("referencedVariables = %v, want %v", got, want)
		}
	}
}
