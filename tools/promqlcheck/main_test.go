package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

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
	count, diagnostics := validateVariables(parsed)
	if len(diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %v", diagnostics)
	}
	if count != 1 {
		t.Fatalf("validated %d variable queries, want 1 (the textbox is not a query)", count)
	}
}
