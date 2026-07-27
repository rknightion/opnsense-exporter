package main

import (
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

	count, _, err := validateDashboard(
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
	targets, variables, err := validateDashboard(
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
		_, variables, err := validateDashboard(variableFixture("v", "prometheus", query))
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

	_, _, err := validateDashboard(variableFixture("device", "prometheus", query))

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
	_, _, err := validateDashboard(
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
	_, variables, err := validateDashboard(
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

	count, _, err := validateDashboard(
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
	count, _, err := validateDashboard(
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
	_, _, err := validateDashboard(
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

	_, _, err := validateDashboard(
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
	_, _, err := validateDashboard([]byte(`{"spec":`))

	if err == nil {
		t.Fatal("validateDashboard() error = nil, want JSON decoding error")
	}
	if !strings.Contains(err.Error(), "decode dashboard JSON") {
		t.Fatalf("validateDashboard() error = %q, want JSON decoding context", err)
	}
}
