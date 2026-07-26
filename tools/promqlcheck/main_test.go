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

func TestValidateDashboardAcceptsKnownGrafanaTokens(t *testing.T) {
	expression := `rate(opnsense_packets_total{` +
		`opnsense_instance=~"$opnsense_instance",` +
		`device=~"$device",interface=~"$interface"}[$__rate_interval])`

	count, err := validateDashboard(
		dashboardFixture(1, "Valid", "prometheus", "prometheus", "A", expression),
	)

	if err != nil {
		t.Fatalf("validateDashboard() error = %v", err)
	}
	if count != 1 {
		t.Fatalf("validateDashboard() count = %d, want 1", count)
	}
}

func TestValidateDashboardReportsMalformedPromQLWithPanelContext(t *testing.T) {
	expression := `opnsense_metric{one="1"}{two="2"}`

	count, err := validateDashboard(
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
	count, err := validateDashboard(
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
	_, err := validateDashboard(
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

	_, err := validateDashboard(
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
	_, err := validateDashboard([]byte(`{"spec":`))

	if err == nil {
		t.Fatal("validateDashboard() error = nil, want JSON decoding error")
	}
	if !strings.Contains(err.Error(), "decode dashboard JSON") {
		t.Fatalf("validateDashboard() error = %q, want JSON decoding context", err)
	}
}
