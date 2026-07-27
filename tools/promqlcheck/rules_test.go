package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// alertRuleFixture is a minimal grafana-managed AlertRule: one "prometheus"
// datasource node holding the real PromQL, plus one "__expr__" threshold node that
// only ever references another refID (never PromQL) and must not reach the parser.
// Shape matches grafana/alerts/grafana-managed/opnsense-cert-expiring.json.
func alertRuleFixture(promExpr string) []byte {
	return []byte(fmt.Sprintf(`{
		"apiVersion": "rules.alerting.grafana.app/v0alpha1",
		"kind": "AlertRule",
		"metadata": {"name": "fixture-alert"},
		"spec": {
			"title": "FixtureAlert",
			"noDataState": "Ok",
			"execErrState": "Error",
			"expressions": {
				"A": {
					"model": {
						"datasource": {"type": "prometheus", "uid": "grafanacloud-prom"},
						"expr": %q,
						"refId": "A"
					}
				},
				"C": {
					"model": {
						"datasource": {"type": "__expr__", "uid": "__expr__"},
						"expression": "A",
						"type": "threshold",
						"refId": "C",
						"conditions": [{
							"evaluator": {"type": "within_range", "params": [0, 14]},
							"operator": {"type": "and"},
							"query": {"params": []},
							"reducer": {"type": "last", "params": []},
							"type": "query"
						}]
					},
					"source": true
				}
			}
		}
	}`, promExpr))
}

// recordingRuleFixture is a minimal grafana-managed RecordingRule: a single
// "prometheus" node and no threshold node, matching
// grafana/alerts/grafana-managed/oxrec-gateway-loss-ratio.json.
func recordingRuleFixture(promExpr string) []byte {
	return []byte(fmt.Sprintf(`{
		"apiVersion": "rules.alerting.grafana.app/v0alpha1",
		"kind": "RecordingRule",
		"metadata": {"name": "fixture-recording"},
		"spec": {
			"title": "instance:fixture:ratio",
			"metric": "instance:fixture:ratio",
			"expressions": {
				"A": {
					"model": {
						"datasource": {"type": "prometheus", "uid": "grafanacloud-prom"},
						"expr": %q,
						"refId": "A"
					}
				}
			}
		}
	}`, promExpr))
}

func folderFixture() []byte {
	return []byte(`{
		"apiVersion": "folder.grafana.app/v1beta1",
		"kind": "Folder",
		"metadata": {"name": "opnsense-alerts"},
		"spec": {"title": "OPNsense Exporter Alerts"}
	}`)
}

func TestValidateRuleManifestValidatesAlertRuleAndSkipsThresholdNode(t *testing.T) {
	count, err := validateRuleManifest(alertRuleFixture(
		`(opnsense_certificate_valid_to_seconds - time()) / 86400`,
	))
	if err != nil {
		t.Fatalf("validateRuleManifest() error = %v", err)
	}
	// Exactly one PromQL expression: the "__expr__" threshold node in "C" must not
	// be counted or parsed, it holds no PromQL.
	if count != 1 {
		t.Fatalf("validateRuleManifest() count = %d, want 1", count)
	}
}

func TestValidateRuleManifestValidatesRecordingRuleExpression(t *testing.T) {
	count, err := validateRuleManifest(recordingRuleFixture(
		`opnsense_gateways_loss_percentage / 100`,
	))
	if err != nil {
		t.Fatalf("validateRuleManifest() error = %v", err)
	}
	if count != 1 {
		t.Fatalf("validateRuleManifest() count = %d, want 1", count)
	}
}

func TestValidateRuleManifestSkipsFolderManifest(t *testing.T) {
	count, err := validateRuleManifest(folderFixture())
	if err != nil {
		t.Fatalf("validateRuleManifest() error = %v", err)
	}
	if count != 0 {
		t.Fatalf("validateRuleManifest() count = %d, want 0 for a Folder manifest", count)
	}
}

func TestValidateRuleManifestReportsMalformedPromQLWithRefIDContext(t *testing.T) {
	expression := `opnsense_gateways_loss_percentage{a="1"}{b="2"} / 100`

	_, err := validateRuleManifest(recordingRuleFixture(expression))

	if err == nil {
		t.Fatal("validateRuleManifest() error = nil, want malformed PromQL error")
	}
	for _, want := range []string{
		`rule "instance:fixture:ratio"`, "ref A", expression, "unexpected",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("validateRuleManifest() error = %q, want substring %q", err, want)
		}
	}
}

func TestValidateRuleManifestRejectsUnrecognizedExpressionDatasourceType(t *testing.T) {
	// A "loki" (or any other non-prometheus, non-"__expr__") node is an alert/recording
	// shape this tool does not model. It must be a loud error, never a silent skip -
	// exactly the class of bug already found once in this tool (#435, the TextVariable
	// decode that quietly validated nothing).
	manifest := []byte(`{
		"apiVersion": "rules.alerting.grafana.app/v0alpha1",
		"kind": "RecordingRule",
		"metadata": {"name": "fixture-recording"},
		"spec": {
			"title": "instance:fixture:ratio",
			"expressions": {
				"A": {"model": {"datasource": {"type": "loki"}, "expr": "{job=\"x\"}", "refId": "A"}}
			}
		}
	}`)

	_, err := validateRuleManifest(manifest)

	if err == nil {
		t.Fatal("validateRuleManifest() error = nil, want unrecognized datasource type error")
	}
	if !strings.Contains(err.Error(), `datasource type "loki"`) {
		t.Fatalf("validateRuleManifest() error = %q, want datasource type context", err)
	}
}

func TestValidateRuleManifestRejectsUnrecognizedKind(t *testing.T) {
	manifest := []byte(`{
		"apiVersion": "rules.alerting.grafana.app/v0alpha1",
		"kind": "Dashboard",
		"metadata": {"name": "fixture"},
		"spec": {"title": "unexpected kind"}
	}`)

	_, err := validateRuleManifest(manifest)

	if err == nil {
		t.Fatal("validateRuleManifest() error = nil, want unrecognized kind error")
	}
	if !strings.Contains(err.Error(), `kind "Dashboard"`) {
		t.Fatalf("validateRuleManifest() error = %q, want kind context", err)
	}
}

func TestValidateRuleManifestRejectsInvalidJSON(t *testing.T) {
	_, err := validateRuleManifest([]byte(`{"spec":`))

	if err == nil {
		t.Fatal("validateRuleManifest() error = nil, want JSON decoding error")
	}
	if !strings.Contains(err.Error(), "decode rule manifest JSON") {
		t.Fatalf("validateRuleManifest() error = %q, want JSON decoding context", err)
	}
}

func TestValidateRuleManifestReusesGrafanaTokenSubstitution(t *testing.T) {
	// No shipped rule expression currently carries a Grafana dashboard token
	// ($opnsense_instance, $__rate_interval, ...) - verified against every file in
	// grafana/alerts/grafana-managed/ on 2026-07-27. This proves the substitution
	// table is wired in regardless, so a future rule expression that does use one
	// does not regress into a false "unknown token" failure or a raw parser error.
	count, err := validateRuleManifest(recordingRuleFixture(
		`rate(opnsense_packets_total{opnsense_instance=~"$opnsense_instance"}[$__rate_interval])`,
	))
	if err != nil {
		t.Fatalf("validateRuleManifest() error = %v", err)
	}
	if count != 1 {
		t.Fatalf("validateRuleManifest() count = %d, want 1", count)
	}
}

func TestValidateRuleManifestRejectsUnknownGrafanaToken(t *testing.T) {
	_, err := validateRuleManifest(recordingRuleFixture(
		`rate(opnsense_metric_total[$unknown_macro])`,
	))
	if err == nil {
		t.Fatal("validateRuleManifest() error = nil, want unknown token error")
	}
	if !strings.Contains(err.Error(), `unknown Grafana token "$unknown_macro"`) {
		t.Fatalf("validateRuleManifest() error = %q, want unknown token context", err)
	}
}

// TestValidateRuleManifestCatchesACorruptedRealManifest proves the check works
// against the ACTUAL shape shipped in grafana/alerts/grafana-managed/, not just the
// minimal synthetic fixtures above. testdata/corrupted-recording-rule.json is a copy
// of oxrec-gateway-loss-ratio.json with its expr mutated to an adjacent-braces
// selector error; the real manifest is never touched.
func TestValidateRuleManifestCatchesACorruptedRealManifest(t *testing.T) {
	data, err := os.ReadFile("testdata/corrupted-recording-rule.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	_, verr := validateRuleManifest(data)

	if verr == nil {
		t.Fatal("validateRuleManifest() error = nil, want the corrupted expr to fail")
	}
	if !strings.Contains(verr.Error(), "unexpected") {
		t.Fatalf("validateRuleManifest() error = %q, want a parser error", verr)
	}
}

// TestValidateRuleManifestAcceptsARealShippedManifest proves the happy path against
// an UNMODIFIED copy of a real manifest (opnsense-cert-expiring.json), so the
// fixtures above are not accidentally simpler than what ships.
func TestValidateRuleManifestAcceptsARealShippedManifest(t *testing.T) {
	data, err := os.ReadFile("testdata/valid-alert-rule.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	count, verr := validateRuleManifest(data)

	if verr != nil {
		t.Fatalf("validateRuleManifest() error = %v", verr)
	}
	if count != 1 {
		t.Fatalf("validateRuleManifest() count = %d, want 1 (the threshold node must not be counted)", count)
	}
}
