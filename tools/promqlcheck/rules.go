package main

import (
	"encoding/json"
	"fmt"
	"sort"
)

// A grafana-managed rule manifest (grafana/alerts/grafana-managed/*.json) is a
// different schema from the v2 dashboard: the PromQL lives in
// spec.expressions.<refID>.model, keyed by an arbitrary Grafana refID rather than
// nested under a panel. Three kinds ship from build_rules.py: Folder (no
// expressions, nothing to validate), AlertRule and RecordingRule (both carry
// spec.expressions the same way).
type ruleManifest struct {
	Kind string `json:"kind"`
	Spec struct {
		Title       string                    `json:"title"`
		Expressions map[string]ruleExpression `json:"expressions"`
	} `json:"spec"`
}

type ruleExpression struct {
	Model struct {
		Datasource struct {
			Type string `json:"type"`
		} `json:"datasource"`
		Expression string `json:"expr"`
		RefID      string `json:"refId"`
	} `json:"model"`
}

// ruleKinds that carry spec.expressions. Folder is deliberately absent: it has no
// expressions at all, so it is handled as its own case rather than folded in here.
var ruleKinds = map[string]bool{"AlertRule": true, "RecordingRule": true}

// validateRuleManifest parses every PromQL expression in one grafana-managed rule
// manifest and returns how many it validated.
//
// Every expression node's kind is decided by spec.expressions.<refID>.model.datasource.type,
// exactly the field Grafana itself uses to route the node at evaluation time:
//   - "prometheus" is a real Prometheus query - its model.expr is fed to the parser.
//   - "__expr__" is one of Grafana's server-side expressions (threshold, reduce, math,
//     resample, classic_conditions, sql, ...) - its "expression"/"conditions" fields
//     reference OTHER refIDs or hold reducer/evaluator config, never PromQL, and must
//     never reach the parser.
//   - anything else (a Loki node, a missing/empty type, a datasource this tool has
//     never seen) is an unrecognized shape and is a hard error, not a silent skip.
//     That silent-skip failure mode is exactly the #435 bug this tool already hit once
//     (an unhandled Grafana variable kind made the whole document appear to validate
//     cleanly while actually checking nothing) - it must not be reintroduced here.
func validateRuleManifest(data []byte) (int, validationErrors) {
	var manifest ruleManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return 0, validationErrors{fmt.Sprintf("decode rule manifest JSON: %v", err)}
	}

	if manifest.Kind == "Folder" {
		return 0, nil
	}
	if !ruleKinds[manifest.Kind] {
		return 0, validationErrors{fmt.Sprintf(
			"unrecognized rule manifest kind %q (want AlertRule, RecordingRule or Folder)",
			manifest.Kind)}
	}

	var refIDs []string
	for refID := range manifest.Spec.Expressions {
		refIDs = append(refIDs, refID)
	}
	sort.Strings(refIDs)

	validated := 0
	var diagnostics validationErrors
	for _, refID := range refIDs {
		expression := manifest.Spec.Expressions[refID]
		datasourceType := expression.Model.Datasource.Type

		switch datasourceType {
		case "__expr__":
			// Server-side expression node - nothing to parse.
			continue
		case "prometheus":
			// fall through to validation below
		default:
			diagnostics = append(diagnostics, fmt.Sprintf(
				"rule %q ref %s: unrecognized expression datasource type %q "+
					"(want \"prometheus\" or \"__expr__\")",
				manifest.Spec.Title, refID, datasourceType))
			continue
		}

		promql := expression.Model.Expression
		if promql == "" {
			diagnostics = append(diagnostics, fmt.Sprintf(
				"rule %q ref %s: prometheus expression node has no expr", manifest.Spec.Title, refID))
			continue
		}

		validated++
		if err := validateExpression(grafanaTokens.Replace(promql)); err != nil {
			diagnostics = append(diagnostics, fmt.Sprintf(
				"rule %q ref %s: %v\nexpression: %s", manifest.Spec.Title, refID, err, promql))
		}
	}

	return validated, diagnostics
}
