package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/prometheus/prometheus/promql/parser"
)

var (
	grafanaTokens = strings.NewReplacer(
		"$__rate_interval", "5m",
		"$opnsense_instance", "fixture",
		"$device", "fixture",
		"$interface", "fixture",
	)
	unknownGrafanaToken = regexp.MustCompile(
		`\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)`,
	)
)

type dashboard struct {
	Spec struct {
		Elements map[string]element `json:"elements"`
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

func validateDashboard(data []byte) (int, error) {
	var document dashboard
	if err := json.Unmarshal(data, &document); err != nil {
		return 0, fmt.Errorf("decode dashboard JSON: %w", err)
	}

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
		normalized := grafanaTokens.Replace(query.Expression)
		if token := unknownGrafanaToken.FindString(normalized); token != "" {
			diagnostics = append(diagnostics, fmt.Sprintf(
				"panel %d %q ref %s: unknown Grafana token %q\nexpression: %s",
				query.PanelID,
				query.PanelTitle,
				query.RefID,
				token,
				query.Expression,
			))
			continue
		}

		p := parser.NewParser(parser.Options{})
		if _, err := p.ParseExpr(normalized); err != nil {
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

	if len(diagnostics) > 0 {
		return prometheusTargets, diagnostics
	}
	return prometheusTargets, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: promqlcheck <dashboard.json>")
		os.Exit(2)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read dashboard: %v\n", err)
		os.Exit(1)
	}
	count, err := validateDashboard(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("validated %d Prometheus targets\n", count)
}
