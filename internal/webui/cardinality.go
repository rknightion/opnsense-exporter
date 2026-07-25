package webui

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	dto "github.com/prometheus/client_model/go"
)

// Default cardinality thresholds (series-per-metric). A metric at or above
// warnCardinality is flagged for review; at or above critCardinality it is an
// alert. These match the plan's defaults.
const (
	warnCardinality = 500
	critCardinality = 2000
)

// CardinalityReport is the pure cardinality model built from a passive scrape
// snapshot. It is rendered by the /cardinality pages and encoded verbatim by
// /api/cardinality.json and /cardinality/export.json. buildCardinality is pure
// over its []*dto.MetricFamily input and never triggers a scrape.
type CardinalityReport struct {
	TotalFamilies   int
	TotalSeries     int
	WarnThreshold   int
	CritThreshold   int
	Warn            int          // metrics at warn level (>= warn, < crit)
	Crit            int          // metrics at crit level (>= crit)
	TopMetrics      []MetricCard // every family, sorted by series desc
	TopLabels       []LabelCard  // every label, sorted by distinct values desc
	Alerts          []string     // crit-level metrics, human readable
	Recommendations []string     // warn-level metrics, human readable
	Growth          []GrowthRow  // per-minute series growth over the sampling window
	Generated       time.Time
}

// GrowthRow is one metric family's series growth rate, derived from the
// background growth sampler's ring (oldest→newest over the window).
type GrowthRow struct {
	Name   string
	Series int     // current series count
	PerMin float64 // series added/removed per minute over the window (signed)
}

// MetricCard is one metric family's cardinality summary.
type MetricCard struct {
	Name   string
	Series int
	Labels int    // distinct label names on the family
	Level  string // ok|warn|crit
}

// LabelCard is one label name's cross-family cardinality summary.
type LabelCard struct {
	Name           string
	DistinctValues int
	Families       int // number of families that use this label
}

// cardLevel classifies a metric's series count against the thresholds.
func cardLevel(series, warn, crit int) string {
	switch {
	case series >= crit:
		return "crit"
	case series >= warn:
		return "warn"
	default:
		return "ok"
	}
}

// buildCardinality reduces the metric families to the cardinality report. It is
// pure and never gathers. warn/crit are the series-per-metric thresholds.
func buildCardinality(families []*dto.MetricFamily, warn, crit int) CardinalityReport {
	rep := CardinalityReport{WarnThreshold: warn, CritThreshold: crit}

	type labelAgg struct {
		values   map[string]struct{}
		families map[string]struct{}
	}
	labels := map[string]*labelAgg{}

	for _, mf := range families {
		name := mf.GetName()
		metrics := mf.GetMetric()
		series := len(metrics)
		rep.TotalFamilies++
		rep.TotalSeries += series

		labelNames := map[string]struct{}{}
		for _, m := range metrics {
			for _, lp := range m.GetLabel() {
				ln := lp.GetName()
				labelNames[ln] = struct{}{}
				agg := labels[ln]
				if agg == nil {
					agg = &labelAgg{values: map[string]struct{}{}, families: map[string]struct{}{}}
					labels[ln] = agg
				}
				agg.values[lp.GetValue()] = struct{}{}
				agg.families[name] = struct{}{}
			}
		}

		level := cardLevel(series, warn, crit)
		switch level {
		case "crit":
			rep.Crit++
			rep.Alerts = append(rep.Alerts, fmt.Sprintf("%s has %d series (critical — at or above %d)", name, series, crit))
		case "warn":
			rep.Warn++
			rep.Recommendations = append(rep.Recommendations, fmt.Sprintf("%s has %d series (review — at or above %d)", name, series, warn))
		}
		rep.TopMetrics = append(rep.TopMetrics, MetricCard{
			Name:   name,
			Series: series,
			Labels: len(labelNames),
			Level:  level,
		})
	}

	sort.Slice(rep.TopMetrics, func(i, j int) bool {
		if rep.TopMetrics[i].Series != rep.TopMetrics[j].Series {
			return rep.TopMetrics[i].Series > rep.TopMetrics[j].Series
		}
		return rep.TopMetrics[i].Name < rep.TopMetrics[j].Name
	})

	for name, agg := range labels {
		rep.TopLabels = append(rep.TopLabels, LabelCard{
			Name:           name,
			DistinctValues: len(agg.values),
			Families:       len(agg.families),
		})
	}
	sort.Slice(rep.TopLabels, func(i, j int) bool {
		if rep.TopLabels[i].DistinctValues != rep.TopLabels[j].DistinctValues {
			return rep.TopLabels[i].DistinctValues > rep.TopLabels[j].DistinctValues
		}
		return rep.TopLabels[i].Name < rep.TopLabels[j].Name
	})

	return rep
}

// init registers the cardinality JSON endpoints. The cardinality data itself is
// rendered as a tab on the single console page (folded from the old drill-down
// pages); these endpoints remain for machine consumption and the export button.
func init() { registerRoutes((*Server).registerCardinality) }

// registerCardinality mounts the cardinality JSON twin and the export attachment.
func (s *Server) registerCardinality(mux *http.ServeMux) {
	mux.HandleFunc("GET /cardinality/export.json", s.handleCardinalityExport)
	mux.HandleFunc("GET /api/cardinality.json", s.handleCardinalityJSON)
}

// cardinalitySnapshot builds the report from the passive metrics snapshot. It
// never gathers. (The console page builds its own copy inside snapshot(); these
// endpoints keep an independent build so they work even if that changes.)
func (s *Server) cardinalitySnapshot() CardinalityReport {
	rep := buildCardinality(s.families(), warnCardinality, critCardinality)
	rep.Generated = time.Now()
	if s.growth != nil {
		rep.Growth = s.growth.rows()
	}
	return rep
}

func (s *Server) handleCardinalityJSON(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.cardinalitySnapshot())
}

func (s *Server) handleCardinalityExport(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Disposition", `attachment; filename="cardinality.json"`)
	writeJSON(w, s.cardinalitySnapshot())
}
