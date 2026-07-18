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

// MetricLabelValues is the per-metric drill-down model for the
// /cardinality/label-values/{metric} page.
type MetricLabelValues struct {
	Metric string
	Series int
	Labels []LabelValueGroup
	Found  bool
}

// LabelValueGroup is one label's observed values on a single metric.
type LabelValueGroup struct {
	Name   string
	Values []LabelValueCount // sorted by count desc, then value asc
}

// LabelValueCount is one label value and how many series carry it.
type LabelValueCount struct {
	Value string
	Count int
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

// buildMetricLabelValues computes the per-label value breakdown for a single
// metric family. Found is false when the metric is not present in the snapshot.
func buildMetricLabelValues(families []*dto.MetricFamily, metric string) MetricLabelValues {
	out := MetricLabelValues{Metric: metric}
	var target *dto.MetricFamily
	for _, mf := range families {
		if mf.GetName() == metric {
			target = mf
			break
		}
	}
	if target == nil {
		return out
	}
	out.Found = true
	out.Series = len(target.GetMetric())

	counts := map[string]map[string]int{}
	order := []string{}
	for _, m := range target.GetMetric() {
		for _, lp := range m.GetLabel() {
			ln := lp.GetName()
			if _, ok := counts[ln]; !ok {
				counts[ln] = map[string]int{}
				order = append(order, ln)
			}
			counts[ln][lp.GetValue()]++
		}
	}
	sort.Strings(order)
	for _, ln := range order {
		grp := LabelValueGroup{Name: ln}
		for v, c := range counts[ln] {
			grp.Values = append(grp.Values, LabelValueCount{Value: v, Count: c})
		}
		sort.Slice(grp.Values, func(i, j int) bool {
			if grp.Values[i].Count != grp.Values[j].Count {
				return grp.Values[i].Count > grp.Values[j].Count
			}
			return grp.Values[i].Value < grp.Values[j].Value
		})
		out.Labels = append(out.Labels, grp)
	}
	return out
}

// init registers the cardinality page area's routes. New page areas register
// themselves the same way (see server.go's extension docs) so no central file
// edit is required.
func init() { registerRoutes((*Server).registerCardinality) }

// registerCardinality mounts the cardinality hub, its drill-down pages, the
// export attachment, and the JSON twin.
func (s *Server) registerCardinality(mux *http.ServeMux) {
	mux.HandleFunc("GET /cardinality", s.handleCardinality)
	mux.HandleFunc("GET /cardinality/all-metrics", s.handleCardinalityAllMetrics)
	mux.HandleFunc("GET /cardinality/all-labels", s.handleCardinalityAllLabels)
	mux.HandleFunc("GET /cardinality/label-values/{metric}", s.handleCardinalityLabelValues)
	mux.HandleFunc("GET /cardinality/export.json", s.handleCardinalityExport)
	mux.HandleFunc("GET /api/cardinality.json", s.handleCardinalityJSON)
}

// cardinalityPage is the render envelope shared by the cardinality pages. Each
// template reads the fields it needs; unused fields stay zero.
type cardinalityPage struct {
	Report      CardinalityReport
	HeadMetrics []MetricCard      // capped list for the hub
	HeadLabels  []LabelCard       // capped list for the hub
	LabelValues MetricLabelValues // populated only on the drill-down page
	Hot         int               // Warn+Crit, precomputed (no template add func)
	Empty       bool
	ScrapeAge   string
}

// cardinalitySnapshot builds the report from the passive metrics snapshot and
// derives the empty-state / scrape-age chrome. It never gathers.
func (s *Server) cardinalitySnapshot() (CardinalityReport, bool, string) {
	var families []*dto.MetricFamily
	var at time.Time
	if s.deps.Metrics != nil {
		families, at = s.deps.Metrics()
	}
	rep := buildCardinality(families, warnCardinality, critCardinality)
	rep.Generated = time.Now()
	if s.growth != nil {
		rep.Growth = s.growth.rows()
	}
	empty := at.IsZero()
	age := "never"
	if !empty {
		age = shortDur(time.Since(at)) + " ago"
	}
	return rep, empty, age
}

func headMetrics(in []MetricCard, n int) []MetricCard {
	if len(in) > n {
		return in[:n]
	}
	return in
}

func headLabels(in []LabelCard, n int) []LabelCard {
	if len(in) > n {
		return in[:n]
	}
	return in
}

func (s *Server) renderCardinality(w http.ResponseWriter, page string, id, title string, data cardinalityPage) {
	v := s.newView(id, title, data)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := renderPage(w, page, v); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

func (s *Server) handleCardinality(w http.ResponseWriter, _ *http.Request) {
	rep, empty, age := s.cardinalitySnapshot()
	s.renderCardinality(w, "cardinality.html.tmpl", "cardinality", "Cardinality", cardinalityPage{
		Report:      rep,
		HeadMetrics: headMetrics(rep.TopMetrics, 15),
		HeadLabels:  headLabels(rep.TopLabels, 15),
		Hot:         rep.Warn + rep.Crit,
		Empty:       empty,
		ScrapeAge:   age,
	})
}

func (s *Server) handleCardinalityAllMetrics(w http.ResponseWriter, _ *http.Request) {
	rep, empty, age := s.cardinalitySnapshot()
	s.renderCardinality(w, "cardinality_all_metrics.html.tmpl", "cardinality", "Cardinality · Metrics", cardinalityPage{
		Report:    rep,
		Empty:     empty,
		ScrapeAge: age,
	})
}

func (s *Server) handleCardinalityAllLabels(w http.ResponseWriter, _ *http.Request) {
	rep, empty, age := s.cardinalitySnapshot()
	s.renderCardinality(w, "cardinality_all_labels.html.tmpl", "cardinality", "Cardinality · Labels", cardinalityPage{
		Report:    rep,
		Empty:     empty,
		ScrapeAge: age,
	})
}

func (s *Server) handleCardinalityLabelValues(w http.ResponseWriter, r *http.Request) {
	metric := r.PathValue("metric")
	var families []*dto.MetricFamily
	var at time.Time
	if s.deps.Metrics != nil {
		families, at = s.deps.Metrics()
	}
	empty := at.IsZero()
	age := "never"
	if !empty {
		age = shortDur(time.Since(at)) + " ago"
	}
	s.renderCardinality(w, "cardinality_label_values.html.tmpl", "cardinality", "Cardinality · "+metric, cardinalityPage{
		LabelValues: buildMetricLabelValues(families, metric),
		Empty:       empty,
		ScrapeAge:   age,
	})
}

func (s *Server) handleCardinalityJSON(w http.ResponseWriter, _ *http.Request) {
	rep, _, _ := s.cardinalitySnapshot()
	writeJSON(w, rep)
}

func (s *Server) handleCardinalityExport(w http.ResponseWriter, _ *http.Request) {
	rep, _, _ := s.cardinalitySnapshot()
	w.Header().Set("Content-Disposition", `attachment; filename="cardinality.json"`)
	writeJSON(w, rep)
}
