package webui

import (
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/rknightion/opnsense-exporter/internal/collector"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

// Status is the full data model rendered by the status console page and
// encoded verbatim by /api/status.json. It is built by buildStatus from the
// passive StatusTracker snapshot, the last-scrape metric families, and the
// API-client cache view — never from a live Gather().
type Status struct {
	Service    ServiceInfo
	Health     string // healthy|degraded|starting
	Reasons    []string
	Stats      ExporterStats
	Collectors []CollectorRow
	Skipped    []SkippedRow
	Cache      []CacheRow
	API        APIStats
	ScrapeAge  string // "Ns ago" style; "never" if no capture yet
	Generated  time.Time
}

// ServiceInfo is the identity/uptime header shown at the top of the console.
type ServiceInfo struct{ Name, Version, GoVersion, Host, Instance, Uptime, Start string }

// ExporterStats are the three headline counts on the status tiles.
type ExporterStats struct{ ActiveCollectors, MetricFamilies, Series int }

// CollectorRow is one row of the per-collector table. SuccessRate is -1 when
// the collector has never run. Sparkline/Outcomes are pre-rendered SVG/HTML.
//
// Interval/Next-run/Freshness are derived from the poll scheduler (#336): each
// collector polls on its own interval, so NextRun = LastFinished + Interval and
// Freshness = now - LastFinished. FreshnessState is "fresh", "stale" (age beyond
// 2× interval — more than a poll-cycle overdue), or "none" (never run).
type CollectorRow struct {
	Name, Display, State        string // state: ok|failing|starting
	SuccessRate                 float64
	Runs, Failures, Consecutive uint64
	LastDurationMs              float64
	Staleness, LastError        string
	Sparkline, Outcomes         template.HTML
	IntervalSec                 int
	NextRunIn                   string // "45s" | "due" | "" (never run)
	NextRunInSec                int
	Freshness                   string // "15s ago" | "" (never run)
	FreshnessState              string // fresh|stale|none
	HasRun                      bool
	LastSuccess                 bool
}

// SkippedRow is a configured collector that has no run history yet (disabled or
// not scraped since start).
type SkippedRow struct{ Name, Display, Reason string }

// CacheRow is one held response-cache entry rendered on the freshness card.
type CacheRow struct {
	Endpoint, Path, TTL, Remaining string
	StatusCode                     int
	PluginGated                    bool
}

// APIStats summarise the exporter's OPNsense API traffic from the last scrape.
// AvgMs is the mean request duration (SampleSum/SampleCount), NOT a quantile.
type APIStats struct {
	AuthOK    bool
	Requests  float64
	AvgMs     float64
	TopErrors []ErrRow
}

// ErrRow is one endpoint's error count for the API card's top-errors list.
type ErrRow struct {
	Endpoint string
	Count    float64
}

// successRate returns the percentage of successful runs, or -1 when the
// collector has never run (Runs==0).
func successRate(runs, failures uint64) float64 {
	if runs == 0 {
		return -1
	}
	return 100 * float64(runs-failures) / float64(runs)
}

// deriveHealth reduces the per-collector snapshot to a single health verdict
// plus human reasons. Precedence: degraded (any collector's last run failed)
// beats starting (any tracked collector not yet run, or no history at all);
// otherwise healthy.
func deriveHealth(stats []collector.CollectorStat) (string, []string) {
	if len(stats) == 0 {
		return "starting", []string{"no collector has run yet"}
	}
	var reasons []string
	degraded, starting := false, false
	for _, s := range stats {
		if s.Runs == 0 {
			starting = true
			continue
		}
		if !s.LastOK {
			degraded = true
			reason := s.Display + ": " + firstNonEmpty(s.LastError, "last run failed")
			if s.ConsecutiveFails >= 3 {
				reason += fmt.Sprintf(" (%d consecutive)", s.ConsecutiveFails)
			}
			reasons = append(reasons, reason)
		}
	}
	switch {
	case degraded:
		return "degraded", reasons
	case starting:
		return "starting", reasons
	default:
		return "healthy", nil
	}
}

// buildStatus assembles the Status model. It is pure over its inputs and never
// triggers a scrape. ScrapeAge/Generated are set by the caller (they depend on
// the snapshot capture time, which is passed separately).
func buildStatus(stats []collector.CollectorStat, families []*dto.MetricFamily, cache []opnsense.CacheEntryView, svc ServiceInfo, allNames []string) Status {
	health, reasons := deriveHealth(stats)

	series := 0
	for _, mf := range families {
		series += len(mf.GetMetric())
	}

	rows := make([]CollectorRow, 0, len(stats))
	tracked := make(map[string]struct{}, len(stats))
	for _, s := range stats {
		tracked[s.Name] = struct{}{}
		rows = append(rows, collectorRow(s))
	}

	skipped := make([]SkippedRow, 0)
	for _, name := range allNames {
		if _, ok := tracked[name]; ok {
			continue
		}
		display := collector.SubsystemDisplayNames[name]
		if display == "" {
			display = name
		}
		skipped = append(skipped, SkippedRow{Name: name, Display: display, Reason: "disabled or not yet scraped"})
	}
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].Display < skipped[j].Display })

	cacheRows := make([]CacheRow, 0, len(cache))
	for _, e := range cache {
		cacheRows = append(cacheRows, CacheRow{
			Endpoint:    e.Endpoint,
			Path:        e.Path,
			TTL:         shortDur(e.TTL),
			Remaining:   shortDur(e.Remaining),
			StatusCode:  e.StatusCode,
			PluginGated: e.PluginGated,
		})
	}

	return Status{
		Service: svc,
		Health:  health,
		Reasons: reasons,
		Stats: ExporterStats{
			ActiveCollectors: len(stats),
			MetricFamilies:   len(families),
			Series:           series,
		},
		Collectors: rows,
		Skipped:    skipped,
		Cache:      cacheRows,
		API:        parseAPIStats(families),
	}
}

func collectorRow(s collector.CollectorStat) CollectorRow {
	state := "ok"
	switch {
	case s.Runs == 0:
		state = "starting"
	case !s.LastOK:
		state = "failing"
	}

	hasRun := s.Runs > 0
	intervalSec := int(s.Interval / time.Second)
	nextRunIn, nextRunInSec := "", 0
	freshness, freshnessState := "", "none"
	if hasRun && !s.LastFinished.IsZero() {
		age := time.Since(s.LastFinished)
		freshness = shortDur(age) + " ago"
		freshnessState = "fresh"
		if s.Interval > 0 && age > 2*s.Interval {
			freshnessState = "stale"
		}
		if s.Interval > 0 {
			until := time.Until(s.LastFinished.Add(s.Interval))
			nextRunInSec = int(until / time.Second)
			if until <= 0 {
				nextRunIn = "due"
			} else {
				nextRunIn = shortDur(until)
			}
		}
	}

	return CollectorRow{
		Name:           s.Name,
		Display:        s.Display,
		State:          state,
		SuccessRate:    successRate(s.Runs, s.Failures),
		Runs:           s.Runs,
		Failures:       s.Failures,
		Consecutive:    s.ConsecutiveFails,
		LastDurationMs: s.LastDurationMs,
		Staleness:      staleness(s.LastFinished),
		LastError:      s.LastError,
		Sparkline:      sparkline(s.DurationMs),
		Outcomes:       outcomeStrip(s.Outcomes),
		IntervalSec:    intervalSec,
		NextRunIn:      nextRunIn,
		NextRunInSec:   nextRunInSec,
		Freshness:      freshness,
		FreshnessState: freshnessState,
		HasRun:         hasRun,
		LastSuccess:    s.LastOK,
	}
}

// parseAPIStats reads the exporter's self-metrics out of the last-scrape family
// set: request count (sum), mean duration in ms (SampleSum/SampleCount over the
// histogram) and the top endpoints by error count. Families are matched by name
// suffix so the "opnsense_" namespace prefix is tolerated.
func parseAPIStats(families []*dto.MetricFamily) APIStats {
	api := APIStats{AuthOK: true}

	if mf := familyBySuffix(families, "exporter_api_requests_total"); mf != nil {
		for _, m := range mf.GetMetric() {
			v := m.GetCounter().GetValue()
			api.Requests += v
			if code := labelValue(m, "code"); v > 0 && (code == "401" || code == "403") {
				api.AuthOK = false
			}
		}
	}

	if mf := familyBySuffix(families, "exporter_api_request_duration_seconds"); mf != nil {
		var sum float64
		var count uint64
		for _, m := range mf.GetMetric() {
			h := m.GetHistogram()
			sum += h.GetSampleSum()
			count += h.GetSampleCount()
		}
		if count > 0 {
			api.AvgMs = sum / float64(count) * 1000
		}
	}

	if mf := familyBySuffix(families, "exporter_endpoint_errors_total"); mf != nil {
		agg := map[string]float64{}
		for _, m := range mf.GetMetric() {
			agg[labelValue(m, "endpoint")] += m.GetCounter().GetValue()
		}
		for ep, c := range agg {
			if c > 0 {
				api.TopErrors = append(api.TopErrors, ErrRow{Endpoint: ep, Count: c})
			}
		}
		sort.Slice(api.TopErrors, func(i, j int) bool {
			if api.TopErrors[i].Count != api.TopErrors[j].Count {
				return api.TopErrors[i].Count > api.TopErrors[j].Count
			}
			return api.TopErrors[i].Endpoint < api.TopErrors[j].Endpoint
		})
		if len(api.TopErrors) > 10 {
			api.TopErrors = api.TopErrors[:10]
		}
	}

	return api
}

func familyBySuffix(families []*dto.MetricFamily, suffix string) *dto.MetricFamily {
	for _, mf := range families {
		if strings.HasSuffix(mf.GetName(), suffix) {
			return mf
		}
	}
	return nil
}

func labelValue(m *dto.Metric, name string) string {
	for _, lp := range m.GetLabel() {
		if lp.GetName() == name {
			return lp.GetValue()
		}
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// staleness renders how long ago a collector last finished; empty when it has
// never finished.
func staleness(last time.Time) string {
	if last.IsZero() {
		return ""
	}
	return shortDur(time.Since(last)) + " ago"
}

// shortDur formats a duration compactly (e.g. "1.5s", "3m", "0s"). Negative
// durations (a just-expired cache entry) render as "expired".
func shortDur(d time.Duration) string {
	if d < 0 {
		return "expired"
	}
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%.0fm", d.Minutes())
	default:
		return fmt.Sprintf("%.1fh", d.Hours())
	}
}
