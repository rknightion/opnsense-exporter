package webui

import (
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/rknightion/opnsense2otel/v4/internal/collector"
	"github.com/rknightion/opnsense2otel/v4/internal/metricsnap"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// Status is the full data model rendered by the status console page and
// encoded verbatim by /api/status.json. It is built by buildStatus from the
// passive StatusTracker snapshot, the last-scrape metric families, and the
// API-client cache view — never from a live Gather().
type Status struct {
	Service     ServiceInfo
	Health      string // healthy|degraded|starting
	Reasons     []string
	Upstream    UpstreamHealth
	Stats       ExporterStats
	Collectors  []CollectorRow
	Skipped     []SkippedRow
	Cache       []CacheRow
	API         APIStats
	Runtime     RuntimeStats
	Trend       TrendStats
	Cardinality CardinalityReport
	Pipeline    PipelineStats
	Capture     CaptureInfo
	ScrapeAge   string // "Ns ago" style; "never" if no capture yet
	Generated   time.Time
}

// UpstreamHealth is the console's view of the scheduler's passive upstream-health
// state (#384): whether the OPNsense box itself is answering, independent of
// collector run history. It is populated from collector.HealthSnapshot without an
// API call or a registry gather.
type UpstreamHealth struct {
	// Known is false when no health seam is wired at all (Deps.Health nil). The
	// console then says nothing about the box rather than claiming it is fine.
	Known bool
	// State is one of: ok (last check passed), unreachable (transport-level
	// failure — nothing answered), error (box answered but the check failed),
	// pending (no check has completed yet), unknown (Known false).
	State      string
	Polled     bool
	CheckOK    bool
	Reason     string // bounded; empty when ok/pending/unknown
	CheckedAgo string // "15s ago"; "never" before the first completed check
}

// CaptureInfo describes the passive metric capture the whole console is rendered
// from (#389). The recorder now stores families that arrived WITH a gather error,
// so the console shows current data during a persistent consistency error instead
// of being pinned to an old snapshot — which is only honest if the page says the
// capture was partial.
//
// No unbounded error string is ever carried here: the recorder stores counts and
// timestamps only.
type CaptureInfo struct {
	// State is full (clean gather), partial (families arrived with an error) or
	// never (nothing captured yet).
	State        string
	Partial      bool
	Age          string // "15s ago"; "never" before the first capture
	ErrorCount   uint64 // cumulative erroring gathers, never reset
	LastErrorAt  string // RFC3339 of the last erroring gather; "" if never
	LastErrorAgo string // "3s ago"; "" if never
}

// ServiceInfo is the identity/uptime header shown at the top of the console.
type ServiceInfo struct{ Name, Version, GoVersion, Host, Instance, Uptime, Start string }

// ExporterStats are the three headline counts on the status tiles.
type ExporterStats struct{ ActiveCollectors, MetricFamilies, Series int }

// CollectorRow is one row of the per-collector table. SuccessRate is -1 when
// the collector has never run. Sparkline/Outcomes are pre-rendered SVG/HTML.
//
// # Two clocks, never conflated (#382)
//
// Error-aware retention deliberately keeps a collector's last-good metrics when a
// later poll fails without emitting anything, so a collector that has failed every
// minute for six hours is still replaying six-hour-old values — while every failed
// retry refreshes the ATTEMPT clock. Freshness therefore comes from the DATA clock
// (CollectorStat.SnapshotAt: when the stored buffer was last replaced), and the
// attempt clock is surfaced separately as AttemptAge. Neither may be labelled as
// the other.
//
//   - Freshness / DataAgeSec / FreshnessState / HasData — data age, from SnapshotAt.
//     FreshnessState is "fresh", "stale" (data older than 2× interval, i.e. more
//     than a poll cycle overdue) or "none" (nothing stored yet).
//   - AttemptAge / AttemptAgeSec / Staleness — last poll ATTEMPT, from LastFinished.
//   - LastSuccessAgo — last fully clean poll, from LastSuccessAt.
//
// Next-run comes from the scheduler's real deadline (CollectorStat.NextDeadline,
// #385), never from LastFinished + Interval: the recomputed value runs late by the
// poll duration and is a whole cadence wrong after a poll that overran. A zero
// deadline means no poll is scheduled at all — Scheduled is false and NextRunIn
// says so rather than showing a countdown or claiming a run is due.
type CollectorRow struct {
	Name, Display, State        string // state: ok|failing|starting
	SuccessRate                 float64
	Runs, Failures, Consecutive uint64
	LastDurationMs              float64
	// Staleness is the last-ATTEMPT age. Retained for compatibility; AttemptAge is
	// the same value under an unambiguous name.
	Staleness, LastError string
	Sparkline, Outcomes  template.HTML
	IntervalSec          int
	NextRunIn            string // "45s" | "due" | "not scheduled"
	NextRunInSec         int    // seconds to the scheduler deadline; -1 when unscheduled
	Scheduled            bool   // the scheduler has a real next deadline for this collector

	Freshness      string // DATA age, "15s ago"; "" when nothing is stored
	FreshnessState string // fresh|stale|none
	DataAgeSec     int    // DATA age in seconds; -1 when nothing is stored
	HasData        bool   // the collector has stored a metric buffer at least once

	AttemptAge    string // last-ATTEMPT age, "15s ago"; "" when never attempted
	AttemptAgeSec int    // last-ATTEMPT age in seconds; -1 when never attempted

	LastSuccessAgo string // last fully clean poll, "3m ago"; "" when never

	HasRun      bool
	LastSuccess bool
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
	// AuthOK is retained for JSON compatibility: true means no 401/403 was
	// recorded in the process-lifetime counters, not proof of current access.
	AuthOK   bool
	Requests float64
	AvgMs    float64
	// AuthFailures lists every endpoint the captured lifetime counters record a 401/403 for, with
	// the collector behind it and the OPNsense privilege that would fix it (#442).
	// AuthOK is the same signal collapsed to a badge; this is what makes it
	// actionable. Empty whenever AuthOK is true.
	AuthFailures []AuthzRow
	TopErrors    []ErrRow
}

// AuthzRow is one endpoint OPNsense refused on authentication or authorisation,
// joined with the exporter's endpoint→collector→privilege matrix.
//
// It carries no credential material: every field is derived from the endpoint
// path, the HTTP status and opnsense's static ACL table. The response body is
// deliberately not surfaced here.
type AuthzRow struct {
	// Endpoint is the api/* path from the self-metric's endpoint label.
	Endpoint string
	// Code is "401" or "403".
	Code string
	// Count is how many such responses the last scrape's counters hold.
	Count float64
	// Collector is the collector subsystem that calls the endpoint, or a
	// parenthesised non-collector consumer.
	Collector string
	// Component is "core" or the plugin's ports path.
	Component string
	// ACLStatus is "known", "plugin-dependent" or "unknown".
	ACLStatus string
	// Privilege is the ACL key(s) to grant — comma-separated when any one of
	// several suffices, or "page-all" when nothing narrower covers the URL.
	Privilege string
	// Hint is the full operator-facing sentence.
	Hint string
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

// maxUpstreamReason bounds the upstream health reason rendered into the console
// and /api/status.json. The scheduler already bounds HealthSnapshot.LastError;
// this is belt-and-braces so an unbounded transport error can never reach a page.
const maxUpstreamReason = 200

// deriveHealth reduces the per-collector snapshot plus the scheduler's upstream
// health state to a single verdict and its human reasons.
//
// Collector run history alone is NOT sufficient (#384): during a transport
// outage the scheduler deliberately SKIPS collector polls, so no failed run is
// ever recorded and every collector's last run keeps reading OK while
// opnsense_up is zero and readiness is failing. A failed upstream health check
// therefore takes precedence over otherwise-successful collector history, and
// its reason leads the list.
//
// Precedence: degraded (failed health check, or any collector's last run failed)
// beats starting (health check not yet run, any tracked collector not yet run,
// or no history at all); otherwise healthy.
//
// upstream may be nil when no health seam is wired, in which case the verdict
// falls back to collector history exactly as it did before.
func deriveHealth(stats []collector.CollectorStat, upstream *collector.HealthSnapshot) (string, []string) {
	upReason, upDegraded, upStarting := upstreamVerdict(upstream)

	if len(stats) == 0 {
		reasons := []string{"no collector has run yet"}
		if upReason != "" {
			reasons = append([]string{upReason}, reasons...)
		}
		if upDegraded {
			return "degraded", reasons
		}
		return "starting", reasons
	}

	var reasons []string
	if upReason != "" {
		reasons = append(reasons, upReason)
	}
	degraded, starting := upDegraded, upStarting
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
		return "healthy", reasons
	}
}

// upstreamVerdict turns a scheduler health snapshot into its contribution to the
// top-level verdict: a bounded human reason (empty when there is nothing to say)
// and whether it forces degraded or starting.
//
// Transport failure and reachable-but-erroring are worded distinctly on purpose:
// a box answering HTTP 500 must degrade the verdict without the console claiming
// nothing answered.
func upstreamVerdict(h *collector.HealthSnapshot) (reason string, degraded, starting bool) {
	if h == nil {
		return "", false, false
	}
	if !h.Polled {
		return "OPNsense API health check has not completed yet", false, true
	}
	if h.CheckOK {
		return "", false, false
	}
	if h.Unreachable {
		return withDetail("OPNsense API unreachable", h.LastError), true, false
	}
	return withDetail("OPNsense API health check failed (box answered)", h.LastError), true, false
}

// withDetail appends a bounded detail to a fixed prefix. The detail is truncated
// rather than dropped so an operator still sees the head of the transport error.
func withDetail(prefix, detail string) string {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return prefix
	}
	if len(detail) > maxUpstreamReason {
		detail = detail[:maxUpstreamReason] + "…"
	}
	return prefix + ": " + detail
}

// buildStatus assembles the Status model. It is pure over its inputs and never
// triggers a scrape: capt is an already-taken passive metric capture and upstream
// an already-taken scheduler health snapshot (nil when no health seam is wired).
// Generated is set by the caller.
func buildStatus(stats []collector.CollectorStat, capt metricsnap.Capture, cache []opnsense.CacheEntryView, svc ServiceInfo, allNames []string, upstream *collector.HealthSnapshot) Status {
	health, reasons := deriveHealth(stats, upstream)

	families := capt.Families
	series := countSeries(families)

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

	captureInfo := captureInfo(capt)

	return Status{
		Service:  svc,
		Health:   health,
		Reasons:  reasons,
		Upstream: upstreamHealth(upstream),
		Stats: ExporterStats{
			ActiveCollectors: len(stats),
			MetricFamilies:   len(families),
			Series:           series,
		},
		Collectors: rows,
		Skipped:    skipped,
		Cache:      cacheRows,
		API:        parseAPIStats(families),
		Pipeline:   parsePipelineStats(families),
		Capture:    captureInfo,
		ScrapeAge:  captureInfo.Age,
	}
}

// captureInfo renders the passive metric capture's metadata for the console.
//
// A partial capture (#389) is CURRENT data that arrived alongside a gather error:
// the real /metrics and OTLP paths both continue on error and serve those families,
// so the recorder stores them too rather than leaving the console pinned to an old
// snapshot. The console keeps showing the current family/series/API numbers and
// says the capture was partial — it does not pretend the gather was clean, and it
// does not pretend the data is old.
//
// Only counts and timestamps cross this boundary. No error string is stored by the
// recorder, so none can reach a page — and none is ever put in a label.
func captureInfo(c metricsnap.Capture) CaptureInfo {
	info := CaptureInfo{
		State:      "never",
		Partial:    c.Partial,
		Age:        "never",
		ErrorCount: c.ErrorCount,
	}
	if !c.At.IsZero() {
		info.Age = shortDur(time.Since(c.At)) + " ago"
		info.State = "full"
		if c.Partial {
			info.State = "partial"
		}
	}
	if !c.LastErrorAt.IsZero() {
		info.LastErrorAt = c.LastErrorAt.Format(time.RFC3339)
		info.LastErrorAgo = shortDur(time.Since(c.LastErrorAt)) + " ago"
	}
	return info
}

// upstreamHealth renders the scheduler health snapshot into the console model.
// A nil snapshot is "unknown" — no health seam is wired, so the console must not
// imply the box has been checked and found fine.
func upstreamHealth(h *collector.HealthSnapshot) UpstreamHealth {
	if h == nil {
		return UpstreamHealth{State: "unknown", CheckedAgo: "never"}
	}
	reason, _, _ := upstreamVerdict(h)
	u := UpstreamHealth{
		Known:      true,
		Polled:     h.Polled,
		CheckOK:    h.CheckOK,
		Reason:     reason,
		CheckedAgo: "never",
	}
	if !h.CheckedAt.IsZero() {
		u.CheckedAgo = shortDur(time.Since(h.CheckedAt)) + " ago"
	}
	switch {
	case !h.Polled:
		u.State = "pending"
	case h.CheckOK:
		u.State = "ok"
	case h.Unreachable:
		u.State = "unreachable"
	default:
		u.State = "error"
	}
	return u
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

	// DATA age — from the snapshot clock, NOT the attempt clock. A collector whose
	// every poll has failed for hours keeps refreshing LastFinished while replaying
	// hours-old values; calling that "fresh" is the bug this fixes (#382).
	hasData := !s.SnapshotAt.IsZero()
	freshness, freshnessState, dataAgeSec := "", "none", -1
	if hasData {
		age := time.Since(s.SnapshotAt)
		freshness = shortDur(age) + " ago"
		freshnessState = "fresh"
		if s.Interval > 0 && age > 2*s.Interval {
			freshnessState = "stale"
		}
		dataAgeSec = int(age / time.Second)
	}

	// ATTEMPT age — kept visible, deliberately under its own name.
	attemptAge, attemptAgeSec := "", -1
	if !s.LastFinished.IsZero() {
		age := time.Since(s.LastFinished)
		attemptAge = shortDur(age) + " ago"
		attemptAgeSec = int(age / time.Second)
	}

	lastSuccessAgo := ""
	if !s.LastSuccessAt.IsZero() {
		lastSuccessAgo = shortDur(time.Since(s.LastSuccessAt)) + " ago"
	}

	// NEXT RUN — the scheduler's real deadline. A zero deadline means nothing is
	// scheduled, which is a different statement from "a run is due".
	scheduled := !s.NextDeadline.IsZero()
	nextRunIn, nextRunInSec := "not scheduled", -1
	if scheduled {
		until := time.Until(s.NextDeadline)
		nextRunInSec = int(until / time.Second)
		if until <= 0 {
			nextRunIn = "due"
		} else {
			nextRunIn = shortDur(until)
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
		Scheduled:      scheduled,
		Freshness:      freshness,
		FreshnessState: freshnessState,
		DataAgeSec:     dataAgeSec,
		HasData:        hasData,
		AttemptAge:     attemptAge,
		AttemptAgeSec:  attemptAgeSec,
		LastSuccessAgo: lastSuccessAgo,
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
			code := labelValue(m, "code")
			if v > 0 && (code == "401" || code == "403") {
				api.AuthOK = false
				api.AuthFailures = append(api.AuthFailures, authzRow(labelValue(m, "endpoint"), code, v))
			}
		}
		sort.Slice(api.AuthFailures, func(i, j int) bool {
			if api.AuthFailures[i].Count != api.AuthFailures[j].Count {
				return api.AuthFailures[i].Count > api.AuthFailures[j].Count
			}
			return api.AuthFailures[i].Endpoint < api.AuthFailures[j].Endpoint
		})
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

// authzRow joins one refused endpoint with the ACL matrix. An endpoint the matrix
// does not know still produces a row — with the fact stated, not a guessed
// privilege — because a 403 the console cannot explain is still a 403 the operator
// needs to see.
func authzRow(endpoint, code string, count float64) AuthzRow {
	row := AuthzRow{Endpoint: endpoint, Code: code, Count: count}

	statusCode := http.StatusForbidden
	if code == "401" {
		statusCode = http.StatusUnauthorized
	}
	apiErr := opnsense.APICallError{Endpoint: endpoint, StatusCode: statusCode}
	row.Hint = apiErr.AuthzHint()

	acl, ok := opnsense.ACLForPath(endpoint)
	if !ok {
		row.Collector = "unknown"
		row.Component = "unknown"
		row.ACLStatus = "unclassified"
		row.Privilege = "unknown"
		return row
	}
	row.Collector = acl.Consumer
	row.Component = acl.Component
	row.ACLStatus = string(acl.Status)
	if acl.Status == opnsense.ACLStatusUnknown {
		// No ACL unit covers this URL, so page-all is the only honest answer.
		row.Privilege = "page-all"
	} else {
		row.Privilege = strings.Join(acl.PrivilegeKeys(), ", ")
	}
	return row
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

// staleness renders how long ago a collector's last poll ATTEMPT finished; empty
// when it has never finished one. This is not data freshness — see CollectorRow.
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
