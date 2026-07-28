// Package webui serves the opnsense-exporter operator console: a single
// server-rendered, tabbed page (Overview / Collectors / API / Cardinality /
// Devices / Config) with inline CSS/JS and zero external assets. It mirrors the
// tailscale2otel/graph2otel fleet console standard — a manual theme toggle, a
// poll-and-patch refresh of /api/status.json, a freshness ticker, Pause/Resume,
// and a disconnect banner.
//
// No console request ever triggers a firewall scrape. The status snapshot is
// built only from Deps.Capture (a metricsnap capture), the StatusTracker, and
// the API-client cache view — never a live Gather(). Two exceptions load
// off the auto-refresh poll: the effective Config is rendered server-side once
// per full page load (EffectiveConfig reads secret files from disk), and the
// Devices tab loads /api/devices.json lazily on tab-open (the only console call
// that reaches the firewall — ARP/DHCP only, never the metric collectors).
//
// # Routes
//
// Route areas register themselves from an init() so no central edit is needed:
//
//  1. In the area file, add `func init() { registerRoutes((*Server).register<Area>) }`.
//  2. Implement `func (s *Server) register<Area>(mux *http.ServeMux)` calling
//     mux.HandleFunc("GET /<path>", s.handle<Area>).
//  3. Handlers read s.deps / s.snapshot() (never Gather).
//
// The console is one page (handlers.go's GET /), so new UI is a tab in
// templates/page.html.tmpl fed by the status snapshot, not a new route.
// Handler() iterates every registered registrar against a fresh ServeMux, so
// registration order is init order and no central edit is required.
package webui

import (
	"context"
	"net/http"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/rknightion/opnsense-exporter/internal/collector"
	"github.com/rknightion/opnsense-exporter/internal/metricsnap"
	"github.com/rknightion/opnsense-exporter/internal/options"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

// Deps is the fully-resolved set of read-only accessors the console renders
// from. main.go builds it once and hands it to NewServer. Every field is a
// snapshot func or an already-redacted model, so the console can never reach
// past these into live scrape machinery.
type Deps struct {
	Version, GoVersion, Host, InstanceLabel string
	StartTime                               time.Time
	// SeriesBudget is the soft TOTAL-series budget (#494,
	// --exporter.series-budget) the Cardinality report measures against. 0
	// disables the check. It is threaded through Deps rather than held as
	// package state so a report can never depend on hidden startup order.
	SeriesBudget int
	Tracker      *collector.StatusTracker
	// Capture returns the passive metric capture the whole console renders from
	// (metricsnap.Recorder.Capture). It carries the families, their capture time,
	// and whether that capture arrived WITH a gather error — the console must say
	// so rather than presenting partial data as a clean snapshot (#389). May be
	// nil; the console then renders a never-captured state.
	Capture func() metricsnap.Capture
	// Health returns the scheduler's passive upstream-health snapshot
	// (collector.Collector.HealthSnapshot). It makes no API call and never gathers
	// the registry. It is what lets the top-level badge report an unreachable box
	// during an outage in which the scheduler skips collector polls entirely, so
	// collector history alone stays deceptively green (#384). May be nil, in which
	// case the console says nothing about the box rather than claiming it is fine.
	Health          func() collector.HealthSnapshot
	Cache           func() []opnsense.CacheEntryView
	EffectiveConfig func() []options.ConfigSection
	Devices         func(ctx context.Context) (DeviceReport, error)
	// LogThroughput returns the log-shipping pipeline's process-lifetime totals of
	// records confirmed exported and records lost (logship.Throughput). It is nil
	// when --logs.enabled is off, which is how the console knows there is no emit
	// boundary to chart at all — see TrendStats.LogShipping.
	LogThroughput func() (shipped, dropped uint64)
	// IfIndexMap returns the resolved NetFlow ifIndex map. Nil when the flow
	// lane is disabled.
	IfIndexMap        func() IfIndexReport
	AllCollectorNames []string
	RefreshSeconds    int
	DisableConfig     bool
	DisableDevices    bool
}

// DeviceReport is the connected-devices model surfaced on the /devices page.
// The fetch/merge/OUI logic that populates it is owned by the devices lane
// (Task 8); the types are frozen here because Deps.Devices references them.
type DeviceReport struct {
	Devices   []DeviceRow
	Generated time.Time
}

// DeviceRow is one merged ARP/DHCP device entry. Expiry is populated for ARP
// rows only; Hostname is absent for DHCPv6.
type DeviceRow struct {
	IP, MAC, Hostname, Interface, Expiry, Manufacturer, Source string
}

// Server owns the resolved Deps and serves the console's HTTP handlers.
type Server struct {
	deps    Deps
	growth  *growthSampler
	runtime *runtimeSampler
	trend   *trendSampler
}

// growthSampleInterval is how often the cardinality growth ring samples the
// passive metrics snapshot. 30s × the ring size gives a ~15-minute window.
const (
	growthSampleInterval = 30 * time.Second
	growthRingSize       = 30
)

// NewServer returns a console Server over the given dependencies. Background
// growth sampling is not started until StartBackground is called (so tests that
// build a Server don't spawn a goroutine).
func NewServer(d Deps) *Server {
	trend := newTrendSampler(growthRingSize)
	trend.logShipping = d.LogThroughput != nil
	return &Server{
		deps:    d,
		growth:  newGrowthSampler(growthRingSize),
		runtime: newRuntimeSampler(growthRingSize),
		trend:   trend,
	}
}

// StartBackground begins the cardinality growth sampler, the runtime-stats
// sampler and the series/throughput/fleet trend sampler — all on the same
// cadence. Call once after NewServer; pair with Close on shutdown.
func (s *Server) StartBackground() {
	s.growth.start(s.families, growthSampleInterval)
	s.runtime.start(growthSampleInterval)
	s.trend.start(s.trendSample, growthSampleInterval)
}

// Close stops background sampling.
func (s *Server) Close() {
	s.growth.close()
	s.runtime.close()
	s.trend.close()
}

// trendSample takes one trend observation from the same passive sources the rest
// of the console reads: the metricsnap snapshot (for the exposed series count),
// the status tracker (for the fleet roll-up) and the log pipeline's raw counters.
// It never gathers and never touches the firewall.
func (s *Server) trendSample() trendSample {
	smp := trendSample{at: time.Now()}
	smp.series = countSeries(s.families())
	if s.deps.Tracker != nil {
		smp.active, smp.failing, smp.meanMs = aggregateFleet(s.deps.Tracker.Snapshot())
	}
	if s.deps.LogThroughput != nil {
		smp.shipped, smp.dropped = s.deps.LogThroughput()
	}
	return smp
}

// capture returns the latest passive metric capture, or a zero Capture when no
// recorder is wired. Every console read of the metric families goes through here
// so the partial/never-captured metadata travels with them.
func (s *Server) capture() metricsnap.Capture {
	if s.deps.Capture == nil {
		return metricsnap.Capture{}
	}
	return s.deps.Capture()
}

// families is the families-only view of capture(), for the samplers that need
// nothing else.
func (s *Server) families() []*dto.MetricFamily { return s.capture().Families }

// health returns the scheduler's upstream-health snapshot, or nil when no health
// seam is wired. Nil means "we cannot say", never "the box is fine".
func (s *Server) health() *collector.HealthSnapshot {
	if s.deps.Health == nil {
		return nil
	}
	h := s.deps.Health()
	return &h
}

// routeRegistrars is the set of per-area route registration functions. Each
// page-area file appends its registrar from an init(), so Handler() wires them
// all up without this file naming them.
var routeRegistrars []func(*Server, *http.ServeMux)

// registerRoutes appends one or more per-area registrars. Called from area
// files' init() functions.
func registerRoutes(fns ...func(*Server, *http.ServeMux)) {
	routeRegistrars = append(routeRegistrars, fns...)
}

// Handler builds the console's HTTP handler by running every registered
// per-area registrar against a fresh ServeMux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, reg := range routeRegistrars {
		reg(s, mux)
	}
	return mux
}

// pageView assembles the root value for the single-page console: the
// poll-refreshed status snapshot, the static server-rendered effective config
// (omitted when the config tab is disabled — and never re-fetched by the poll,
// since EffectiveConfig reads secret files from disk), and the refresh interval.
func (s *Server) pageView() view {
	v := view{
		Title:          "Status",
		RefreshMs:      s.deps.RefreshSeconds * 1000,
		Data:           s.snapshot(),
		DisableConfig:  s.deps.DisableConfig,
		DisableDevices: s.deps.DisableDevices,
	}
	if v.RefreshMs <= 0 {
		v.RefreshMs = 5000
	}
	if !s.deps.DisableConfig && s.deps.EffectiveConfig != nil {
		v.Config = s.deps.EffectiveConfig()
	}
	return v
}

// serviceInfo assembles the identity/uptime header from Deps.
func (s *Server) serviceInfo() ServiceInfo {
	info := ServiceInfo{
		Name:      "opnsense-exporter",
		Version:   s.deps.Version,
		GoVersion: s.deps.GoVersion,
		Host:      s.deps.Host,
		Instance:  s.deps.InstanceLabel,
	}
	if !s.deps.StartTime.IsZero() {
		info.Uptime = shortDur(time.Since(s.deps.StartTime))
		info.Start = s.deps.StartTime.Format(time.RFC3339)
	}
	return info
}

// snapshot builds the full Status model from the passive tracker, the passive
// metric capture, the scheduler's upstream-health snapshot and the cache view. It
// never gathers and never calls the OPNsense API.
func (s *Server) snapshot() Status {
	var stats []collector.CollectorStat
	if s.deps.Tracker != nil {
		stats = s.deps.Tracker.Snapshot()
	}
	capt := s.capture()
	families := capt.Families
	var cache []opnsense.CacheEntryView
	if s.deps.Cache != nil {
		cache = s.deps.Cache()
	}
	st := buildStatus(stats, capt, cache, s.serviceInfo(), s.deps.AllCollectorNames, s.health())
	st.Runtime = s.runtime.stats()
	st.Trend = s.trend.stats()
	// Fold the cardinality report from the SAME already-fetched families (single
	// snapshot fetch) so the Cardinality tab refreshes with the poll. This is a
	// pure, passive computation — no live API call. Config is deliberately NOT
	// folded in here: EffectiveConfig re-reads secret files from disk, so it is
	// rendered server-side once per page load (see handleStatus), not per poll.
	card := buildCardinality(families, warnCardinality, critCardinality, s.deps.SeriesBudget)
	card.Generated = time.Now()
	card.Growth = s.growth.rows()
	st.Cardinality = card
	st.Generated = time.Now()
	return st
}
