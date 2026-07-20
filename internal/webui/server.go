// Package webui serves the opnsense-exporter operator console: a hub-and-spoke,
// server-rendered set of pages (status, cardinality, config, devices) built
// from passively-captured scrape data. No console request ever triggers a
// firewall scrape — metrics come only from Deps.Metrics (a metricsnap snapshot),
// the StatusTracker, and the API-client cache view.
//
// # Extending the console with a new page
//
// Page areas register their own routes so new pages drop in as NEW files
// without editing this file. The pattern (see handlers.go for the status/static
// /health example, and Tasks 6–9 for cardinality/config/devices/trigger):
//
//  1. Create internal/webui/<area>.go.
//  2. In it, add `func init() { registerRoutes((*Server).register<Area>) }`.
//  3. Implement `func (s *Server) register<Area>(mux *http.ServeMux)` that calls
//     mux.HandleFunc("GET /<path>", s.handle<Area>), etc.
//  4. Handler methods read s.deps (and s.snapshot()/s.deps.Metrics() for data —
//     never Gather), build a view with s.newView("<key>", "<Title>", data), and
//     render with renderPage(w, "<area>.html.tmpl", v).
//  5. Add templates/<area>.html.tmpl defining `{{define "body"}}...{{end}}`.
//  6. Nav already lists Status/Cardinality/Config/Devices (Config/Devices are
//     omitted when DisableConfig/DisableDevices); a page whose key matches an
//     existing nav entry needs no nav change.
//
// Handler() iterates every registered registrar against a fresh ServeMux, so
// registration order is init order and no central edit is required.
package webui

import (
	"context"
	"net/http"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/rknightion/opnsense-exporter/internal/collector"
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
	Tracker                                 *collector.StatusTracker
	Metrics                                 func() ([]*dto.MetricFamily, time.Time) // metricsnap.Recorder.Snapshot
	Cache                                   func() []opnsense.CacheEntryView
	EffectiveConfig                         func() []options.ConfigSection
	RunCollector                            func(ctx context.Context, name string) (time.Duration, error)
	Devices                                 func(ctx context.Context) (DeviceReport, error)
	AllCollectorNames                       []string
	RefreshSeconds                          int
	DisableConfig                           bool
	DisableDevices                          bool
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
	return &Server{
		deps:    d,
		growth:  newGrowthSampler(growthRingSize),
		runtime: newRuntimeSampler(growthRingSize),
	}
}

// StartBackground begins the cardinality growth sampler and the runtime-stats
// sampler. Call once after NewServer; pair with Close on shutdown.
func (s *Server) StartBackground() {
	s.growth.start(s.deps.Metrics, growthSampleInterval)
	s.runtime.start(growthSampleInterval)
}

// Close stops background sampling.
func (s *Server) Close() {
	s.growth.close()
	s.runtime.close()
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

// nav builds the data-driven navigation, marking active and omitting the
// pages disabled by kill switch.
func (s *Server) nav(active string) []navItem {
	items := []navItem{
		{Label: "Status", Href: "/", Key: "status"},
		{Label: "Cardinality", Href: "/cardinality", Key: "cardinality"},
	}
	if !s.deps.DisableConfig {
		items = append(items, navItem{Label: "Config", Href: "/config", Key: "config"})
	}
	if !s.deps.DisableDevices {
		items = append(items, navItem{Label: "Devices", Href: "/devices", Key: "devices"})
	}
	for i := range items {
		items[i].Active = items[i].Key == active
	}
	return items
}

// newView wraps page-specific data with the shared shell (nav/refresh/title)
// for renderPage. Every page lane uses this to get consistent chrome.
func (s *Server) newView(pageID, title string, data any) view {
	return view{
		Title:          title,
		PageID:         pageID,
		Nav:            s.nav(pageID),
		RefreshSeconds: s.deps.RefreshSeconds,
		Data:           data,
	}
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

// snapshot builds the full Status model from the passive tracker, the
// last-scrape metric families, and the cache view. It never gathers.
func (s *Server) snapshot() Status {
	var stats []collector.CollectorStat
	if s.deps.Tracker != nil {
		stats = s.deps.Tracker.Snapshot()
	}
	var families []*dto.MetricFamily
	var at time.Time
	if s.deps.Metrics != nil {
		families, at = s.deps.Metrics()
	}
	var cache []opnsense.CacheEntryView
	if s.deps.Cache != nil {
		cache = s.deps.Cache()
	}
	st := buildStatus(stats, families, cache, s.serviceInfo(), s.deps.AllCollectorNames)
	st.Runtime = s.runtime.stats()
	// Fold the cardinality report from the SAME already-fetched families (single
	// snapshot fetch) so the Cardinality tab refreshes with the poll. This is a
	// pure, passive computation — no live API call. Config is deliberately NOT
	// folded in here: EffectiveConfig re-reads secret files from disk, so it is
	// rendered server-side once per page load (see handleStatus), not per poll.
	card := buildCardinality(families, warnCardinality, critCardinality)
	card.Generated = time.Now()
	card.Growth = s.growth.rows()
	st.Cardinality = card
	st.Generated = time.Now()
	if at.IsZero() {
		st.ScrapeAge = "never"
	} else {
		st.ScrapeAge = shortDur(time.Since(at)) + " ago"
	}
	return st
}
