package webui

import (
	"net/http"

	"github.com/rknightion/opnsense-exporter/internal/options"
)

// init registers the config page area's routes. See server.go's extension
// docs for the pattern every page area follows.
func init() { registerRoutes((*Server).registerConfig) }

// registerConfig mounts the redacted effective-configuration page.
func (s *Server) registerConfig(mux *http.ServeMux) {
	mux.HandleFunc("GET /config", s.handleConfig)
}

// handleConfig renders the effective-configuration view, or 404s when the
// page is disabled via the --web.ui-disable-config kill switch. The sections
// it renders are already redacted (options.buildEffectiveConfig never carries
// a real secret string past a presence boolean), so this handler has nothing
// further to scrub.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if s.deps.DisableConfig {
		http.NotFound(w, r)
		return
	}
	var sections []options.ConfigSection
	if s.deps.EffectiveConfig != nil {
		sections = s.deps.EffectiveConfig()
	}
	v := s.newView("config", "Config", sections)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := renderPage(w, "config.html.tmpl", v); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}
