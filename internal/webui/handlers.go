package webui

import (
	"encoding/json"
	"net/http"
)

// init wires the core routes — the single console page, its JSON twin, and the
// liveness probe. Other page areas (cardinality/devices JSON) add their own
// init() in their own file; this one owns the status page + health.
func init() {
	registerRoutes(
		(*Server).registerStatus,
		(*Server).registerHealth,
	)
}

// registerStatus mounts the single-page console and its JSON twin. The console
// is one tabbed page (Overview/Collectors/API/Cardinality/Logs/Flow/Devices/Config); the
// JSON twin carries the poll-refreshed snapshot the page's JS patches into view.
func (s *Server) registerStatus(mux *http.ServeMux) {
	mux.HandleFunc("GET /", s.handleStatus)
	mux.HandleFunc("GET /api/status.json", s.handleStatusJSON)
}

// registerHealth mounts the liveness probe.
func (s *Server) registerHealth(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", s.handleHealthz)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	v := s.pageView()
	v.Nonce = nonceFromContext(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := renderPage(w, v); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

func (s *Server) handleStatusJSON(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.snapshot())
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok"))
}

// writeJSON encodes v as an indented JSON body. Shared by every JSON twin so
// encoding stays consistent.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
	}
}
