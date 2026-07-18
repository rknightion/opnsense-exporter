package webui

import (
	"encoding/json"
	"net/http"
)

// init wires the core page areas — status, static assets, and health — into the
// registrar set. New page lanes add their own init() in their own file; this
// one owns only what Task 5 ships.
func init() {
	registerRoutes(
		(*Server).registerStatus,
		(*Server).registerStatic,
		(*Server).registerHealth,
	)
}

// registerStatus mounts the status console page and its JSON twin.
func (s *Server) registerStatus(mux *http.ServeMux) {
	mux.HandleFunc("GET /", s.handleStatus)
	mux.HandleFunc("GET /api/status.json", s.handleStatusJSON)
}

// registerHealth mounts the liveness probe.
func (s *Server) registerHealth(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", s.handleHealthz)
}

// registerStatic mounts the embedded CSS/JS with explicit content types (no
// FileServer content sniffing).
func (s *Server) registerStatic(mux *http.ServeMux) {
	mux.HandleFunc("GET /static/app.css", s.staticHandler("static/app.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET /static/app.js", s.staticHandler("static/app.js", "text/javascript; charset=utf-8"))
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	st := s.snapshot()
	v := s.newView("status", "Status", st)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := renderPage(w, "status.html.tmpl", v); err != nil {
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

// staticHandler serves one embedded asset with a fixed content type.
func (s *Server) staticHandler(name, contentType string) http.HandlerFunc {
	body, err := staticFS.ReadFile(name)
	return func(w http.ResponseWriter, r *http.Request) {
		if err != nil {
			http.Error(w, "asset unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(body)
	}
}

// writeJSON encodes v as an indented JSON body. Shared by every page's JSON
// twin so encoding stays consistent across lanes.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
	}
}
