package webui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/collector"
)

// triggerTimeout bounds a single on-demand collector run so a wedged endpoint
// cannot hold a request (and its in-flight slot) open indefinitely.
const triggerTimeout = 30 * time.Second

// inflight tracks which collectors currently have an in-flight Run Now request,
// keyed by collector name. It lives at package scope (not on Server) so the
// guard state is shared across the process without widening the Server struct —
// a single exporter process should never run the same collector on demand
// twice concurrently regardless of how many Server instances exist.
var inflight = struct {
	mu sync.Mutex
	m  map[string]struct{}
}{m: make(map[string]struct{})}

// acquireInflight reserves the in-flight slot for name, returning false if a run
// for that name is already in progress.
func acquireInflight(name string) bool {
	inflight.mu.Lock()
	defer inflight.mu.Unlock()
	if _, running := inflight.m[name]; running {
		return false
	}
	inflight.m[name] = struct{}{}
	return true
}

// releaseInflight frees the in-flight slot for name.
func releaseInflight(name string) {
	inflight.mu.Lock()
	delete(inflight.m, name)
	inflight.mu.Unlock()
}

func init() { registerRoutes((*Server).registerTrigger) }

// registerTrigger mounts the on-demand collector run endpoint. A method-less
// pattern would conflict with the "GET /" catch-all (ServeMux 1.22 specificity
// rule), so the route is registered per method: POST does the work and GET is
// routed to the same handler purely so a browser GET receives the JSON 405 the
// contract promises (handleTrigger's own method check) rather than the status
// page or ServeMux's plain-text default.
func (s *Server) registerTrigger(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/collectors/trigger", s.handleTrigger)
	mux.HandleFunc("GET /api/collectors/trigger", s.handleTrigger)
}

// handleTrigger runs a single collector on demand and reports the outcome as
// JSON. Response contract:
//
//	POST  ok        → 200 {"status":"ok","duration_ms":<ms>}
//	POST  run-error → 200 {"status":"error","duration_ms":<ms>,"error":<msg>}  (the run happened, it failed)
//	POST  unknown   → 404 {"status":"error","error":<msg>}
//	POST  in-flight → 409 {"status":"already_running"}
//	non-POST        → 405 {"status":"error","error":"method not allowed"}
//
// A per-collector in-flight guard prevents concurrent on-demand runs of the same
// collector; it is always released before returning.
func (s *Server) handleTrigger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]any{
			"status": "error",
			"error":  "method not allowed",
		})
		return
	}

	name := r.URL.Query().Get("collector")

	if !acquireInflight(name) {
		writeJSONStatus(w, http.StatusConflict, map[string]any{"status": "already_running"})
		return
	}
	defer releaseInflight(name)

	ctx, cancel := context.WithTimeout(r.Context(), triggerTimeout)
	defer cancel()

	dur, err := s.deps.RunCollector(ctx, name)
	switch {
	case errors.Is(err, collector.ErrUnknownCollector):
		writeJSONStatus(w, http.StatusNotFound, map[string]any{
			"status": "error",
			"error":  err.Error(),
		})
	case err != nil:
		writeJSONStatus(w, http.StatusOK, map[string]any{
			"status":      "error",
			"duration_ms": dur.Milliseconds(),
			"error":       err.Error(),
		})
	default:
		writeJSONStatus(w, http.StatusOK, map[string]any{
			"status":      "ok",
			"duration_ms": dur.Milliseconds(),
		})
	}
}

// writeJSONStatus writes v as a JSON body with an explicit status code. It is the
// status-coded companion to writeJSON (which always implies 200).
func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Header is already written; nothing further we can do but stop.
		return
	}
}
