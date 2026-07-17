// Package server holds the exporter's HTTP handlers: the filtered /metrics
// handler and the /-/healthy and /-/ready probe endpoints.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// HealthyPath and ReadyPath are the fixed liveness/readiness routes the exporter
// registers. They are exported so metrics-path validation can reject them as reserved:
// reusing one for --web.telemetry-path registers two handlers under the same pattern,
// which panics net/http.ServeMux at startup.
const (
	HealthyPath = "/-/healthy"
	ReadyPath   = "/-/ready"
)

// readyProbeTimeout bounds a single upstream readiness probe independently of the API
// client's own retry budget (--opnsense.max-retries × --opnsense.timeout, 3 × 15s = 45s
// by default), so a hung OPNsense API cannot pin a probe request for the full client
// worst-case. This fixed bound is deliberately decoupled from the client config.
const readyProbeTimeout = 5 * time.Second

// Healthy returns the liveness handler: it answers 200 as soon as the HTTP
// server is serving, with no upstream dependency.
func Healthy() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
}

// ProbeFunc checks whether the OPNsense API is reachable.
type ProbeFunc func(ctx context.Context) error

type readyHandler struct {
	probe ProbeFunc
	ttl   time.Duration
	log   *slog.Logger
	now   func() time.Time

	mu        sync.Mutex
	lastProbe time.Time
	lastErr   error
}

// NewReady returns the readiness handler: 200 when the OPNsense API health
// check succeeds, 503 otherwise. Probe results — successes AND failures — are
// cached for ttl so multiple aggressive probers (kubelets, load balancers)
// cannot hammer the firewall API; the mutex additionally guarantees a single
// probe in flight. The probe runs on context.WithoutCancel(r.Context()): a
// prober with a short request timeout (kubelet default timeoutSeconds=1)
// must not abort the probe and poison the cache for everyone else — the 5s
// readyProbeTimeout is the only deadline. Results carrying context.Canceled
// are never cached (belt and braces). Readiness means "the API answers", not
// "the firewall is healthy": degraded-firewall signal belongs to
// opnsense_up/opnsense_firewall_status.
func NewReady(probe ProbeFunc, ttl time.Duration, log *slog.Logger) http.Handler {
	return &readyHandler{probe: probe, ttl: ttl, log: log, now: time.Now}
}

func (h *readyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	err := h.lastErr
	if h.lastProbe.IsZero() || h.now().Sub(h.lastProbe) >= h.ttl {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), readyProbeTimeout)
		err = h.probe(ctx)
		cancel()
		if !errors.Is(err, context.Canceled) {
			h.lastErr = err
			h.lastProbe = h.now()
		}
		if err != nil {
			h.log.Warn("readiness probe failed", "err", err)
		}
	}
	h.mu.Unlock()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err != nil {
		// Deliberately generic: APICallError messages can carry response body
		// excerpts. Details go to the log, never to unauthenticated probers.
		http.Error(w, "Not Ready: OPNsense API health check failed", http.StatusServiceUnavailable)
		return
	}
	_, _ = w.Write([]byte("OK"))
}
