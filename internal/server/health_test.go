package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/common/promslog"
)

func TestHealthyAlwaysOK(t *testing.T) {
	rec := httptest.NewRecorder()
	Healthy().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/-/healthy", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "OK" {
		t.Errorf("body = %q, want OK", rec.Body.String())
	}
}

func TestReadySuccess(t *testing.T) {
	h := NewReady(func(ctx context.Context) error { return nil }, 10*time.Second, promslog.NewNopLogger())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/-/ready", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestReadyFailureIs503WithGenericBody(t *testing.T) {
	h := NewReady(func(ctx context.Context) error {
		return errors.New("secret-bearing upstream detail")
	}, 10*time.Second, promslog.NewNopLogger())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/-/ready", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	if got := rec.Body.String(); got != "Not Ready: OPNsense API health check failed\n" {
		t.Errorf("body = %q, want generic not-ready message", got)
	}
}

func TestReadyCachesWithinTTL(t *testing.T) {
	calls := 0
	current := time.Unix(1000, 0)
	h := &readyHandler{
		probe: func(ctx context.Context) error { calls++; return nil },
		ttl:   10 * time.Second,
		log:   promslog.NewNopLogger(),
		now:   func() time.Time { return current },
	}

	for range 5 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/-/ready", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	}
	if calls != 1 {
		t.Errorf("probe calls within TTL = %d, want 1 (cached)", calls)
	}

	// Advance past the TTL: exactly one re-probe.
	current = current.Add(11 * time.Second)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/-/ready", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if calls != 2 {
		t.Errorf("probe calls after TTL = %d, want 2", calls)
	}
}

func TestReadyCachesFailures(t *testing.T) {
	calls := 0
	current := time.Unix(1000, 0)
	h := &readyHandler{
		probe: func(ctx context.Context) error { calls++; return errors.New("down") },
		ttl:   10 * time.Second,
		log:   promslog.NewNopLogger(),
		now:   func() time.Time { return current },
	}
	for range 3 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/-/ready", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	}
	if calls != 1 {
		t.Errorf("probe calls = %d, want 1 (failures cached too)", calls)
	}
}

func TestReadyProbeSurvivesCancelledProber(t *testing.T) {
	// kubelet's default timeoutSeconds=1 aborts the HTTP request; the probe
	// must run on a detached context so an impatient prober cannot poison the
	// cache for everyone else.
	probeCtxErr := errors.New("probe never ran")
	h := NewReady(func(ctx context.Context) error {
		probeCtxErr = ctx.Err()
		return nil
	}, 10*time.Second, promslog.NewNopLogger())

	reqCtx, cancel := context.WithCancel(context.Background())
	cancel() // prober already gave up
	req := httptest.NewRequest(http.MethodGet, "/-/ready", nil).WithContext(reqCtx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if probeCtxErr != nil {
		t.Errorf("probe context error = %v, want nil (WithoutCancel must detach prober cancellation)", probeCtxErr)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestReadyDoesNotCacheCancelledProbe(t *testing.T) {
	calls := 0
	current := time.Unix(1000, 0)
	h := &readyHandler{
		probe: func(ctx context.Context) error {
			calls++
			if calls == 1 {
				return context.Canceled
			}
			return nil
		},
		ttl: 10 * time.Second,
		log: promslog.NewNopLogger(),
		now: func() time.Time { return current },
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/-/ready", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("first request: status = %d, want 503 (cancelled probe is not-ready now)", rec.Code)
	}

	// Same instant: a context.Canceled result must NOT have been cached, so a
	// second request re-probes and succeeds.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/-/ready", nil))
	if calls != 2 {
		t.Errorf("probe calls = %d, want 2 (context.Canceled result must not be cached)", calls)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("second request: status = %d, want 200", rec.Code)
	}
}
