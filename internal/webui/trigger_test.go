package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/collector"
)

// decodeJSON reads a recorder body into a generic map for contract assertions.
func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return m
}

func TestTrigger_OK(t *testing.T) {
	srv := NewServer(Deps{
		RunCollector: func(_ context.Context, _ string) (time.Duration, error) {
			return 12 * time.Millisecond, nil
		},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/collectors/trigger?collector=gateways", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	m := decodeJSON(t, rec)
	if m["status"] != "ok" {
		t.Fatalf("want status ok, got %v", m["status"])
	}
	if m["duration_ms"] != float64(12) {
		t.Fatalf("want duration_ms 12, got %v", m["duration_ms"])
	}
}

func TestTrigger_Unknown(t *testing.T) {
	srv := NewServer(Deps{
		RunCollector: func(_ context.Context, _ string) (time.Duration, error) {
			return 0, collector.ErrUnknownCollector
		},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/collectors/trigger?collector=nope", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
	m := decodeJSON(t, rec)
	if m["status"] != "error" {
		t.Fatalf("want status error, got %v", m["status"])
	}
}

func TestTrigger_MethodNotAllowed(t *testing.T) {
	srv := NewServer(Deps{
		RunCollector: func(_ context.Context, _ string) (time.Duration, error) {
			t.Fatal("RunCollector must not be called on GET")
			return 0, nil
		},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/collectors/trigger?collector=gateways", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rec.Code)
	}
	m := decodeJSON(t, rec)
	if m["status"] != "error" {
		t.Fatalf("want status error, got %v", m["status"])
	}
}

func TestTrigger_ConcurrentSameNameBusy(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	srv := NewServer(Deps{
		RunCollector: func(_ context.Context, _ string) (time.Duration, error) {
			close(started)
			<-release
			return 5 * time.Millisecond, nil
		},
	})
	handler := srv.Handler()

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/collectors/trigger?collector=busycol", nil)
		handler.ServeHTTP(rec, req)
		done <- rec
	}()

	<-started // first request is now inside RunCollector, holding the in-flight guard

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/collectors/trigger?collector=busycol", nil)
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("want 409 while in-flight, got %d", rec2.Code)
	}
	m := decodeJSON(t, rec2)
	if m["status"] != "already_running" {
		t.Fatalf("want status already_running, got %v", m["status"])
	}

	close(release)
	rec1 := <-done
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request want 200, got %d", rec1.Code)
	}
}
