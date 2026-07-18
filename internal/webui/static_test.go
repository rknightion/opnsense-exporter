package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStatic_AppJS(t *testing.T) {
	srv := NewServer(Deps{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Fatalf("want a javascript content-type, got %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "pollStatus") {
		t.Fatalf("app.js body should contain pollStatus")
	}
}
