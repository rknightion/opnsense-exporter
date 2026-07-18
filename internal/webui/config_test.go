package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rknightion/opnsense-exporter/internal/options"
)

func configDeps(disable bool, sections []options.ConfigSection) Deps {
	d := testDeps()
	d.DisableConfig = disable
	d.EffectiveConfig = func() []options.ConfigSection { return sections }
	return d
}

func fixtureSections() []options.ConfigSection {
	return []options.ConfigSection{
		{
			Title: "Connection",
			Items: []options.ConfigItem{
				{Key: "Host", Value: "fw.example"},
				{Key: "API Key", Value: "••••", Secret: true},
			},
		},
	}
}

func TestHandler_ConfigPage(t *testing.T) {
	srv := NewServer(configDeps(false, fixtureSections()))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Connection") {
		t.Fatalf("body missing section title, got %q", body)
	}
	if !strings.Contains(body, "••••") {
		t.Fatalf("body missing redacted secret marker, got %q", body)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("content-type want html, got %q", got)
	}
}

func TestHandler_ConfigDisabled(t *testing.T) {
	srv := NewServer(configDeps(true, fixtureSections()))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}
