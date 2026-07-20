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

// TestHandler_ConfigTab asserts the effective config is folded into the single
// page as a tab (rendered server-side, once — never on the poll), with secrets
// redacted.
func TestHandler_ConfigTab(t *testing.T) {
	srv := NewServer(configDeps(false, fixtureSections()))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `data-tab="config"`) {
		t.Fatalf("page missing config tab")
	}
	if !strings.Contains(body, "Connection") {
		t.Fatalf("page missing config section title")
	}
	if !strings.Contains(body, "••••") {
		t.Fatalf("page missing redacted secret marker")
	}
}

// TestHandler_ConfigDisabled asserts the config tab is omitted when the config
// kill switch is set (the page still serves — the tab is just gone).
func TestHandler_ConfigDisabled(t *testing.T) {
	srv := NewServer(configDeps(true, fixtureSections()))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, `data-tab="config"`) {
		t.Fatalf("config tab should be omitted when disabled")
	}
	if strings.Contains(body, "Connection") {
		t.Fatalf("config section content should be absent when disabled")
	}
}
