package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/rknightion/opnsense-exporter/opnsense"
)

func TestCaptureContracts(t *testing.T) {
	const body = `{"metadata":{"system":{"status":"OK"}},"subsystems":[]}`
	var gotAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); ok && u == "k" && p == "s" {
			gotAuth = true
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	outDir := t.TempDir()
	contracts := []opnsense.ResponseContract{{Endpoint: "healthCheck"}}
	manifest := map[opnsense.EndpointName]opnsense.EndpointContract{
		"healthCheck": {Path: "api/core/system/status", Method: "GET"},
	}

	results, err := captureContracts(srv.Client(), srv.URL, "k", "s", outDir, contracts, manifest)
	if err != nil {
		t.Fatalf("captureContracts: %v", err)
	}
	if !gotAuth {
		t.Error("expected basic auth credentials to be sent")
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	r := results[0]
	if r.Err != nil {
		t.Fatalf("result error: %v", r.Err)
	}
	if r.Status != http.StatusOK {
		t.Errorf("status = %d, want 200", r.Status)
	}
	want := filepath.Join(outDir, "healthCheck.json")
	if r.File != want {
		t.Errorf("file = %q, want %q", r.File, want)
	}
	got, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("read captured file: %v", err)
	}
	if string(got) != body {
		t.Errorf("captured body = %q, want %q", got, body)
	}
}

func TestCaptureContracts_HTTPErrorRecorded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	contracts := []opnsense.ResponseContract{{Endpoint: "healthCheck"}}
	manifest := map[opnsense.EndpointName]opnsense.EndpointContract{
		"healthCheck": {Path: "api/core/system/status", Method: "GET"},
	}
	results, err := captureContracts(srv.Client(), srv.URL, "k", "s", t.TempDir(), contracts, manifest)
	if err != nil {
		t.Fatalf("captureContracts: %v", err)
	}
	if results[0].Err == nil {
		t.Error("expected an error for a non-2xx response")
	}
	if results[0].Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", results[0].Status)
	}
}

func TestCaptureContracts_SkipsNonGET(t *testing.T) {
	contracts := []opnsense.ResponseContract{{Endpoint: "firewallRules"}}
	manifest := map[opnsense.EndpointName]opnsense.EndpointContract{
		"firewallRules": {Path: "api/firewall/filter/search_rule", Method: "POST"},
	}
	results, err := captureContracts(http.DefaultClient, "http://unused", "k", "s", t.TempDir(), contracts, manifest)
	if err != nil {
		t.Fatalf("captureContracts: %v", err)
	}
	if results[0].Err == nil || results[0].File != "" {
		t.Errorf("expected POST endpoint to be skipped with an error, got %+v", results[0])
	}
}
