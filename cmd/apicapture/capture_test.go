package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/rknightion/opnsense2otel/v4/internal/options"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
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
	if err := os.Chmod(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
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
	for target, wantMode := range map[string]os.FileMode{outDir: 0o700, want: 0o600} {
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if gotMode := info.Mode().Perm(); gotMode != wantMode {
			t.Errorf("%s mode = %o, want %o", target, gotMode, wantMode)
		}
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

// TestCredentialResolutionParity verifies apicapture resolves credentials through the
// same helper the exporter uses, so file-based secrets (OPS_API_KEY_FILE /
// OPS_API_SECRET_FILE) work identically to `just run` (#157): a *_FILE secret
// resolves to the same value as the plaintext env var, and takes precedence over the
// flag/env fallback, while the plaintext path keeps working.
func TestCredentialResolutionParity(t *testing.T) {
	writeSecret := func(t *testing.T, val string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(p, []byte(val+"\n"), 0o600); err != nil {
			t.Fatalf("write secret file: %v", err)
		}
		return p
	}

	t.Run("plaintext flag/env value passes through", func(t *testing.T) {
		got, err := options.ResolveOPSAPIKey("plainkey")
		if err != nil || got != "plainkey" {
			t.Fatalf("got (%q, %v), want (\"plainkey\", nil)", got, err)
		}
	})

	t.Run("_FILE resolves to the same value as the plaintext var", func(t *testing.T) {
		keyFile := writeSecret(t, "filekey")
		secretFile := writeSecret(t, "filesecret")
		t.Setenv("OPS_API_KEY_FILE", keyFile)
		t.Setenv("OPS_API_SECRET_FILE", secretFile)

		// flagValue empty (as when only the *_FILE env is set): file wins.
		gotKey, err := options.ResolveOPSAPIKey("")
		if err != nil || gotKey != "filekey" {
			t.Fatalf("key: got (%q, %v), want (\"filekey\", nil)", gotKey, err)
		}
		gotSecret, err := options.ResolveOPSAPISecret("")
		if err != nil || gotSecret != "filesecret" {
			t.Fatalf("secret: got (%q, %v), want (\"filesecret\", nil)", gotSecret, err)
		}
	})

	t.Run("_FILE takes precedence over the flag/env fallback", func(t *testing.T) {
		keyFile := writeSecret(t, "filekey")
		t.Setenv("OPS_API_KEY_FILE", keyFile)
		got, err := options.ResolveOPSAPIKey("plainkey")
		if err != nil || got != "filekey" {
			t.Fatalf("got (%q, %v), want (\"filekey\", nil) — *_FILE must win", got, err)
		}
	})
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
