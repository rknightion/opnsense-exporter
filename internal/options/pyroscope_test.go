package options

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPyroscopeConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     PyroscopeConfig
		wantErr bool
	}{
		{
			name:    "valid",
			cfg:     PyroscopeConfig{ServerAddress: "https://x:4040", AuthUser: "u", AuthPassword: "p", ApplicationName: "opnsense-exporter"},
			wantErr: false,
		},
		{
			name:    "missing address",
			cfg:     PyroscopeConfig{AuthUser: "u", AuthPassword: "p", ApplicationName: "opnsense-exporter"},
			wantErr: true,
		},
		{
			name:    "missing auth user",
			cfg:     PyroscopeConfig{ServerAddress: "https://x:4040", AuthPassword: "p", ApplicationName: "opnsense-exporter"},
			wantErr: true,
		},
		{
			name:    "missing auth password",
			cfg:     PyroscopeConfig{ServerAddress: "https://x:4040", AuthUser: "u", ApplicationName: "opnsense-exporter"},
			wantErr: true,
		},
		{
			name:    "missing application name",
			cfg:     PyroscopeConfig{ServerAddress: "https://x:4040", AuthUser: "u", AuthPassword: "p"},
			wantErr: true,
		},
		// #142: schemeless address parses as Scheme="host", Host="" — must be rejected.
		{
			name:    "schemeless address rejected",
			cfg:     PyroscopeConfig{ServerAddress: "profiles-prod-011.grafana.net:4040", AuthUser: "u", AuthPassword: "p", ApplicationName: "opnsense-exporter"},
			wantErr: true,
		},
		{
			name:    "scheme with empty host rejected",
			cfg:     PyroscopeConfig{ServerAddress: "https://", AuthUser: "u", AuthPassword: "p", ApplicationName: "opnsense-exporter"},
			wantErr: true,
		},
		{
			name:    "http url accepted (self-hosted)",
			cfg:     PyroscopeConfig{ServerAddress: "http://pyroscope.local:4040", AuthUser: "u", AuthPassword: "p", ApplicationName: "opnsense-exporter"},
			wantErr: false,
		},
		{
			name:    "https grafana cloud url accepted",
			cfg:     PyroscopeConfig{ServerAddress: "https://profiles-prod-011.grafana.net:443", AuthUser: "u", AuthPassword: "p", ApplicationName: "opnsense-exporter"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestResolveSecret_FilePrecedence(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(filePath, []byte("file-token\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("PYRO_TEST_FILE", filePath)

	got, err := resolveSecret("PYRO_TEST_FILE", "flag-token")
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	if got != "file-token" {
		t.Errorf("expected file value to win, got %q", got)
	}
}

// TestResolveSecretMulti_PrefixPrecedence covers #141: resolveSecretMulti accepts the
// canonical prefixed name and the legacy alias, preferring the prefixed one.
func TestResolveSecretMulti_PrefixPrecedence(t *testing.T) {
	dir := t.TempDir()
	prefixed := filepath.Join(dir, "p")
	legacy := filepath.Join(dir, "l")
	if err := os.WriteFile(prefixed, []byte("from-prefixed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte("from-legacy\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Legacy alias alone is honored.
	t.Setenv("PYROSCOPE_AUTH_USER_FILE", legacy)
	got, err := resolveSecretMulti("flag", "OPNSENSE_EXPORTER_PYROSCOPE_AUTH_USER_FILE", "PYROSCOPE_AUTH_USER_FILE")
	if err != nil || got != "from-legacy" {
		t.Fatalf("legacy alias: got %q err %v, want from-legacy", got, err)
	}

	// Prefixed name wins when both are set.
	t.Setenv("OPNSENSE_EXPORTER_PYROSCOPE_AUTH_USER_FILE", prefixed)
	got, err = resolveSecretMulti("flag", "OPNSENSE_EXPORTER_PYROSCOPE_AUTH_USER_FILE", "PYROSCOPE_AUTH_USER_FILE")
	if err != nil || got != "from-prefixed" {
		t.Errorf("prefixed precedence: got %q err %v, want from-prefixed", got, err)
	}
}

func TestResolveSecret_FallbackToFlag(t *testing.T) {
	got, err := resolveSecret("PYRO_TEST_UNSET_FILE", "flag-token")
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	if got != "flag-token" {
		t.Errorf("expected flag value, got %q", got)
	}
}

func TestResolveSecret_EmptyFileFallsBackToFlag(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "empty")
	if err := os.WriteFile(filePath, []byte(""), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("PYRO_TEST_EMPTY_FILE", filePath)

	got, err := resolveSecret("PYRO_TEST_EMPTY_FILE", "flag-token")
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	if got != "flag-token" {
		t.Errorf("expected fallback to flag when file empty, got %q", got)
	}
}

func TestResolveSecret_MissingFileErrors(t *testing.T) {
	t.Setenv("PYRO_TEST_MISSING_FILE", "/nonexistent/path/token")
	_, err := resolveSecret("PYRO_TEST_MISSING_FILE", "flag-token")
	if err == nil {
		t.Fatal("expected error reading missing file, got nil")
	}
}
