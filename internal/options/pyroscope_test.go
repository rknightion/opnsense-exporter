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
