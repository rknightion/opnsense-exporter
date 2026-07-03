package options

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOPNSenseConfig(t *testing.T) {
	conf := OPNSenseConfig{
		Protocol:  "ftp",
		Host:      "test",
		APIKey:    "test",
		APISecret: "test",
	}

	if err := conf.Validate(); err == nil {
		t.Errorf("expected invalid protocol error, got nil")
	}

	conf.Protocol = "https"

	if err := conf.Validate(); err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	conf.Protocol = "http"

	if err := conf.Validate(); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestValidate_MissingHost(t *testing.T) {
	conf := OPNSenseConfig{
		Protocol:  "https",
		Host:      "",
		APIKey:    "test-key",
		APISecret: "test-secret",
	}

	err := conf.Validate()
	if err == nil {
		t.Fatal("expected error for missing host, got nil")
	}
	if err.Error() != "host must be set" {
		t.Errorf("expected 'host must be set', got %q", err.Error())
	}
}

func TestValidate_MissingAPIKey(t *testing.T) {
	conf := OPNSenseConfig{
		Protocol:  "https",
		Host:      "firewall.example.com",
		APIKey:    "",
		APISecret: "test-secret",
	}

	err := conf.Validate()
	if err == nil {
		t.Fatal("expected error for missing api-key, got nil")
	}
	if err.Error() != "api-key must be set" {
		t.Errorf("expected 'api-key must be set', got %q", err.Error())
	}
}

func TestValidate_MissingAPISecret(t *testing.T) {
	conf := OPNSenseConfig{
		Protocol:  "https",
		Host:      "firewall.example.com",
		APIKey:    "test-key",
		APISecret: "",
	}

	err := conf.Validate()
	if err == nil {
		t.Fatal("expected error for missing api-secret, got nil")
	}
	if err.Error() != "api-secret must be set" {
		t.Errorf("expected 'api-secret must be set', got %q", err.Error())
	}
}

func TestValidate_InvalidProtocol(t *testing.T) {
	protocols := []string{"ftp", "ssh", "tcp", "", "HTTP", "HTTPS"}
	for _, proto := range protocols {
		conf := OPNSenseConfig{
			Protocol:  proto,
			Host:      "firewall.example.com",
			APIKey:    "test-key",
			APISecret: "test-secret",
		}

		err := conf.Validate()
		if err == nil {
			t.Errorf("expected error for protocol %q, got nil", proto)
		}
	}
}

func TestValidate_ValidConfigurations(t *testing.T) {
	validConfigs := []OPNSenseConfig{
		{Protocol: "http", Host: "192.168.1.1", APIKey: "key", APISecret: "secret"},
		{Protocol: "https", Host: "firewall.local", APIKey: "key", APISecret: "secret"},
		{Protocol: "http", Host: "10.0.0.1:8080", APIKey: "long-api-key-value", APISecret: "long-api-secret-value"},
	}

	for i, conf := range validConfigs {
		err := conf.Validate()
		if err != nil {
			t.Errorf("config %d: expected no error, got %v", i, err)
		}
	}
}

func TestGetLineFromFile_ValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "secret.txt")
	err := os.WriteFile(filePath, []byte("my-secret-value\n"), 0600)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := getLineFromFile(filePath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result != "my-secret-value" {
		t.Errorf("expected 'my-secret-value', got %q", result)
	}
}

func TestGetLineFromFile_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "empty.txt")
	err := os.WriteFile(filePath, []byte(""), 0600)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := getLineFromFile(filePath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

func TestGetLineFromFile_MissingFile(t *testing.T) {
	_, err := getLineFromFile("/nonexistent/path/to/file.txt")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestGetLineFromFile_WhitespaceTrimming(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "whitespace.txt")
	err := os.WriteFile(filePath, []byte("  my-api-key  \n"), 0600)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := getLineFromFile(filePath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result != "my-api-key" {
		t.Errorf("expected 'my-api-key', got %q", result)
	}
}

func TestGetLineFromFile_OnlyWhitespace(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "spaces.txt")
	err := os.WriteFile(filePath, []byte("   \n"), 0600)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := getLineFromFile(filePath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result != "" {
		t.Errorf("expected empty string after trimming, got %q", result)
	}
}

func TestGetLineFromFile_MultipleLines(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "multi.txt")
	err := os.WriteFile(filePath, []byte("first-line\nsecond-line\nthird-line\n"), 0600)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := getLineFromFile(filePath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Should only read the first line
	if result != "first-line" {
		t.Errorf("expected 'first-line', got %q", result)
	}
}

// resetOpsFlags saves the package-global credential flag values and restores
// them when the test finishes, so tests can mutate them safely.
func resetOpsFlags(t *testing.T) {
	t.Helper()
	savedKey, savedSecret := *opnsenseAPIKey, *opnsenseAPISecret
	t.Cleanup(func() {
		*opnsenseAPIKey = savedKey
		*opnsenseAPISecret = savedSecret
	})
}

func TestOpsAPISecret_ResolvesFlag(t *testing.T) {
	resetOpsFlags(t)
	os.Unsetenv("OPS_API_SECRET_FILE")
	*opnsenseAPISecret = "s3cret"
	got, err := opsAPISecret()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got != "s3cret" {
		t.Errorf("expected 's3cret', got %q", got)
	}
}

func TestOpsAPIKey_ResolvesFlag(t *testing.T) {
	resetOpsFlags(t)
	os.Unsetenv("OPS_API_KEY_FILE")
	*opnsenseAPIKey = "the-key"
	got, err := opsAPIKey()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got != "the-key" {
		t.Errorf("expected 'the-key', got %q", got)
	}
}

// TestOpsAPIKey_PrefixedFileEnv covers #141: the prefixed
// OPNSENSE_EXPORTER_OPS_API_KEY_FILE alias is recognized (in addition to the legacy
// unprefixed name), and takes precedence over it.
func TestOpsAPIKey_PrefixedFileEnv(t *testing.T) {
	resetOpsFlags(t)
	dir := t.TempDir()
	os.Unsetenv("OPS_API_KEY_FILE")

	// Prefixed alias alone resolves.
	prefixed := filepath.Join(dir, "prefixed")
	if err := os.WriteFile(prefixed, []byte("prefixed-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPNSENSE_EXPORTER_OPS_API_KEY_FILE", prefixed)
	*opnsenseAPIKey = ""
	if got, err := opsAPIKey(); err != nil || got != "prefixed-key" {
		t.Fatalf("prefixed alias: got %q err %v, want prefixed-key", got, err)
	}

	// When both are set, the prefixed (canonical) name wins.
	legacy := filepath.Join(dir, "legacy")
	if err := os.WriteFile(legacy, []byte("legacy-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPS_API_KEY_FILE", legacy)
	if got, err := opsAPIKey(); err != nil || got != "prefixed-key" {
		t.Errorf("with both set: got %q err %v, want prefixed-key (prefixed precedence)", got, err)
	}
}

// TestOpsAPISecret_PrefixedFileEnv covers #141 for the secret.
func TestOpsAPISecret_PrefixedFileEnv(t *testing.T) {
	resetOpsFlags(t)
	dir := t.TempDir()
	os.Unsetenv("OPS_API_SECRET_FILE")
	p := filepath.Join(dir, "sec")
	if err := os.WriteFile(p, []byte("prefixed-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPNSENSE_EXPORTER_OPS_API_SECRET_FILE", p)
	*opnsenseAPISecret = ""
	if got, err := opsAPISecret(); err != nil || got != "prefixed-secret" {
		t.Fatalf("prefixed secret alias: got %q err %v", got, err)
	}
}

// The core #109 bug: OPS_API_KEY_FILE / OPS_API_SECRET_FILE set but empty (a common
// templated-blank env pattern) must fall back to the flag/env value, not abort startup
// by trying to os.Open("").
func TestOpsAPIKey_EmptyFileEnvFallsBackToFlag(t *testing.T) {
	resetOpsFlags(t)
	t.Setenv("OPS_API_KEY_FILE", "") // present but empty
	*opnsenseAPIKey = "flag-key"
	got, err := opsAPIKey()
	if err != nil {
		t.Fatalf("empty OPS_API_KEY_FILE should fall back to the flag, got err: %v", err)
	}
	if got != "flag-key" {
		t.Errorf("expected fallback to 'flag-key', got %q", got)
	}
}

func TestOpsAPISecret_EmptyFileEnvFallsBackToFlag(t *testing.T) {
	resetOpsFlags(t)
	t.Setenv("OPS_API_SECRET_FILE", "") // present but empty
	*opnsenseAPISecret = "flag-secret"
	got, err := opsAPISecret()
	if err != nil {
		t.Fatalf("empty OPS_API_SECRET_FILE should fall back to the flag, got err: %v", err)
	}
	if got != "flag-secret" {
		t.Errorf("expected fallback to 'flag-secret', got %q", got)
	}
}

// Regression guard: a real, valid OPS_API_KEY_FILE path is still read from the file,
// taking precedence over the flag value.
func TestOpsAPIKey_ValidFileTakesPrecedence(t *testing.T) {
	resetOpsFlags(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "key")
	if err := os.WriteFile(p, []byte("file-key\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("OPS_API_KEY_FILE", p)
	*opnsenseAPIKey = "flag-key"
	got, err := opsAPIKey()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got != "file-key" {
		t.Errorf("expected file value 'file-key' to win, got %q", got)
	}
}
