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
