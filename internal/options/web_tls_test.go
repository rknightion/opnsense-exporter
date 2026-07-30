package options

import (
	"os"
	"path/filepath"
	"testing"
)

// writeWebConfig writes a minimal exporter-toolkit web-config YAML with the
// given tls_server_config body and returns its path.
func writeWebConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "web-config.yml")
	content := "tls_server_config:\n" + body
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing test web config: %v", err)
	}
	return path
}

func TestValidateWebTLSConfig(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name: "no client_allowed_sans is always fine",
			body: "  client_auth_type: NoClientCert\n",
		},
		{
			name:    "NoClientCert with client_allowed_sans is rejected",
			body:    "  client_auth_type: NoClientCert\n  client_allowed_sans:\n    - example.com\n",
			wantErr: true,
		},
		{
			name:    "implicit NoClientCert (client_auth_type omitted) with client_allowed_sans is rejected",
			body:    "  client_allowed_sans:\n    - example.com\n",
			wantErr: true,
		},
		{
			name:    "RequestClientCert with client_allowed_sans is rejected",
			body:    "  client_auth_type: RequestClientCert\n  client_allowed_sans:\n    - example.com\n",
			wantErr: true,
		},
		{
			name:    "VerifyClientCertIfGiven with client_allowed_sans is rejected",
			body:    "  client_auth_type: VerifyClientCertIfGiven\n  client_allowed_sans:\n    - example.com\n",
			wantErr: true,
		},
		{
			name: "RequireAnyClientCert with client_allowed_sans is accepted",
			body: "  client_auth_type: RequireAnyClientCert\n  client_allowed_sans:\n    - example.com\n",
		},
		{
			name: "RequireAndVerifyClientCert with client_allowed_sans is accepted",
			body: "  client_auth_type: RequireAndVerifyClientCert\n  client_allowed_sans:\n    - example.com\n",
		},
		{
			name: "RequireClientCert (legacy alias) with client_allowed_sans is accepted",
			body: "  client_auth_type: RequireClientCert\n  client_allowed_sans:\n    - example.com\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeWebConfig(t, tt.body)
			err := ValidateWebTLSConfig(path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateWebTLSConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateWebTLSConfig_EmptyPath(t *testing.T) {
	if err := ValidateWebTLSConfig(""); err != nil {
		t.Errorf("empty path should be a no-op, got %v", err)
	}
}

func TestValidateWebTLSConfig_UnreadableFile(t *testing.T) {
	// web.Validate (called alongside this in main.go) already surfaces
	// read/parse failures for the operator; this guard should not duplicate
	// that error, so an unreadable path is a silent no-op here.
	if err := ValidateWebTLSConfig(filepath.Join(t.TempDir(), "does-not-exist.yml")); err != nil {
		t.Errorf("unreadable path should be a no-op here, got %v", err)
	}
}
