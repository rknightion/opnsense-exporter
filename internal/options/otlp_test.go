package options

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func validRaw() otlpRawInputs {
	return otlpRawInputs{
		enabled:     true,
		protocol:    "http/protobuf",
		interval:    60 * time.Second,
		serviceName: "opnsense-exporter",
	}
}

func TestOTLPConfig_Validate(t *testing.T) {
	base := func() OTLPConfig {
		return OTLPConfig{Protocol: "http/protobuf", ExportInterval: 60 * time.Second}
	}
	tests := []struct {
		name    string
		mutate  func(*OTLPConfig)
		wantErr bool
	}{
		{"valid", func(*OTLPConfig) {}, false},
		{"valid grpc", func(c *OTLPConfig) { c.Protocol = "grpc" }, false},
		{"bad protocol", func(c *OTLPConfig) { c.Protocol = "thrift" }, true},
		{"empty protocol ok (sdk fallthrough)", func(c *OTLPConfig) { c.Protocol = "" }, false},
		{"zero interval", func(c *OTLPConfig) { c.ExportInterval = 0 }, true},
		{"negative interval", func(c *OTLPConfig) { c.ExportInterval = -time.Second }, true},
		{"cert without key", func(c *OTLPConfig) { c.TLSCertFile = "c.pem" }, true},
		{"key without cert", func(c *OTLPConfig) { c.TLSKeyFile = "k.pem" }, true},
		{"cert and key ok", func(c *OTLPConfig) { c.TLSCertFile = "c.pem"; c.TLSKeyFile = "k.pem" }, false},
		{"insecure with ca file", func(c *OTLPConfig) { c.Insecure = true; c.TLSCAFile = "ca.pem" }, true},
		{"insecure with cert+key", func(c *OTLPConfig) { c.Insecure = true; c.TLSCertFile = "c.pem"; c.TLSKeyFile = "k.pem" }, true},
		{"insecure alone ok", func(c *OTLPConfig) { c.Insecure = true }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base()
			tt.mutate(&c)
			err := c.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAssembleOTLP_Disabled(t *testing.T) {
	in := validRaw()
	in.enabled = false
	cfg, enabled, err := assembleOTLP(in)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if enabled {
		t.Error("expected disabled")
	}
	if cfg != nil {
		t.Error("expected nil cfg when disabled")
	}
}

func TestAssembleOTLP_HeadersParsing(t *testing.T) {
	in := validRaw()
	in.headers = "X-Scope-OrgID=42, Authorization=Bearer abc "
	cfg, enabled, err := assembleOTLP(in)
	if err != nil || !enabled {
		t.Fatalf("enabled=%v err=%v", enabled, err)
	}
	if cfg.Headers["X-Scope-OrgID"] != "42" {
		t.Errorf("orgid header = %q", cfg.Headers["X-Scope-OrgID"])
	}
	if cfg.Headers["Authorization"] != "Bearer abc" {
		t.Errorf("auth header = %q", cfg.Headers["Authorization"])
	}
}

func TestAssembleOTLP_GrafanaCloudShortcut(t *testing.T) {
	in := validRaw()
	in.gcInstanceID = "123456"
	in.gcToken = "glc_secret"
	in.gcEndpoint = "https://otlp-gateway-prod.grafana.net/otlp"
	cfg, enabled, err := assembleOTLP(in)
	if err != nil || !enabled {
		t.Fatalf("enabled=%v err=%v", enabled, err)
	}
	if cfg.Endpoint != in.gcEndpoint {
		t.Errorf("endpoint = %q, want %q", cfg.Endpoint, in.gcEndpoint)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("123456:glc_secret"))
	if cfg.Headers["Authorization"] != want {
		t.Errorf("authorization = %q, want %q", cfg.Headers["Authorization"], want)
	}
}

func TestAssembleOTLP_ExplicitEndpointWinsOverGC(t *testing.T) {
	in := validRaw()
	in.endpoint = "https://explicit:4318"
	in.gcInstanceID = "1"
	in.gcToken = "t"
	in.gcEndpoint = "https://gc:4318"
	cfg, _, err := assembleOTLP(in)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if cfg.Endpoint != "https://explicit:4318" {
		t.Errorf("explicit endpoint should win, got %q", cfg.Endpoint)
	}
}

func TestAssembleOTLP_ExplicitAuthHeaderWinsOverGC(t *testing.T) {
	in := validRaw()
	in.headers = "Authorization=Bearer mine"
	in.gcInstanceID = "1"
	in.gcToken = "t"
	in.gcEndpoint = "https://gc:4318"
	cfg, _, err := assembleOTLP(in)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if cfg.Headers["Authorization"] != "Bearer mine" {
		t.Errorf("explicit auth header should win, got %q", cfg.Headers["Authorization"])
	}
}

func TestAssembleOTLP_GCErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*otlpRawInputs)
	}{
		{"id without token", func(in *otlpRawInputs) { in.gcInstanceID = "1" }},
		{"token without id", func(in *otlpRawInputs) { in.gcToken = "t" }},
		{"creds without any endpoint", func(in *otlpRawInputs) { in.gcInstanceID = "1"; in.gcToken = "t" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validRaw()
			tt.mutate(&in)
			if _, _, err := assembleOTLP(in); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestAssembleOTLP_InvalidConfigErrors(t *testing.T) {
	in := validRaw()
	in.protocol = "thrift"
	if _, _, err := assembleOTLP(in); err == nil {
		t.Error("expected validate error for bad protocol")
	}
}

func TestResolveSecret_OTLPTokenFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tok")
	if err := os.WriteFile(p, []byte("file-tok\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("OTLP_TEST_TOKEN_FILE", p)
	got, err := resolveSecret("OTLP_TEST_TOKEN_FILE", "flag-tok")
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	if got != "file-tok" {
		t.Errorf("got %q", got)
	}
}
