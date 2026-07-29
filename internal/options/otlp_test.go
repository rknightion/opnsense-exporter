package options

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
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
		// The OTel Go SDK never reads OTEL_EXPORTER_OTLP_PROTOCOL, so an empty
		// protocol has no fallthrough — it is a config error, not a silent default (#92).
		{"empty protocol rejected (no sdk fallthrough)", func(c *OTLPConfig) { c.Protocol = "" }, true},
		{"zero interval", func(c *OTLPConfig) { c.ExportInterval = 0 }, true},
		{"negative interval", func(c *OTLPConfig) { c.ExportInterval = -time.Second }, true},
		{"cert without key", func(c *OTLPConfig) { c.TLSCertFile = "c.pem" }, true},
		{"key without cert", func(c *OTLPConfig) { c.TLSKeyFile = "k.pem" }, true},
		{"cert and key ok", func(c *OTLPConfig) { c.TLSCertFile = "c.pem"; c.TLSKeyFile = "k.pem" }, false},
		{"insecure with ca file", func(c *OTLPConfig) { c.Insecure = true; c.TLSCAFile = "ca.pem" }, true},
		{"insecure with cert+key", func(c *OTLPConfig) { c.Insecure = true; c.TLSCertFile = "c.pem"; c.TLSKeyFile = "k.pem" }, true},
		{"insecure alone ok", func(c *OTLPConfig) { c.Insecure = true }, false},
		// http/protobuf: a non-https endpoint is treated as insecure-by-scheme by the SDK,
		// which then rejects TLS material at construction. Catch it up front (#92).
		{"http endpoint + ca file rejected", func(c *OTLPConfig) { c.Endpoint = "http://collector:4318"; c.TLSCAFile = "ca.pem" }, true},
		{"http endpoint + cert+key rejected", func(c *OTLPConfig) {
			c.Endpoint = "http://collector:4318"
			c.TLSCertFile = "c.pem"
			c.TLSKeyFile = "k.pem"
		}, true},
		{"https endpoint + ca ok", func(c *OTLPConfig) { c.Endpoint = "https://collector:4318"; c.TLSCAFile = "ca.pem" }, false},
		// grpc's oconf prioritizes TLS credentials over scheme-derived insecurity, so the
		// same http endpoint + TLS is fine there — the scheme guard must not fire.
		{"grpc http endpoint + ca unaffected", func(c *OTLPConfig) { c.Protocol = "grpc"; c.Endpoint = "http://collector:4317"; c.TLSCAFile = "ca.pem" }, false},
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

func TestAssembleOTLP_MalformedHeadersRejected(t *testing.T) {
	tests := []struct {
		name    string
		headers string
	}{
		{"missing '=' (colon typo)", "Authorization: Bearer x"},
		{"empty key", "=value"},
		{"only separators parses to zero pairs", ",, ,"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validRaw()
			in.headers = tt.headers
			if _, _, err := assembleOTLP(in); err == nil {
				t.Errorf("expected fatal error for malformed headers %q, got nil", tt.headers)
			}
		})
	}
}

func TestAssembleOTLP_EmptyHeadersOK(t *testing.T) {
	// An empty --otlp.headers is legitimate (defers to OTEL_EXPORTER_OTLP_HEADERS);
	// it must not be treated as a malformed value.
	in := validRaw()
	in.headers = ""
	cfg, enabled, err := assembleOTLP(in)
	if err != nil || !enabled {
		t.Fatalf("empty headers should be valid: enabled=%v err=%v", enabled, err)
	}
	if cfg.Headers != nil {
		t.Errorf("empty headers should yield nil map, got %v", cfg.Headers)
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

// #308: a malformed --otlp.headers segment must never echo the raw segment or its
// value back in the error, because main.go logs this error verbatim at startup and
// the value half of a header is very often a bearer token or similar secret.
func TestParseHeaders_ColonTypoDoesNotLeakSecret(t *testing.T) {
	const canary = "supersecrettoken"
	_, err := parseHeaders("Authorization:Bearer " + canary)
	if err == nil {
		t.Fatal("expected an error for a colon-separated header (missing '=')")
	}
	if strings.Contains(err.Error(), canary) {
		t.Errorf("error must not contain the secret value, got: %v", err)
	}
}

func TestParseHeaders_EmptyKeyDoesNotLeakSecret(t *testing.T) {
	const canary = "supersecrettoken"
	_, err := parseHeaders("=Bearer " + canary)
	if err == nil {
		t.Fatal("expected an error for a header with an empty key")
	}
	if strings.Contains(err.Error(), canary) {
		t.Errorf("error must not contain the secret value, got: %v", err)
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

// otlpCompressionEnvVars are every env var OTLPGzipDefault reads for either
// signal. Tests clear all of them via t.Setenv so a stray value left by an
// earlier test (or the outer shell) can never leak into a later case.
var otlpCompressionEnvVars = []string{
	"OTEL_EXPORTER_OTLP_COMPRESSION",
	"OTEL_EXPORTER_OTLP_LOGS_COMPRESSION",
	"OTEL_EXPORTER_OTLP_METRICS_COMPRESSION",
}

// clearOTLPCompressionEnv resets every compression env var OTLPGzipDefault
// reads to "" via t.Setenv, so a test starts from a known-empty state and the
// previous value (including "unset") is restored automatically afterwards.
func clearOTLPCompressionEnv(t *testing.T) {
	t.Helper()
	for _, k := range otlpCompressionEnvVars {
		t.Setenv(k, "")
	}
}

func TestOTLPGzipDefault(t *testing.T) {
	tests := []struct {
		name   string
		env    map[string]string
		signal string
		want   bool
	}{
		{
			name:   "neither var set -> gzip default (logs)",
			env:    nil,
			signal: OTLPSignalLogs,
			want:   true,
		},
		{
			name:   "neither var set -> gzip default (metrics)",
			env:    nil,
			signal: OTLPSignalMetrics,
			want:   true,
		},
		{
			name:   "generic none disables gzip",
			env:    map[string]string{"OTEL_EXPORTER_OTLP_COMPRESSION": "none"},
			signal: OTLPSignalLogs,
			want:   false,
		},
		{
			// The operator asked explicitly for gzip. We must still return
			// false here: if we asked the SDK for gzip ourselves too, that's
			// harmless when it agrees, but the point of staying silent is
			// that a passed option beats the env var in the SDK's own
			// resolution order (see the doc comment on OTLPGzipDefault) --
			// so once a preference is expressed at all, we get out of the
			// way rather than relying on our own default and the operator's
			// explicit value happening to agree.
			name:   "generic gzip also means 'operator expressed a preference' -> false",
			env:    map[string]string{"OTEL_EXPORTER_OTLP_COMPRESSION": "gzip"},
			signal: OTLPSignalLogs,
			want:   false,
		},
		{
			// Most important case: a signal-specific var must not leak
			// across signals. Setting it for logs must leave metrics on the
			// gzip default.
			name:   "logs-specific none affects only logs",
			env:    map[string]string{"OTEL_EXPORTER_OTLP_LOGS_COMPRESSION": "none"},
			signal: OTLPSignalLogs,
			want:   false,
		},
		{
			name:   "logs-specific none does not leak to metrics",
			env:    map[string]string{"OTEL_EXPORTER_OTLP_LOGS_COMPRESSION": "none"},
			signal: OTLPSignalMetrics,
			want:   true,
		},
		{
			name:   "metrics-specific none affects only metrics",
			env:    map[string]string{"OTEL_EXPORTER_OTLP_METRICS_COMPRESSION": "none"},
			signal: OTLPSignalMetrics,
			want:   false,
		},
		{
			name:   "metrics-specific none does not leak to logs",
			env:    map[string]string{"OTEL_EXPORTER_OTLP_METRICS_COMPRESSION": "none"},
			signal: OTLPSignalLogs,
			want:   true,
		},
		{
			// Signal-specific beats generic when they'd otherwise disagree
			// on which key "wins" -- but both keys here are recognised
			// preferences (none and gzip), and OTLPGzipDefault only ever
			// returns false for a recognised preference, so this asserts
			// the outcome, not which key was consulted.
			name: "signal-specific (gzip) and generic (none) both count as a preference -> false for logs",
			env: map[string]string{
				"OTEL_EXPORTER_OTLP_COMPRESSION":      "none",
				"OTEL_EXPORTER_OTLP_LOGS_COMPRESSION": "gzip",
			},
			signal: OTLPSignalLogs,
			want:   false,
		},
		{
			// Same env, but for metrics: no metrics-specific var is set, so
			// this falls through to the generic key.
			name: "generic none governs metrics when no metrics-specific var is set",
			env: map[string]string{
				"OTEL_EXPORTER_OTLP_COMPRESSION":      "none",
				"OTEL_EXPORTER_OTLP_LOGS_COMPRESSION": "gzip",
			},
			signal: OTLPSignalMetrics,
			want:   false,
		},
		{
			// Falls through to our gzip default -- this deliberately
			// differs from the SDK's own resolution, which skips
			// unconvertible values and ends up with no compression. Our
			// terminal fallback is gzip, not none (see the doc comment).
			name:   "unrecognised value falls through to gzip default",
			env:    map[string]string{"OTEL_EXPORTER_OTLP_COMPRESSION": "bogus"},
			signal: OTLPSignalLogs,
			want:   true,
		},
		{
			name:   "empty string explicitly set behaves as unset -> gzip default",
			env:    map[string]string{"OTEL_EXPORTER_OTLP_COMPRESSION": ""},
			signal: OTLPSignalMetrics,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearOTLPCompressionEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			if got := OTLPGzipDefault(tt.signal); got != tt.want {
				t.Errorf("OTLPGzipDefault(%q) = %v, want %v", tt.signal, got, tt.want)
			}
		})
	}
}
