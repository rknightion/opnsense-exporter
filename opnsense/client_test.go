package opnsense

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense-exporter/internal/options"
)

// TestNewClient_InsecureWarns covers #159: NewClient must emit a Warn when TLS
// verification is disabled, and stay silent otherwise.
func TestNewClient_InsecureWarns(t *testing.T) {
	const wantMsg = "TLS certificate verification disabled (opnsense.insecure); API credentials and data are exposed to MITM risk"

	for _, tc := range []struct {
		name     string
		insecure bool
		wantWarn bool
	}{
		{"insecure warns", true, true},
		{"secure silent", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
			cfg := options.OPNSenseConfig{Protocol: "https", Host: "fw", APIKey: "k", APISecret: "s", Insecure: tc.insecure}
			if _, err := NewClient(cfg, "test", log); err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			got := strings.Contains(buf.String(), wantMsg)
			if got != tc.wantWarn {
				t.Errorf("warn emitted=%v, want %v; log=%q", got, tc.wantWarn, buf.String())
			}
		})
	}
}

// TestNewClient_ConfigurableTimeout covers #140: the HTTP client timeout is taken from
// OPNSenseConfig.Timeout, defaulting to 15s to preserve existing behaviour.
func TestNewClient_ConfigurableTimeout(t *testing.T) {
	base := options.OPNSenseConfig{Protocol: "http", Host: "h", APIKey: "k", APISecret: "s"}

	def, err := NewClient(base, "t", promslog.NewNopLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if def.httpClient.Timeout != defaultClientTimeout {
		t.Errorf("default timeout = %v, want %v", def.httpClient.Timeout, defaultClientTimeout)
	}

	base.Timeout = 7 * time.Second
	custom, err := NewClient(base, "t", promslog.NewNopLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if custom.httpClient.Timeout != 7*time.Second {
		t.Errorf("configured timeout = %v, want 7s", custom.httpClient.Timeout)
	}
}

// TestNewClient_ConfigurableMaxRetries covers #140: the retry count comes from
// OPNSenseConfig.MaxRetries (default 3), so a GET against a persistent 503 with
// MaxRetries=1 hits the server exactly once.
func TestNewClient_ConfigurableMaxRetries(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	cfg := options.OPNSenseConfig{
		Protocol: "http", Host: strings.TrimPrefix(server.URL, "http://"),
		APIKey: "k", APISecret: "s", MaxRetries: 1,
	}
	client, err := NewClient(cfg, "t", promslog.NewNopLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	var out map[string]any
	_ = client.do("GET", "api/test/x", nil, &out)
	if got := hits.Load(); got != 1 {
		t.Errorf("with MaxRetries=1, server hit %d times, want 1", got)
	}
}

func TestNewClient_EndpointCount(t *testing.T) {
	cfg := options.OPNSenseConfig{
		Protocol:  "http",
		Host:      "localhost",
		APIKey:    "key",
		APISecret: "secret",
	}

	client, err := NewClient(cfg, "test", promslog.NewNopLogger())
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}

	endpoints := client.Endpoints()
	if len(endpoints) != 175 {
		t.Errorf("expected 175 endpoints, got %d", len(endpoints))
	}

	// Content equality, not just count: the live Client must use exactly the
	// canonical defaultEndpoints() table. The fetch tests now build their clients
	// from defaultEndpoints() too (there is no parallel testEndpoints() copy to
	// drift), so this also certifies fetch tests exercise the production URLs (#154).
	if !reflect.DeepEqual(endpoints, defaultEndpoints()) {
		t.Errorf("client endpoints diverge from defaultEndpoints()")
	}

	// Every registered endpoint must carry an ACL classification (#442), so a new
	// endpoint cannot ship without least-privilege guidance or an explicit
	// "unknown" verdict. TestEndpointACLCoversEveryEndpoint names the offender;
	// this keeps the requirement visible next to the count it travels with.
	if len(EndpointACLs()) != len(endpoints) {
		t.Errorf("ACL matrix covers %d endpoints, registry has %d; see opnsense/acl.go",
			len(EndpointACLs()), len(endpoints))
	}
}

func TestDo_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name":"test","value":42}`))
	})
	defer server.Close()

	var result struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	err := client.do("GET", "api/core/service/search", nil, &result)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result.Name != "test" {
		t.Errorf("expected name 'test', got %q", result.Name)
	}
	if result.Value != 42 {
		t.Errorf("expected value 42, got %d", result.Value)
	}
}

func TestDo_BasicAuth(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			t.Error("expected basic auth to be set")
		}
		if user != "test-key" || pass != "test-secret" {
			t.Errorf("expected test-key/test-secret, got %s/%s", user, pass)
		}
		w.Write([]byte(`{}`))
	})
	defer server.Close()

	var result map[string]any
	client.do("GET", "api/core/service/search", nil, &result)
}

// TestDo_DoesNotFollowRedirect covers #306/#307: the shared client must never
// follow a redirect, because Go's stdlib only strips the Authorization header
// when the redirect target's HOSTNAME differs — shouldCopyHeaderOnRedirect
// compares hostname only, not scheme and not port. So a 302 from
// https://fw/api/... to http://fw/api/... (or to another port on the same
// host) FORWARDS the API key and secret in cleartext, an SSL-strip shape.
// The OPNsense /api/* REST surface never redirects, so refusing to follow is
// correct: readResponse turns the 3xx into a loud APICallError.
func TestDo_DoesNotFollowRedirect(t *testing.T) {
	var targetHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		user, pass, _ := r.BasicAuth()
		t.Errorf("redirect target was reached with credentials %q/%q; the client must not follow redirects", user, pass)
		w.Write([]byte(`{}`))
	}))
	defer target.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/api/core/service/search", http.StatusFound)
	}))
	defer origin.Close()

	// A client built by NewClient, not the bare test helper: the CheckRedirect
	// policy under test lives on the http.Client that NewClient constructs.
	cfg := options.OPNSenseConfig{
		Protocol:  "http",
		Host:      strings.TrimPrefix(origin.URL, "http://"),
		APIKey:    "test-key",
		APISecret: "test-secret",
	}
	c, err := NewClient(cfg, "test", promslog.NewNopLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	var result map[string]any
	apiErr := c.do("GET", "api/core/service/search", nil, &result)
	if apiErr == nil {
		t.Fatal("expected an APICallError for a 3xx response, got nil")
	}
	if apiErr.StatusCode != http.StatusFound {
		t.Errorf("expected the 302 to surface as StatusCode=302, got %d (%s)", apiErr.StatusCode, apiErr.Message)
	}
	if n := targetHits.Load(); n != 0 {
		t.Errorf("expected the redirect target never to be hit, got %d request(s)", n)
	}
}

func TestDo_Headers(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("expected Accept: application/json, got %q", got)
		}
		if got := r.Header.Get("User-Agent"); !strings.HasPrefix(got, "prometheus-opnsense-exporter/") {
			t.Errorf("expected User-Agent prefix, got %q", got)
		}
		// Only gzip is advertised: readResponse can decode gzip but not
		// deflate/br, so unsupported encodings must not be requested.
		if got := r.Header.Get("Accept-Encoding"); got != "gzip" {
			t.Errorf("expected Accept-Encoding to be exactly %q, got %q", "gzip", got)
		}
		w.Write([]byte(`{}`))
	})
	defer server.Close()

	var result map[string]any
	client.do("GET", "api/core/service/search", nil, &result)
}

func TestDo_PostContentType(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		ct := r.Header.Get("Content-Type")
		if !strings.Contains(ct, "application/json") {
			t.Errorf("expected Content-Type application/json, got %q", ct)
		}
		w.Write([]byte(`{}`))
	})
	defer server.Close()

	var result map[string]any
	body := strings.NewReader(`{"key":"value"}`)
	client.do("POST", "api/core/service/search", body, &result)
}

func TestDo_GzipResponse(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		gz.Write([]byte(`{"compressed":true}`))
		gz.Close()

		w.Header().Set("Content-Encoding", "gzip")
		w.Write(buf.Bytes())
	})
	defer server.Close()

	var result struct {
		Compressed bool `json:"compressed"`
	}

	err := client.do("GET", "api/core/service/search", nil, &result)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !result.Compressed {
		t.Error("expected compressed=true after gzip decompression")
	}
}

func TestDo_NonSuccessStatus(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"Bad Request", http.StatusBadRequest},
		{"Unauthorized", http.StatusUnauthorized},
		{"Forbidden", http.StatusForbidden},
		{"Not Found", http.StatusNotFound},
		{"Internal Server Error", http.StatusInternalServerError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				w.Write([]byte("error response"))
			})
			defer server.Close()

			var result map[string]any
			err := client.do("GET", "api/core/service/search", nil, &result)
			if err == nil {
				t.Fatal("expected error for non-success status")
			}
			if err.StatusCode != tc.statusCode {
				t.Errorf("expected status %d, got %d", tc.statusCode, err.StatusCode)
			}
		})
	}
}

func TestDo_RetryOnError(t *testing.T) {
	var attempts atomic.Int32

	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		count := attempts.Add(1)
		if count < 3 {
			// Close the connection to simulate a network error
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("server doesn't support hijacking")
			}
			conn, _, _ := hj.Hijack()
			conn.Close()
			return
		}
		w.Write([]byte(`{"ok":true}`))
	})
	defer server.Close()

	var result struct {
		OK bool `json:"ok"`
	}

	err := client.do("GET", "api/core/service/search", nil, &result)
	if err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if !result.OK {
		t.Error("expected ok=true")
	}
}

func TestDo_MaxRetriesExceeded(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("server doesn't support hijacking")
		}
		conn, _, _ := hj.Hijack()
		conn.Close()
	})
	defer server.Close()

	var result map[string]any
	err := client.do("GET", "api/core/service/search", nil, &result)
	if err == nil {
		t.Fatal("expected error after max retries")
	}
	if !strings.Contains(err.Message, "max retries") {
		t.Errorf("expected 'max retries' in error message, got: %s", err.Message)
	}
}

func TestDo_InvalidJSON(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`not valid json`))
	})
	defer server.Close()

	var result struct {
		Name string `json:"name"`
	}

	err := client.do("GET", "api/core/service/search", nil, &result)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Message, "unmarshal") {
		t.Errorf("expected unmarshal error, got: %s", err.Message)
	}
}

func TestDo_RetryResendsPOSTBody(t *testing.T) {
	var attempts atomic.Int32
	const payload = `{"key":"value"}`

	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		count := attempts.Add(1)
		if count == 1 {
			// Close the connection to simulate a network error
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("server doesn't support hijacking")
			}
			conn, _, _ := hj.Hijack()
			conn.Close()
			return
		}
		got, _ := io.ReadAll(r.Body)
		if string(got) != payload {
			t.Errorf("retry attempt %d: expected body %q, got %q", count, payload, string(got))
		}
		w.Write([]byte(`{"ok":true}`))
	})
	defer server.Close()

	var result struct {
		OK bool `json:"ok"`
	}

	err := client.do("POST", "api/core/service/search", strings.NewReader(payload), &result)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if !result.OK {
		t.Error("expected ok=true")
	}
}

func TestTruncateBody_RedactsSensitiveFields(t *testing.T) {
	body := []byte(`{"username":"dyndns-user","interface":"wan",` +
		`"password":"$2y$10$hash","%password":"***","new.password":"x","token":12345}`)

	got := string(truncateBody(body))

	for _, secret := range []string{"$2y$10$hash", "***", `:"x"`, "12345"} {
		if strings.Contains(got, secret) {
			t.Errorf("expected sensitive value %q to be redacted, got: %s", secret, got)
		}
	}
	if !strings.Contains(got, `"password":"[REDACTED]"`) {
		t.Errorf("expected password value to read [REDACTED], got: %s", got)
	}
	if !strings.Contains(got, `"%password":"[REDACTED]"`) {
		t.Errorf("expected %%password value to read [REDACTED], got: %s", got)
	}
	if !strings.Contains(got, `"new.password":"[REDACTED]"`) {
		t.Errorf("expected new.password value to read [REDACTED], got: %s", got)
	}
	if !strings.Contains(got, `"token":"[REDACTED]"`) {
		t.Errorf("expected numeric token value to read [REDACTED], got: %s", got)
	}
	if !strings.Contains(got, `"username":"dyndns-user"`) {
		t.Errorf("expected benign username value to be untouched, got: %s", got)
	}
	if !strings.Contains(got, `"interface":"wan"`) {
		t.Errorf("expected benign interface value to be untouched, got: %s", got)
	}
}

func TestTruncateBody_RedactsCAPrivateKey(t *testing.T) {
	body := []byte(`{"descr":"OPNsense-CA","prv":"LS0tLS1CRUdJTiBQUklWQVRF","prv_payload":"-----BEGIN PRIVATE KEY-----\nMIIE","crt":"keep"}`)

	got := string(truncateBody(body))

	if strings.Contains(got, "LS0tLS1CRUdJTiBQUklWQVRF") || strings.Contains(got, "BEGIN PRIVATE KEY") {
		t.Errorf("expected private key material to be redacted, got: %s", got)
	}
	if !strings.Contains(got, `"prv":"[REDACTED]"`) || !strings.Contains(got, `"prv_payload":"[REDACTED]"`) {
		t.Errorf("expected prv fields to read [REDACTED], got: %s", got)
	}
	if !strings.Contains(got, `"descr":"OPNsense-CA"`) {
		t.Errorf("expected benign descr value to be untouched, got: %s", got)
	}
}

// TestTruncateBody_RedactsCredentialInURLValue covers #305: redaction by KEY
// name alone is not enough. The firewall GeoIP config returns a field literally
// named "url" whose VALUE embeds "&license_key=<secret>", so a non-2xx or
// malformed-JSON body copies a live MaxMind/ipinfo credential verbatim into
// APICallError.Message, which the firewall collector then logs. Credential-
// bearing query parameters and URL userinfo must be scrubbed by value,
// whatever the enclosing key is called.
func TestTruncateBody_RedactsCredentialInURLValue(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		secret string
		keep   string
	}{
		{
			name:   "maxmind license_key in a url field",
			body:   `{"url":"https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip&license_key=SECRETKEY123","usages":1}`,
			secret: "SECRETKEY123",
			keep:   "download.maxmind.com",
		},
		{
			name:   "api_key query parameter",
			body:   `{"endpoint":"https://example.com/v1/fetch?api_key=hunter2&fmt=json"}`,
			secret: "hunter2",
			keep:   "example.com",
		},
		{
			name:   "leading question-mark token parameter",
			body:   `{"href":"https://example.com/cb?token=abc123def"}`,
			secret: "abc123def",
			keep:   "example.com",
		},
		{
			name:   "bare key parameter",
			body:   `{"src":"https://ipinfo.io/data/country.mmdb?key=ipinfosecret"}`,
			secret: "ipinfosecret",
			keep:   "ipinfo.io",
		},
		{
			name:   "url userinfo",
			body:   `{"remote":"https://admin:supersecret@backup.example.com/config.xml"}`,
			secret: "supersecret",
			keep:   "backup.example.com",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := string(truncateBody([]byte(tc.body)))
			if strings.Contains(got, tc.secret) {
				t.Errorf("expected credential %q to be redacted, got: %s", tc.secret, got)
			}
			if !strings.Contains(got, "REDACTED") {
				t.Errorf("expected a REDACTED marker, got: %s", got)
			}
			if !strings.Contains(got, tc.keep) {
				t.Errorf("expected the benign part %q to survive redaction, got: %s", tc.keep, got)
			}
		})
	}
}

// TestTruncateBody_LeavesBenignQueryParametersAlone guards against the
// value-based pass over-redacting: only credential-named parameters go, the
// rest of the URL must stay legible for debugging.
func TestTruncateBody_LeavesBenignQueryParametersAlone(t *testing.T) {
	body := []byte(`{"url":"https://example.com/download?suffix=zip&edition_id=GeoLite2-Country&license_key=SECRET"}`)

	got := string(truncateBody(body))

	for _, keep := range []string{"suffix=zip", "edition_id=GeoLite2-Country"} {
		if !strings.Contains(got, keep) {
			t.Errorf("expected benign query parameter %q to survive, got: %s", keep, got)
		}
	}
	if strings.Contains(got, "SECRET") {
		t.Errorf("expected the license key to be redacted, got: %s", got)
	}
}

func TestTruncateBody_RedactsBeforeTruncating(t *testing.T) {
	body := []byte(`{"apikey":"supersecret","pad":"` + strings.Repeat("a", maxErrorBodyBytes) + `"}`)

	got := string(truncateBody(body))

	if strings.Contains(got, "supersecret") {
		t.Errorf("expected apikey value to be redacted in oversized body, got prefix: %.100s", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("expected [REDACTED] marker in oversized body, got prefix: %.100s", got)
	}
	if !strings.HasSuffix(got, "... (truncated)") {
		t.Error("expected oversized body to carry the truncation suffix")
	}
	if len(got) > maxErrorBodyBytes+len("... (truncated)") {
		t.Errorf("expected body bounded to %d bytes plus suffix, got %d", maxErrorBodyBytes, len(got))
	}
}

func TestTruncateBody_NonJSONPassesThrough(t *testing.T) {
	body := []byte("<html><body>plain error page</body></html>")

	got := string(truncateBody(body))

	if got != string(body) {
		t.Errorf("expected non-JSON body to pass through unchanged, got: %s", got)
	}
}

func TestDo_InvalidJSONRedactsSecrets(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Unmarshalable (unterminated) JSON carrying a credential.
		w.Write([]byte(`{"password":"hunter2","rows":`))
	})
	defer server.Close()

	var result struct {
		Name string `json:"name"`
	}

	err := client.do("GET", "api/core/service/search", nil, &result)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if strings.Contains(err.Message, "hunter2") {
		t.Errorf("expected password value to be redacted from error message, got: %s", err.Message)
	}
	if !strings.Contains(err.Message, "[REDACTED]") {
		t.Errorf("expected [REDACTED] marker in error message, got: %s", err.Message)
	}
}

func TestDo_NonSuccessStatusRedactsSecrets(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"auth failed","api_key":"hunter2"}`))
	})
	defer server.Close()

	var result map[string]any
	err := client.do("GET", "api/core/service/search", nil, &result)
	if err == nil {
		t.Fatal("expected error for non-success status")
	}
	if strings.Contains(err.Message, "hunter2") {
		t.Errorf("expected api_key value to be redacted from error message, got: %s", err.Message)
	}
	if !strings.Contains(err.Message, "[REDACTED]") {
		t.Errorf("expected [REDACTED] marker in error message, got: %s", err.Message)
	}
	if !strings.Contains(err.Message, "auth failed") {
		t.Errorf("expected benign message field to be untouched, got: %s", err.Message)
	}
}

func TestDo_OversizedGzipResponseRejected(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		// A small compressed payload that inflates past the response size cap.
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		chunk := make([]byte, 1<<20)
		for written := 0; written <= maxResponseBodyBytes; written += len(chunk) {
			if _, err := gz.Write(chunk); err != nil {
				return
			}
		}
	})
	defer server.Close()

	var result map[string]any
	err := client.do("GET", "api/core/service/search", nil, &result)
	if err == nil {
		t.Fatal("expected error for oversized response body")
	}
	if !strings.Contains(err.Message, "exceeds") {
		t.Errorf("expected size limit error, got: %s", err.Message)
	}
}

func TestWithContextCancelsSlowRequest(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	bound := client.WithContext(ctx)

	start := time.Now()
	var out map[string]any
	apiErr := bound.do("GET", "api/test/slow", nil, &out)
	elapsed := time.Since(start)

	if apiErr == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("request was not aborted promptly; took %s", elapsed)
	}
	if !strings.Contains(apiErr.Message, "request aborted") {
		t.Errorf("expected 'request aborted' in error message, got %q", apiErr.Message)
	}
	if strings.Contains(apiErr.Message, "max retries") {
		t.Errorf("cancelled context must not burn the retry budget, got %q", apiErr.Message)
	}
}

func TestWithContextBackgroundStillWorks(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	defer server.Close()

	bound := client.WithContext(context.Background())

	var out map[string]any
	if apiErr := bound.do("GET", "api/test/ok", nil, &out); apiErr != nil {
		t.Fatalf("expected success, got %v", apiErr)
	}
	if out["ok"] != true {
		t.Errorf("expected ok=true in response, got %v", out)
	}
}

// TestDo_RawBytesSentinel covers the *[]byte bypass added for #205
// (crowdsec's version/get, which is not JSON at all): a *[]byte responseStruct
// must receive the exact response bytes, verbatim, with no JSON decoding
// attempted — including bodies that are not valid JSON.
func TestDo_RawBytesSentinel(t *testing.T) {
	const rawBody = "version: v1.7.8_1-6322745\nCodename: alphaga\n"
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, rawBody)
	})
	defer server.Close()

	var out []byte
	if apiErr := client.do("GET", "api/test/raw", nil, &out); apiErr != nil {
		t.Fatalf("expected success, got %v", apiErr)
	}
	if string(out) != rawBody {
		t.Errorf("expected raw body %q, got %q", rawBody, string(out))
	}
}

// TestDo_RawBytesSentinel_CacheRoundtrip verifies the *[]byte bypass also
// works correctly when the response is served from the cache (the second
// GET below never reaches the server), since unmarshalBody is shared by both
// the live-response and cache-hit paths. Uses the real crowdsecVersion
// endpoint so SetEndpointCacheTTL resolves a valid path.
func TestDo_RawBytesSentinel_CacheRoundtrip(t *testing.T) {
	const rawBody = "version: v1.7.8_1-6322745\nCodename: alphaga\n"
	var hits int
	mux := http.NewServeMux()
	mux.HandleFunc("/api/crowdsec/version/get", func(w http.ResponseWriter, r *http.Request) {
		hits++
		fmt.Fprint(w, rawBody)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &Client{
		httpClient: server.Client(),
		baseURL:    server.URL,
		key:        "test-key",
		secret:     "test-secret",
		log:        slog.Default(),
		headers:    map[string]string{},
		endpoints:  defaultEndpoints(),
		maxRetries: MaxRetries,
	}
	client.SetEndpointCacheTTL("crowdsecVersion", time.Hour)
	path := client.endpoints["crowdsecVersion"]

	for i := 0; i < 2; i++ {
		var out []byte
		if apiErr := client.do("GET", path, nil, &out); apiErr != nil {
			t.Fatalf("call %d: expected success, got %v", i, apiErr)
		}
		if string(out) != rawBody {
			t.Errorf("call %d: expected raw body %q, got %q", i, rawBody, string(out))
		}
	}
	if hits != 1 {
		t.Errorf("expected the server to be hit once (second call served from cache), got %d", hits)
	}
}
