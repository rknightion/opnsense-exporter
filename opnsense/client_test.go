package opnsense

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
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
	"github.com/rknightion/opnsense2otel/v5/internal/options"
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
	if len(endpoints) != 204 {
		t.Errorf("expected 204 endpoints, got %d", len(endpoints))
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
		if got := r.Header.Get("User-Agent"); !strings.HasPrefix(got, "prometheus-opnsense2otel/") {
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

func TestTruncateBody_RedactsTruncatedAndCompositeSensitiveFields(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		secrets []string
		keep    string
	}{
		{
			name:    "truncated string",
			body:    `{"community":"forwarded-snmp-community`,
			secrets: []string{"forwarded-snmp-community"},
		},
		{
			name:    "array",
			body:    `{"otp_seed":["first-seed",{"nested":"second-seed"}],"keep":"visible"}`,
			secrets: []string{"first-seed", "second-seed"},
			keep:    `"keep":"visible"`,
		},
		{
			name:    "object",
			body:    `{"enckey":{"ciphertext":"encrypted-material","parts":["other-material"]},"keep":true}`,
			secrets: []string{"encrypted-material", "other-material"},
			keep:    `"keep":true`,
		},
		{
			name:    "truncated composite",
			body:    `{"ldap_bindpw":{"password":"bind-secret","nested":[1,2`,
			secrets: []string{"bind-secret"},
		},
		{
			name:    "malformed unquoted value with spaces",
			body:    `{"ldap_bindpw":alpha bravo charlie,"keep":1}`,
			secrets: []string{"alpha", "bravo", "charlie"},
			keep:    `"keep":1`,
		},
		{
			name:    "malformed escaped sensitive key",
			body:    `{"pass\word":"MALFORMEDKEYSECRET","keep":1}`,
			secrets: []string{"MALFORMEDKEYSECRET"},
			keep:    `"keep":1`,
		},
		{
			name:    "malformed escape inserted in sensitive key",
			body:    `{"pass\qword":"INSERTEDESCAPESECRET","keep":1}`,
			secrets: []string{"INSERTEDESCAPESECRET"},
			keep:    `"keep":1`,
		},
		{
			name:    "HTML quote reference inside sensitive JSON value",
			body:    `{"password":"PREFIX&quot;SUFFIX","keep":1}`,
			secrets: []string{"PREFIX", "SUFFIX"},
			keep:    `"keep":1`,
		},
		{
			name:    "stray quote before sensitive JSON field",
			body:    `"notice {"password":"CREDENTIAL"}`,
			secrets: []string{"CREDENTIAL"},
			keep:    "notice",
		},
		{
			name:    "stray quote before unquoted sensitive JSON-like field",
			body:    `"notice {password:"CREDENTIAL"}`,
			secrets: []string{"CREDENTIAL"},
			keep:    "notice",
		},
		{
			name:    "stray quote before structural-prefix sensitive value",
			body:    `"notice {password:",COMMASECRET"}`,
			secrets: []string{"COMMASECRET"},
			keep:    "notice",
		},
		{
			name:    "object value quote overlaps sensitive value opener",
			body:    `{"message":"notice {password:",OBJECTSECRET"}`,
			secrets: []string{"OBJECTSECRET"},
			keep:    "notice",
		},
		{
			name:    "array value quote overlaps sensitive value opener",
			body:    `["notice {password:",ARRAYSECRET"]`,
			secrets: []string{"ARRAYSECRET"},
			keep:    "notice",
		},
		{
			name:    "comma-delimited value quote overlaps sensitive value opener",
			body:    `{username:"public","notice {password:",COMMASECRET"}`,
			secrets: []string{"COMMASECRET"},
			keep:    "public",
		},
		{
			name:    "single-quoted sensitive JSON-like field",
			body:    `{'password':'FIELDSECRET'}`,
			secrets: []string{"FIELDSECRET"},
		},
		{
			name:    "single-quoted sensitive field containing object delimiters",
			body:    `{'password':'FIELD}SECRET,TAIL'}`,
			secrets: []string{"FIELD", "SECRET", "TAIL"},
		},
		{
			name:    "unquoted sensitive JSON-like field",
			body:    `{password:"UNQUOTEDFIELDSECRET"}`,
			secrets: []string{"UNQUOTEDFIELDSECRET"},
		},
		{
			name:    "split-quote sensitive JSON-like field",
			body:    `{"pass"word":"SPLITFIELDSECRET"}`,
			secrets: []string{"SPLITFIELDSECRET"},
		},
		{
			name:    "single-quoted string inside sensitive composite",
			body:    `{'password':{'part':'CRED}PREFIX'},'keep':1}`,
			secrets: []string{"CRED", "PREFIX"},
			keep:    "'keep':1",
		},
		{
			name:    "malformed suffix after quoted sensitive value",
			body:    `{"password":"CREDPREFIX"CREDSUFFIX,"keep":1}`,
			secrets: []string{"CREDPREFIX", "CREDSUFFIX"},
			keep:    `"keep":1`,
		},
		{
			name:    "malformed suffix after composite sensitive value",
			body:    `{"password":{"part":"CREDPREFIX"}CREDSUFFIX,"keep":1}`,
			secrets: []string{"CREDPREFIX", "CREDSUFFIX"},
			keep:    `"keep":1`,
		},
		{
			name:    "quoted comma inside malformed sensitive suffix",
			body:    `{"password":"CREDPREFIX"junk"CREDMID,CREDSUFFIX","keep":1}`,
			secrets: []string{"CREDPREFIX", "CREDMID", "CREDSUFFIX"},
			keep:    `"keep":1`,
		},
		{
			name:    "Unicode-escaped malformed JSON-like key",
			body:    `{pass\u0077ord:"UNICODESECRET"}`,
			secrets: []string{"UNICODESECRET"},
		},
		{
			name:    "invalidly escaped malformed JSON-like key",
			body:    `{pass\qword:"INVALIDESCAPESECRET"}`,
			secrets: []string{"INVALIDESCAPESECRET"},
		},
		{
			name:    "Unicode-escaped malformed JSON-like field delimiter",
			body:    `{password\u003a"UNICODECOLONSECRET"}`,
			secrets: []string{"UNICODECOLONSECRET"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := string(truncateBody([]byte(tc.body)))
			for _, secret := range tc.secrets {
				if strings.Contains(got, secret) {
					t.Errorf("expected sensitive value %q to be redacted, got: %s", secret, got)
				}
			}
			if !strings.Contains(got, `"[REDACTED]"`) {
				t.Errorf("expected a REDACTED marker, got: %s", got)
			}
			if tc.keep != "" && !strings.Contains(got, tc.keep) {
				t.Errorf("expected benign suffix %q to survive, got: %s", tc.keep, got)
			}
		})
	}
}

func TestTruncateBody_LeavesBenignJSONLikeFieldsAlone(t *testing.T) {
	for _, body := range []string{
		`{'username':'operator',{community_id:"public-name"},{"display"name:"visible"}}`,
		`{"message":"authentication failed, password: incorrect"}`,
		`{"path\\name":"visible"}`,
	} {
		got := string(truncateBody([]byte(body)))
		if got != body {
			t.Errorf("expected benign JSON-like fields to remain unchanged, got: %s", got)
		}
	}
}

func TestTruncateBody_RedactsFieldsInsideJSONString(t *testing.T) {
	// Synthetic backend diagnostics: live OPNsense occurrence is not established.
	for _, body := range []string{
		`{"message":"configd: {'password': 'SYNTH-NESTED'}"}`,
		`{"message":"backend: {\"password\":\"SYNTH-NESTED\"}"}`,
		`{"errorMessage":"cmd '{password:\"SYNTH-NESTED\"}' failed"}`,
		`"{'password':'SYNTH-NESTED'}"`,
	} {
		got := string(truncateBody([]byte(body)))
		if strings.Contains(got, "SYNTH-NESTED") {
			t.Errorf("nested credential survived: %s", got)
		}
		if !json.Valid([]byte(got)) {
			t.Errorf("valid JSON became invalid: %s", got)
		}
	}
	const benign = `{"message":"the password: field is required"}`
	if got := string(truncateBody([]byte(benign))); got != benign {
		t.Errorf("benign prose changed: %s", got)
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
		name           string
		body           string
		secret         string
		decodedSecrets []string
		keep           string
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
		{
			name:   "url userinfo password containing colons",
			body:   `{"remote":"https://admin:password-prefix:password-suffix@backup.example.com/config.xml"}`,
			secret: "password-prefix:password-suffix",
			keep:   "backup.example.com",
		},
		{
			name:   "scheme relative URL userinfo",
			body:   `{"remote":"//admin:relative-secret@backup.example.com/config.xml"}`,
			secret: "relative-secret",
			keep:   "backup.example.com",
		},
		{
			name:   "JSON escaped URL userinfo",
			body:   `{"remote":"https:\/\/admin:escaped-secret@backup.example.com/config.xml"}`,
			secret: "escaped-secret",
			keep:   "backup.example.com",
		},
		{
			name:   "JSON escaped ampersand before query credential",
			body:   `{"url":"https:\/\/example.com\/download?format=json\u0026license_key=escaped-query-secret"}`,
			secret: "escaped-query-secret",
			keep:   "example.com",
		},
		{
			name:   "JSON escaped question mark before query credential",
			body:   `{"url":"https:\/\/example.com\/download\u003fapi_key=escaped-leading-secret"}`,
			secret: "escaped-leading-secret",
			keep:   "example.com",
		},
		{
			name:           "JSON escaped query credential value",
			body:           `{"url":"https:\/\/example.com\/?license_key=\u0053ECRET"}`,
			secret:         `\u0053ECRET`,
			decodedSecrets: []string{"SECRET"},
			keep:           "example.com",
		},
		{
			name:   "JSON escaped query credential key and equals",
			body:   `{"url":"https:\/\/example.com\/?api\u005fkey\u003descaped-key-secret"}`,
			secret: "escaped-key-secret",
			keep:   "example.com",
		},
		{
			name:   "URL percent encoded query credential key",
			body:   `{"url":"https://example.com/?api%5Fkey=percent-encoded-key-secret"}`,
			secret: "percent-encoded-key-secret",
			keep:   "example.com",
		},
		{
			name:   "malformed query component before percent encoded credential key",
			body:   `{"url":"https://example.com/?bad=x;y&api%5Fkey=mixed-query-secret"}`,
			secret: "mixed-query-secret",
			keep:   "example.com",
		},
		{
			name:   "percent encoded credential key with malformed value",
			body:   `{"url":"https://example.com/?api%5Fkey=%zzQUERYSECRET"}`,
			secret: "QUERYSECRET",
			keep:   "example.com",
		},
		{
			name:           "decoded query credential containing spaces",
			body:           `{"url":"https://example.com/?api%5Fkey=alpha bravo charlie"}`,
			secret:         "alpha bravo charlie",
			decodedSecrets: []string{"alpha", "bravo", "charlie"},
			keep:           "example.com",
		},
		{
			name:           "decoded query credential containing backslash",
			body:           `{"url":"https://example.com/?api%5Fkey=alpha\\bravo"}`,
			secret:         `alpha\\bravo`,
			decodedSecrets: []string{"alpha", "bravo"},
			keep:           "example.com",
		},
		{
			name:   "relative URL with percent encoded credential key",
			body:   `{"url":"//example.com/?api%5Fkey=relative-query-secret"}`,
			secret: "relative-query-secret",
			keep:   "example.com",
		},
		{
			name:   "plain text URL with percent encoded credential key",
			body:   `fetch //example.com/?api%5Fkey=plain-query-secret failed`,
			secret: "plain-query-secret",
			keep:   "example.com",
		},
		{
			name:   "HTML named ampersand before credential",
			body:   `<a href="https://example.com/?format=json&amp;api_key=html-secret">retry</a>`,
			secret: "html-secret",
			keep:   "example.com",
		},
		{
			name:   "HTML decimal ampersand before credential",
			body:   `<a href="https://example.com/?format=json&#38;api_key=decimal-secret">retry</a>`,
			secret: "decimal-secret",
			keep:   "example.com",
		},
		{
			name:   "HTML decimal ampersand with leading zero before credential",
			body:   `<a href="https://example.com/?format=json&#038;api_key=leading-zero-secret">retry</a>`,
			secret: "leading-zero-secret",
			keep:   "example.com",
		},
		{
			name:   "HTML semicolonless decimal ampersand before credential",
			body:   `<a href="https://example.com/?format=json&#38api_key=semicolonless-secret">retry</a>`,
			secret: "semicolonless-secret",
			keep:   "example.com",
		},
		{
			name:   "HTML hexadecimal ampersand before credential",
			body:   `<a href="https://example.com/?format=json&#x26;api_key=hex-secret">retry</a>`,
			secret: "hex-secret",
			keep:   "example.com",
		},
		{
			name:   "HTML hexadecimal ampersand with leading zeroes before credential",
			body:   `<a href="https://example.com/?format=json&#x00026;api_key=hex-leading-zero-secret">retry</a>`,
			secret: "hex-leading-zero-secret",
			keep:   "example.com",
		},
		{
			name:   "HTML semicolonless named ampersand before encoded credential",
			body:   `<a href="https://example.com/?format=json&amp%61pi_key=named-semicolonless-secret">retry</a>`,
			secret: "named-semicolonless-secret",
			keep:   "example.com",
		},
		{
			name:   "HTML numeric reference inside credential key",
			body:   `<a href="https://example.com/?api&#95;key=entity-key-secret">retry</a>`,
			secret: "entity-key-secret",
			keep:   "example.com",
		},
		{
			name:           "HTML quote reference inside credential value",
			body:           `<a href="https://example.com/?api_key=PREFIX&quot;SUFFIX">retry</a>`,
			secret:         "PREFIX",
			decodedSecrets: []string{"SUFFIX"},
			keep:           "example.com",
		},
		{
			name:           "HTML question and quote references around credential value",
			body:           `<a href="https://example.com/&#63;api_key=PREFIX&quot;SUFFIX">retry</a>`,
			secret:         "PREFIX",
			decodedSecrets: []string{"SUFFIX"},
			keep:           "example.com",
		},
		{
			name:           "JSON-encoded HTML quote reference inside credential value",
			body:           `{"url":"https://example.com/?api_key=PREFIX&quot;SUFFIX"}`,
			secret:         "PREFIX",
			decodedSecrets: []string{"SUFFIX"},
			keep:           "example.com",
		},
		{
			name:           "JSON-escaped ampersand before HTML quote reference",
			body:           `{"url":"https://example.invalid/?api_key=PREFIX\u0026quot;SUFFIX"}`,
			secret:         "PREFIX",
			decodedSecrets: []string{"SUFFIX"},
			keep:           "example.invalid",
		},
		{
			name:   "JSON-escaped ampersand before HTML question reference",
			body:   `{"url":"https://example.invalid/\u0026#63;api_key=QUESTIONSECRET"}`,
			secret: "QUESTIONSECRET",
			keep:   "example.invalid",
		},
		{
			name:   "JSON-escaped ampersand inside HTML credential key reference",
			body:   `{"url":"https://example.invalid/?api\u0026#95;key=KEYSECRET"}`,
			secret: "KEYSECRET",
			keep:   "example.invalid",
		},
		{
			name:           "HTML quote reference inside userinfo password",
			body:           `<a href="https://admin:PREFIX&quot;SUFFIX@backup.example.com/config">retry</a>`,
			secret:         "PREFIX",
			decodedSecrets: []string{"SUFFIX"},
			keep:           "retry",
		},
		{
			name:           "single-quoted HTML attribute with quote reference inside userinfo password",
			body:           `<a href='https://admin:PREFIX&quot;SUFFIX@backup.example.com/config'>retry</a>`,
			secret:         "PREFIX",
			decodedSecrets: []string{"SUFFIX"},
			keep:           "retry",
		},
		{
			name:           "unquoted HTML attribute with space reference inside userinfo password",
			body:           `<a href=https://admin:PREFIX&#32;SUFFIX@backup.example.com/config>retry</a>`,
			secret:         "PREFIX",
			decodedSecrets: []string{"SUFFIX"},
			keep:           "retry",
		},
		{
			name:           "unquoted HTML attribute with whitespace before equals",
			body:           `<a href =https://admin:PREFIX&#32;SUFFIX@backup.example.com/config>retry</a>`,
			secret:         "PREFIX",
			decodedSecrets: []string{"SUFFIX"},
			keep:           "retry",
		},
		{
			name:           "unquoted HTML attribute with form feed boundaries",
			body:           "<a href\f=\fhttps://admin:PREFIX&#32;SUFFIX@backup.example.com/config>retry</a>",
			secret:         "PREFIX",
			decodedSecrets: []string{"SUFFIX"},
			keep:           "retry",
		},
		{
			name:           "quoted HTML attribute after unmatched text quote",
			body:           `"notice <a href="https://admin:PREFIX SUFFIX@backup.example.com/config">retry</a>`,
			secret:         "PREFIX",
			decodedSecrets: []string{"SUFFIX"},
			keep:           "retry",
		},
		{
			name:           "quoted HTML query credential after unmatched text quote",
			body:           `"notice <a href="https://example.invalid/?api_key=CREDPREFIX CREDSUFFIX">retry</a>`,
			secret:         "CREDPREFIX",
			decodedSecrets: []string{"CREDSUFFIX"},
			keep:           "retry",
		},
		{
			name:           "quoted HTML credential after benign backslash attribute",
			body:           `<a href="safe\">first</a><a href="https://user:CREDPREFIX CREDSUFFIX@example.invalid/config">retry</a>`,
			secret:         "CREDPREFIX",
			decodedSecrets: []string{"CREDSUFFIX"},
			keep:           "retry",
		},
		{
			name:           "credential URL after stray malformed JSON quote",
			body:           `"notice {"url":"https://user:CREDPREFIX CREDSUFFIX@example.invalid/config"}`,
			secret:         "CREDPREFIX",
			decodedSecrets: []string{"CREDSUFFIX"},
			keep:           "notice",
		},
		{
			name:           "overlapping credential JSON URL tokens",
			body:           `"https://old:OLDSECRET@example.invalid "https://user:CRED PREFIX@example.invalid/config"`,
			secret:         "OLDSECRET",
			decodedSecrets: []string{"CRED", "PREFIX"},
			keep:           "example.invalid",
		},
		{
			name:           "credential URL after malformed single-quoted HTML attribute",
			body:           `<a href='safe><a href='https://user:CREDPREFIX CREDSUFFIX@example.invalid/config'>`,
			secret:         "CREDPREFIX",
			decodedSecrets: []string{"CREDSUFFIX"},
			keep:           "example.invalid",
		},
		{
			name:           "credential query after malformed single-quoted HTML attribute",
			body:           `<a href='safe><a href='https://example.invalid/?api_key=CREDPREFIX CREDSUFFIX'>`,
			secret:         "CREDPREFIX",
			decodedSecrets: []string{"CREDSUFFIX"},
			keep:           "example.invalid",
		},
		{
			name:           "standalone single-quoted credential URL",
			body:           `request to 'https://user:CREDPREFIX CREDSUFFIX@example.invalid/config' failed`,
			secret:         "CREDPREFIX",
			decodedSecrets: []string{"CREDSUFFIX"},
			keep:           "example.invalid",
		},
		{
			name:           "incomplete standalone single-quoted credential URL",
			body:           `request to 'https://user:CREDPREFIX CREDSUFFIX@example.invalid/config`,
			secret:         "CREDPREFIX",
			decodedSecrets: []string{"CREDSUFFIX"},
			keep:           "example.invalid",
		},
		{
			name:           "incomplete standalone single-quoted userinfo prefix",
			body:           `request to 'https://user:CREDPREFIX CREDSUFFIX`,
			secret:         "CREDPREFIX",
			decodedSecrets: []string{"CREDSUFFIX"},
			keep:           "request to",
		},
		{
			name:           "single-quoted credential URL with escaped apostrophe",
			body:           `request to 'https://user:CRED\'PREFIX@example.invalid/config' failed`,
			secret:         "CRED",
			decodedSecrets: []string{"PREFIX"},
			keep:           "example.invalid",
		},
		{
			name:           "overlapping single-quoted credential URLs",
			body:           `request 'https://old:OLDSECRET@example.invalid/path\' https://new:NEWSECRET@example.invalid/config'`,
			secret:         "OLDSECRET",
			decodedSecrets: []string{"NEWSECRET"},
			keep:           "example.invalid",
		},
		{
			name:           "nested opposite-quoted HTML credential attributes",
			body:           `<a href="https://old:OLDSECRET@example.invalid <a href='https://new:NEWSECRET@example.invalid'>">`,
			secret:         "OLDSECRET",
			decodedSecrets: []string{"NEWSECRET"},
			keep:           "example.invalid",
		},
		{
			name:   "JSON escaped userinfo separators",
			body:   `{"remote":"https:\/\/admin\u003asupersecret\u0040backup.example.com"}`,
			secret: "supersecret",
			keep:   "backup.example.com",
		},
		{
			name:           "truncated JSON escaped query credential value",
			body:           `{"url":"https:\/\/example.com\/?license_key=\u0053ECRET`,
			secret:         `\u0053ECRET`,
			decodedSecrets: []string{"SECRET"},
			keep:           "example.com",
		},
		{
			name:   "truncated JSON escaped userinfo separators",
			body:   `{"remote":"https:\/\/admin\u003asupersecret\u0040backup.example.com`,
			secret: "supersecret",
			keep:   "backup.example.com",
		},
		{
			name:   "trailing incomplete escape after escaped query syntax",
			body:   `{"url":"https:\/\/example.com\/?api\u005fkey\u003dQUERYSECRET\`,
			secret: "QUERYSECRET",
		},
		{
			name:   "invalid escape after escaped userinfo syntax",
			body:   `{"remote":"https:\/\/admin\u003asupersecret\u0040backup.example.com\q"}`,
			secret: "supersecret",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := string(truncateBody([]byte(tc.body)))
			if strings.Contains(got, tc.secret) {
				t.Errorf("expected credential %q to be redacted, got: %s", tc.secret, got)
			}
			for _, secret := range tc.decodedSecrets {
				if strings.Contains(got, secret) {
					t.Errorf("expected decoded credential component %q to be redacted, got: %s", secret, got)
				}
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

func TestTruncateBody_ReclassifiesUserinfoAfterPostRedactionClamp(t *testing.T) {
	prefix := `{"password":"x","pad":"`
	suffix := ` https://admin:LEAKED-PASSWORD"}`
	body := []byte(prefix + strings.Repeat("a", maxErrorBodyBytes-len(prefix)-len(suffix)) + suffix)

	got := string(truncateBody(body))

	if strings.Contains(got, "LEAK") {
		t.Errorf("expected the userinfo prefix exposed by the final clamp to be redacted, got suffix: %.80s", got[len(got)-80:])
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("expected a redaction marker, got suffix: %.80s", got[len(got)-80:])
	}
}

func TestRedactSensitiveURLValue_RedactsWhitespaceInsideUserinfo(t *testing.T) {
	got := redactSensitiveURLValue(`https://admin:PREFIX SUFFIX@backup.example.com/config`)

	for _, secret := range []string{"PREFIX", "SUFFIX"} {
		if strings.Contains(got, secret) {
			t.Errorf("expected userinfo component %q to be redacted, got: %s", secret, got)
		}
	}
	if !strings.Contains(got, "backup.example.com") {
		t.Errorf("expected the benign host to survive redaction, got: %s", got)
	}
}

func TestTruncateBody_RedactsTruncatedURLUserinfo(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefix string
		tail   string
	}{
		{
			name:   "plain text separators",
			prefix: " https://admin:LEAK",
			tail:   "ED-PASSWORD@host",
		},
		{
			name:   "scheme relative separators",
			prefix: " //admin:LEAK",
			tail:   "ED-PASSWORD@host",
		},
		{
			name:   "JSON escaped separators",
			prefix: ` {"url":"https:\/\/admin\u003aLEAK`,
			tail:   `ED-PASSWORD@host"}`,
		},
		{
			name:   "cut inside JSON escaped at sign",
			prefix: ` {"url":"https:\/\/admin\u003aLEAK\u00`,
			tail:   `40host"}`,
		},
		{
			name:   "cut quoted HTML userinfo after entity whitespace",
			prefix: ` <a href="https://admin:LEAK&#32;ED-PASSWORD`,
			tail:   `@backup.example.com/config">`,
		},
		{
			name:   "cut quoted HTML userinfo after literal whitespace",
			prefix: ` <a href="https://admin:LEAK ED-PASSWORD`,
			tail:   `@backup.example.com/config">`,
		},
		{
			name:   "cut HTML userinfo after encoded opening quote",
			prefix: ` &quot;https://admin:LEAK ED-PASSWORD`,
			tail:   `@backup.example.com/config&quot;`,
		},
		{
			name:   "cut quoted HTML userinfo after unmatched text quote",
			prefix: ` "notice <a href="https://admin:LEAK ED-PASSWORD`,
			tail:   `@backup.example.com/config">`,
		},
		{
			name:   "cut quoted HTML query after unmatched text quote",
			prefix: ` "notice <a href="https://example.invalid/?api_key=LEAK-PREFIX LEAK-SUFFIX`,
			tail:   `">retry</a>`,
		},
		{
			name:   "cut JSON userinfo after escaped text quote",
			prefix: ` {"message":"notice \" https://user:LEAK ED-PASSWORD`,
			tail:   `@backup.example.com/config"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := strings.Repeat("x", maxErrorBodyBytes-len(tc.prefix))
			body := []byte(prefix + tc.prefix + tc.tail)
			got := string(truncateBody(body))

			if strings.Contains(got, "LEAK") {
				t.Errorf("expected truncated userinfo password prefix to be redacted, got suffix: %.80s", got[len(got)-80:])
			}
			if !strings.Contains(got, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker in truncated userinfo body, got suffix: %.80s", got[len(got)-80:])
			}
		})
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

func TestDo_InvalidJSONRedactsSharedSensitiveConfigKeys(t *testing.T) {
	for _, tc := range []struct {
		name   string
		key    string
		secret string
	}{
		{name: "TOTP seed", key: "otp_seed", secret: "totp-seed-secret"},
		{name: "LDAP bind password", key: "ldap_bindpw", secret: "ldap-bind-secret"},
		{name: "encrypted key", key: "enckey", secret: "encrypted-key-material"},
		{name: "Net-SNMP community", key: "community", secret: "snmp-community-secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"` + tc.key + `":"` + tc.secret + `",`))
			})
			defer server.Close()

			var result struct{}
			err := client.do("GET", "api/core/service/search", nil, &result)
			if err == nil {
				t.Fatal("expected malformed response error")
			}
			if got := err.Error(); strings.Contains(got, tc.secret) {
				t.Errorf("APICallError.Error leaked %q: %s", tc.secret, got)
			}
			if got := err.Error(); !strings.Contains(got, `"`+tc.key+`":"[REDACTED]"`) {
				t.Errorf("APICallError.Error did not preserve redacted %q field: %s", tc.key, got)
			}
		})
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
