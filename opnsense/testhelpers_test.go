package opnsense

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

// newTestClientWithServer creates an httptest.Server with a single handler and
// returns a Client pointed at it. The caller must call server.Close().
func newTestClientWithServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	server := httptest.NewServer(handler)

	client := &Client{
		httpClient:       server.Client(),
		baseURL:          server.URL,
		key:              "test-key",
		secret:           "test-secret",
		log:              slog.Default(),
		gatewayLossRegex: regexp.MustCompile(`\d\.\d %`),
		gatewayRTTRegex:  regexp.MustCompile(`\d+\.\d+ ms`),
		headers: map[string]string{
			"Accept":          "application/json",
			"User-Agent":      "prometheus-opnsense-exporter/test",
			"Accept-Encoding": "gzip",
		},
		endpoints:  defaultEndpoints(),
		maxRetries: MaxRetries,
	}

	return server, client
}

// newTestClientWithMux creates an httptest.Server with a ServeMux and returns
// the server, mux, and a Client. Use this for tests that need multiple endpoints.
func newTestClientWithMux(t *testing.T) (*httptest.Server, *http.ServeMux, *Client) {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	client := &Client{
		httpClient:       server.Client(),
		baseURL:          server.URL,
		key:              "test-key",
		secret:           "test-secret",
		log:              slog.Default(),
		gatewayLossRegex: regexp.MustCompile(`\d\.\d %`),
		gatewayRTTRegex:  regexp.MustCompile(`\d+\.\d+ ms`),
		headers: map[string]string{
			"Accept":          "application/json",
			"User-Agent":      "prometheus-opnsense-exporter/test",
			"Accept-Encoding": "gzip",
		},
		endpoints:  defaultEndpoints(),
		maxRetries: MaxRetries,
	}

	return server, mux, client
}

// mustMarshal JSON-encodes v, failing the test on error.
func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("mustMarshal: %v", err)
	}
	return data
}
