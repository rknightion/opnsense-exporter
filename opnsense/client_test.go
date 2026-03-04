package opnsense

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense-exporter/internal/options"
)

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
	if len(endpoints) != 52 {
		t.Errorf("expected 52 endpoints, got %d", len(endpoints))
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

func TestDo_Headers(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("expected Accept: application/json, got %q", got)
		}
		if got := r.Header.Get("User-Agent"); !strings.HasPrefix(got, "prometheus-opnsense-exporter/") {
			t.Errorf("expected User-Agent prefix, got %q", got)
		}
		if got := r.Header.Get("Accept-Encoding"); !strings.Contains(got, "gzip") {
			t.Errorf("expected Accept-Encoding to contain gzip, got %q", got)
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
