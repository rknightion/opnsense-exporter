package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchServiceStatus_Success(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected string
	}{
		{"Running", `{"status": "running"}`, "running"},
		{"Stopped", `{"status": "stopped"}`, "stopped"},
		{"Disabled", `{"status": "disabled"}`, "disabled"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.json))
			})
			defer server.Close()

			result, err := client.FetchServiceStatus("unboundServiceStatus")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestFetchServiceStatus_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchServiceStatus("unboundServiceStatus")
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestFetchServiceStatus_UnknownEndpoint(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for unknown endpoint")
	})
	defer server.Close()

	_, err := client.FetchServiceStatus("nonExistentEndpoint")
	if err == nil {
		t.Fatal("expected error for unknown endpoint")
	}
	if err.StatusCode != 0 {
		t.Errorf("expected status 0 for client error, got %d", err.StatusCode)
	}
}
