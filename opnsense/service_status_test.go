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

func TestFetchServiceStatusOptional_Running(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	defer server.Close()

	status, ok, err := client.FetchServiceStatusOptional("dyndnsServiceStatus")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok || status != "running" {
		t.Errorf("expected (running, true), got (%q, %v)", status, ok)
	}
}

func TestFetchServiceStatusOptional_404IsAbsent(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	status, ok, err := client.FetchServiceStatusOptional("dyndnsServiceStatus")
	if err != nil {
		t.Fatalf("expected nil error on 404, got: %v", err)
	}
	if ok || status != "" {
		t.Errorf("expected (\"\", false), got (%q, %v)", status, ok)
	}
}

func TestFetchServiceStatusOptional_ServerErrorPropagates(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	defer server.Close()

	_, _, err := client.FetchServiceStatusOptional("dyndnsServiceStatus")
	if err == nil {
		t.Fatal("expected error on 500")
	}
}
