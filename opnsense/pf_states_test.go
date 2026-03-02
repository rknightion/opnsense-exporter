package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchPFStates_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{"current": "42350", "limit": "200000"}`))
	})
	defer server.Close()

	states, err := client.FetchPFStates()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if states.Current != 42350 {
		t.Errorf("expected Current=42350, got %d", states.Current)
	}
	if states.Limit != 200000 {
		t.Errorf("expected Limit=200000, got %d", states.Limit)
	}
}

func TestFetchPFStates_InvalidCurrentString(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"current": "not_a_number", "limit": "200000"}`))
	})
	defer server.Close()

	_, err := client.FetchPFStates()
	if err == nil {
		t.Fatal("expected error for invalid current string")
	}
}

func TestFetchPFStates_InvalidLimitString(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"current": "100", "limit": "abc"}`))
	})
	defer server.Close()

	_, err := client.FetchPFStates()
	if err == nil {
		t.Fatal("expected error for invalid limit string")
	}
}

func TestFetchPFStates_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchPFStates()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
