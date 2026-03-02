package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchServices_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		resp := servicesSearchResponse{
			Rows: []struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				Description string `json:"description"`
				Locked      int    `json:"locked"`
				Running     int    `json:"running"`
			}{
				{ID: "1", Name: "sshd", Description: "Secure Shell Daemon", Locked: 0, Running: 1},
				{ID: "2", Name: "ntpd", Description: "NTP Daemon", Locked: 0, Running: 1},
				{ID: "3", Name: "dpinger", Description: "Gateway Monitor", Locked: 1, Running: 0},
			},
			Total:    3,
			RowCount: 3,
			Current:  1,
		}
		w.Write(mustMarshal(t, resp))
	})
	defer server.Close()

	services, err := client.FetchServices()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if services.TotalRunning != 2 {
		t.Errorf("expected TotalRunning=2, got %d", services.TotalRunning)
	}
	if services.TotalStopped != 1 {
		t.Errorf("expected TotalStopped=1, got %d", services.TotalStopped)
	}
	if len(services.Services) != 3 {
		t.Fatalf("expected 3 services, got %d", len(services.Services))
	}

	// Check first service
	svc := services.Services[0]
	if svc.Name != "sshd" {
		t.Errorf("expected name 'sshd', got %q", svc.Name)
	}
	if svc.Description != "Secure Shell Daemon" {
		t.Errorf("expected description 'Secure Shell Daemon', got %q", svc.Description)
	}
	if svc.Status != ServiceStatusRunning {
		t.Errorf("expected status ServiceStatusRunning, got %d", svc.Status)
	}

	// Check stopped service
	svc3 := services.Services[2]
	if svc3.Status != ServiceStatusStopped {
		t.Errorf("expected status ServiceStatusStopped, got %d", svc3.Status)
	}
}

func TestFetchServices_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	})
	defer server.Close()

	_, err := client.FetchServices()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestFetchServices_EmptyList(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		resp := servicesSearchResponse{
			Rows: []struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				Description string `json:"description"`
				Locked      int    `json:"locked"`
				Running     int    `json:"running"`
			}{},
			Total: 0,
		}
		w.Write(mustMarshal(t, resp))
	})
	defer server.Close()

	services, err := client.FetchServices()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if services.TotalRunning != 0 {
		t.Errorf("expected TotalRunning=0, got %d", services.TotalRunning)
	}
	if services.TotalStopped != 0 {
		t.Errorf("expected TotalStopped=0, got %d", services.TotalStopped)
	}
	if len(services.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(services.Services))
	}
}
