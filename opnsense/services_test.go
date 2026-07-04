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
		// Raw JSON literal mirroring a real /api/core/service/search payload, so a
		// wrong json tag or field type in servicesSearchResponse is caught rather than
		// round-tripped away (#155). Live shape: locked/running are native JSON ints.
		w.Write([]byte(`{
			"rows": [
				{"id": "1", "name": "sshd", "description": "Secure Shell Daemon", "locked": 0, "running": 1},
				{"id": "2", "name": "ntpd", "description": "NTP Daemon", "locked": 0, "running": 1},
				{"id": "3", "name": "dpinger", "description": "Gateway Monitor", "locked": 1, "running": 0}
			],
			"total": 3,
			"rowCount": 3,
			"current": 1
		}`))
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
		w.Write([]byte(`{"rows": [], "total": 0, "rowCount": 0, "current": 1}`))
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
