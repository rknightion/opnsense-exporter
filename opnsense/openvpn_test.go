package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchOpenVPNInstances_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.Write([]byte(`{
			"rows": [
				{
					"uuid": "vpn-uuid-1",
					"description": "Road Warrior VPN",
					"role": "Server",
					"dev_type": "tun",
					"enabled": "1"
				},
				{
					"uuid": "vpn-uuid-2",
					"description": "Site-to-Site VPN",
					"role": "CLIENT",
					"dev_type": "tap",
					"enabled": "0"
				}
			],
			"rowCount": 2,
			"total": 2,
			"current": 1
		}`))
	})
	defer server.Close()

	data, err := client.FetchOpenVPNInstances()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Rows) != 2 {
		t.Fatalf("expected 2 instances, got %d", len(data.Rows))
	}

	// Check role lowercasing
	i1 := data.Rows[0]
	if i1.UUID != "vpn-uuid-1" {
		t.Errorf("expected UUID 'vpn-uuid-1', got %q", i1.UUID)
	}
	if i1.Description != "Road Warrior VPN" {
		t.Errorf("expected description 'Road Warrior VPN', got %q", i1.Description)
	}
	if i1.Role != "server" {
		t.Errorf("expected role 'server' (lowercased), got %q", i1.Role)
	}
	if i1.DevType != "tun" {
		t.Errorf("expected DevType 'tun', got %q", i1.DevType)
	}
	if i1.Enabled != 1 {
		t.Errorf("expected Enabled=1, got %d", i1.Enabled)
	}

	i2 := data.Rows[1]
	if i2.Role != "client" {
		t.Errorf("expected role 'client' (lowercased), got %q", i2.Role)
	}
	if i2.Enabled != 0 {
		t.Errorf("expected Enabled=0, got %d", i2.Enabled)
	}
}

func TestFetchOpenVPNInstances_InvalidEnabled(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"uuid": "vpn-uuid-1",
					"description": "Bad VPN",
					"role": "Server",
					"dev_type": "tun",
					"enabled": "not_a_number"
				}
			],
			"rowCount": 1,
			"total": 1,
			"current": 1
		}`))
	})
	defer server.Close()

	_, err := client.FetchOpenVPNInstances()
	if err == nil {
		t.Fatal("expected error for invalid enabled value")
	}
}

func TestFetchOpenVPNInstances_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchOpenVPNInstances()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestFetchOpenVPNSessions_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"rows": [
				{
					"description": "Road Warrior VPN",
					"username": "user1",
					"virtual_address": "10.8.0.2",
					"status": "ok"
				},
				{
					"description": "Road Warrior VPN",
					"username": "user2",
					"virtual_address": "10.8.0.3",
					"status": "disconnected"
				}
			],
			"rowCount": 2,
			"total": 2,
			"current": 1
		}`))
	})
	defer server.Close()

	data, err := client.FetchOpenVPNSessions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Rows) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(data.Rows))
	}

	// Status "ok" -> 1
	s1 := data.Rows[0]
	if s1.Username != "user1" {
		t.Errorf("expected username 'user1', got %q", s1.Username)
	}
	if s1.VirtualAddress != "10.8.0.2" {
		t.Errorf("expected virtual address '10.8.0.2', got %q", s1.VirtualAddress)
	}
	if s1.Status != 1 {
		t.Errorf("expected Status=1 for 'ok', got %d", s1.Status)
	}

	// Status "disconnected" -> 0
	s2 := data.Rows[1]
	if s2.Status != 0 {
		t.Errorf("expected Status=0 for 'disconnected', got %d", s2.Status)
	}
}

func TestFetchOpenVPNSessions_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchOpenVPNSessions()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
