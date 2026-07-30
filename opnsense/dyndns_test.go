package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchDynDNSAccounts_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dyndns/accounts/searchItem", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"total": 2,
			"rowCount": 2,
			"current": 1,
			"rows": [
				{
					"uuid": "aaaa-1111",
					"enabled": "1",
					"service": "cloudflare",
					"%service": "Cloudflare",
					"hostnames": "dyn.example.com",
					"zone": "example.com",
					"interface": "opt7",
					"%interface": "AAISP",
					"description": "Home IP",
					"current_ip": "198.51.100.31",
					"current_mtime": "2026-05-29T21:37:38+01:00",
					"password": "$2y$10$hashed",
					"%password": "***"
				},
				{
					"uuid": "bbbb-2222",
					"enabled": "0",
					"service": "dyndns",
					"%service": "DynDNS",
					"hostnames": "other.example.org",
					"zone": "",
					"interface": "wan",
					"%interface": "WAN",
					"description": "Office",
					"current_ip": "",
					"current_mtime": "",
					"password": "$2y$10$otherhash",
					"%password": "***"
				}
			]
		}`))
	})

	data, err := client.FetchDynDNSAccounts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.Total != 2 {
		t.Errorf("expected Total=2, got %d", data.Total)
	}
	if len(data.Accounts) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(data.Accounts))
	}

	a1 := data.Accounts[0]
	if a1.UUID != "aaaa-1111" {
		t.Errorf("expected UUID 'aaaa-1111', got %q", a1.UUID)
	}
	if !a1.Enabled {
		t.Errorf("expected account 0 to be enabled")
	}
	if a1.Service != "cloudflare" {
		t.Errorf("expected service 'cloudflare', got %q", a1.Service)
	}
	if a1.Hostnames != "dyn.example.com" {
		t.Errorf("expected hostnames 'dyn.example.com', got %q", a1.Hostnames)
	}
	if a1.Zone != "example.com" {
		t.Errorf("expected zone 'example.com', got %q", a1.Zone)
	}
	if a1.Interface != "opt7" {
		t.Errorf("expected interface 'opt7', got %q", a1.Interface)
	}
	if a1.Description != "Home IP" {
		t.Errorf("expected description 'Home IP', got %q", a1.Description)
	}
	if a1.CurrentIP != "198.51.100.31" {
		t.Errorf("expected current_ip '198.51.100.31', got %q", a1.CurrentIP)
	}
	if !a1.HasLastUpdate {
		t.Errorf("expected HasLastUpdate=true for account with current_mtime")
	}
	if a1.LastUpdateSeconds <= 0 {
		t.Errorf("expected positive LastUpdateSeconds, got %v", a1.LastUpdateSeconds)
	}

	a2 := data.Accounts[1]
	if a2.Enabled {
		t.Errorf("expected account 1 to be disabled")
	}
	if a2.CurrentIP != "" {
		t.Errorf("expected empty current_ip for never-updated account, got %q", a2.CurrentIP)
	}
	if a2.HasLastUpdate {
		t.Errorf("expected HasLastUpdate=false for account with empty current_mtime")
	}
	if a2.LastUpdateSeconds != 0 {
		t.Errorf("expected LastUpdateSeconds=0 for never-updated account, got %v", a2.LastUpdateSeconds)
	}
}

func TestFetchDynDNSAccounts_Empty(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dyndns/accounts/searchItem", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 0,
			"rowCount": 0,
			"current": 1,
			"rows": []
		}`))
	})

	data, err := client.FetchDynDNSAccounts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Total != 0 {
		t.Errorf("expected Total=0, got %d", data.Total)
	}
	if len(data.Accounts) != 0 {
		t.Errorf("expected 0 accounts, got %d", len(data.Accounts))
	}
}

func TestFetchDynDNSAccounts_ArrayQuirks(t *testing.T) {
	// OPNsense PHP may serialize unset fields as [] — must not panic.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dyndns/accounts/searchItem", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1,
			"rowCount": 1,
			"current": 1,
			"rows": [
				{
					"uuid": "cccc-3333",
					"enabled": "1",
					"service": [],
					"hostnames": [],
					"zone": [],
					"interface": [],
					"description": [],
					"current_ip": [],
					"current_mtime": []
				}
			]
		}`))
	})

	data, err := client.FetchDynDNSAccounts()
	if err != nil {
		t.Fatalf("unexpected error when fields are []: %v", err)
	}
	if len(data.Accounts) != 1 {
		t.Fatalf("expected 1 account, got %d", len(data.Accounts))
	}
	a := data.Accounts[0]
	if a.Service != "" {
		t.Errorf("expected empty service from [], got %q", a.Service)
	}
	if a.HasLastUpdate {
		t.Errorf("expected HasLastUpdate=false when current_mtime is []")
	}
}

func TestFetchDynDNSAccounts_NotFound(t *testing.T) {
	// Plugin not installed: endpoint returns 404. This must be treated as
	// "feature absent" — empty data, no error.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dyndns/accounts/searchItem", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	})

	data, err := client.FetchDynDNSAccounts()
	if err != nil {
		t.Fatalf("expected nil error for 404 (plugin absent), got %v", err)
	}
	if len(data.Accounts) != 0 || data.Total != 0 {
		t.Errorf("expected empty data for 404, got %d accounts / total %d", len(data.Accounts), data.Total)
	}
}

func TestFetchDynDNSAccounts_ServerError(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dyndns/accounts/searchItem", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})

	_, err := client.FetchDynDNSAccounts()
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestFetchDynDNSAccounts_InvalidMtime(t *testing.T) {
	// current_mtime with a non-RFC3339 value must not panic and must set
	// HasLastUpdate=false.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dyndns/accounts/searchItem", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1,
			"rowCount": 1,
			"current": 1,
			"rows": [
				{
					"uuid": "dddd-4444",
					"enabled": "1",
					"service": "cloudflare",
					"hostnames": "dyn.example.com",
					"zone": "",
					"interface": "opt7",
					"description": "Test",
					"current_ip": "1.2.3.4",
					"current_mtime": "not-a-timestamp"
				}
			]
		}`))
	})

	data, err := client.FetchDynDNSAccounts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Accounts) != 1 {
		t.Fatalf("expected 1 account, got %d", len(data.Accounts))
	}
	if data.Accounts[0].HasLastUpdate {
		t.Errorf("expected HasLastUpdate=false for unparseable current_mtime")
	}
}
