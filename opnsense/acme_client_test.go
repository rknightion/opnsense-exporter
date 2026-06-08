package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchACMECertificates_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/acmeclient/certificates/search", func(w http.ResponseWriter, r *http.Request) {
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
					"name": "example.com",
					"description": "Primary wildcard cert",
					"altNames": "www.example.com,api.example.com",
					"lastUpdate": 1700000000,
					"statusCode": 200,
					"statusLastUpdate": 1700000100
				},
				{
					"uuid": "bbbb-2222",
					"enabled": "0",
					"name": "staging.example.com",
					"description": "Staging cert",
					"altNames": [],
					"lastUpdate": 0,
					"statusCode": 100,
					"statusLastUpdate": 0
				}
			]
		}`))
	})

	data, err := client.FetchACMECertificates()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.Total != 2 {
		t.Errorf("expected Total=2, got %d", data.Total)
	}
	if len(data.Certificates) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(data.Certificates))
	}

	c1 := data.Certificates[0]
	if c1.Name != "example.com" {
		t.Errorf("expected name 'example.com', got %q", c1.Name)
	}
	if c1.Description != "Primary wildcard cert" {
		t.Errorf("expected description 'Primary wildcard cert', got %q", c1.Description)
	}
	if c1.AltNames != "www.example.com,api.example.com" {
		t.Errorf("expected altNames 'www.example.com,api.example.com', got %q", c1.AltNames)
	}
	if !c1.Enabled {
		t.Errorf("expected cert 0 to be enabled")
	}
	if c1.LastUpdate != 1700000000 {
		t.Errorf("expected LastUpdate=1700000000, got %v", c1.LastUpdate)
	}
	if c1.StatusCode != 200 {
		t.Errorf("expected StatusCode=200, got %v", c1.StatusCode)
	}
	if c1.StatusLastUpdate != 1700000100 {
		t.Errorf("expected StatusLastUpdate=1700000100, got %v", c1.StatusLastUpdate)
	}

	c2 := data.Certificates[1]
	if c2.Name != "staging.example.com" {
		t.Errorf("expected name 'staging.example.com', got %q", c2.Name)
	}
	if c2.Enabled {
		t.Errorf("expected cert 1 to be disabled")
	}
	// altNames arrived as [] — must decode to empty string
	if c2.AltNames != "" {
		t.Errorf("expected empty altNames from [], got %q", c2.AltNames)
	}
	if c2.LastUpdate != 0 {
		t.Errorf("expected LastUpdate=0, got %v", c2.LastUpdate)
	}
	if c2.StatusCode != 100 {
		t.Errorf("expected StatusCode=100, got %v", c2.StatusCode)
	}
	if c2.StatusLastUpdate != 0 {
		t.Errorf("expected StatusLastUpdate=0, got %v", c2.StatusLastUpdate)
	}
}

func TestFetchACMECertificates_Empty(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/acmeclient/certificates/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 0,
			"rowCount": 0,
			"current": 1,
			"rows": []
		}`))
	})

	data, err := client.FetchACMECertificates()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Total != 0 {
		t.Errorf("expected Total=0, got %d", data.Total)
	}
	if len(data.Certificates) != 0 {
		t.Errorf("expected 0 certificates, got %d", len(data.Certificates))
	}
}

func TestFetchACMECertificates_ArrayQuirks(t *testing.T) {
	// OPNsense PHP may serialize integer fields as [] when unset.
	// All flexString fields must tolerate [] without error.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/acmeclient/certificates/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1,
			"rowCount": 1,
			"current": 1,
			"rows": [
				{
					"uuid": "cccc-3333",
					"enabled": "1",
					"name": "new.example.com",
					"description": [],
					"altNames": [],
					"lastUpdate": [],
					"statusCode": [],
					"statusLastUpdate": []
				}
			]
		}`))
	})

	data, err := client.FetchACMECertificates()
	if err != nil {
		t.Fatalf("unexpected error when fields are []: %v", err)
	}
	if len(data.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(data.Certificates))
	}
	c := data.Certificates[0]
	if c.Name != "new.example.com" {
		t.Errorf("expected name 'new.example.com', got %q", c.Name)
	}
	if c.Description != "" {
		t.Errorf("expected empty description from [], got %q", c.Description)
	}
	if c.LastUpdate != 0 {
		t.Errorf("expected LastUpdate=0 from [], got %v", c.LastUpdate)
	}
	if c.StatusCode != 0 {
		t.Errorf("expected StatusCode=0 from [], got %v", c.StatusCode)
	}
}

func TestFetchACMECertificates_NotFound(t *testing.T) {
	// Plugin not installed: endpoint returns 404. This must be treated as
	// "feature absent" — empty data, no error — so boxes without os-acme-client
	// do not log errors or increment endpoint counters every scrape.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/acmeclient/certificates/search", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	})

	data, err := client.FetchACMECertificates()
	if err != nil {
		t.Fatalf("expected nil error for 404 (plugin absent), got %v", err)
	}
	if len(data.Certificates) != 0 || data.Total != 0 {
		t.Errorf("expected empty data for 404, got %d certs / total %d", len(data.Certificates), data.Total)
	}
}

func TestFetchACMECertificates_ServerError(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/acmeclient/certificates/search", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})

	_, err := client.FetchACMECertificates()
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
