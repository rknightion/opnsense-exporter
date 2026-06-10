package opnsense

import (
	"net/http"
	"testing"
)

// hasyncVersionConfiguredFixture: configured & reachable response.
const hasyncVersionConfiguredFixture = `{
  "response": {
    "firmware": {"version": "26.1.3", "_my_version": "26.1.2"},
    "base":     {"version": "26.1"},
    "kernel":   {"version": "26.1"}
  }
}`

// hasyncVersionMatchFixture: both versions identical → VersionMatch true.
const hasyncVersionMatchFixture = `{
  "response": {
    "firmware": {"version": "26.1.3", "_my_version": "26.1.3"},
    "base":     {"version": "26.1"},
    "kernel":   {"version": "26.1"}
  }
}`

// hasyncServicesFixture: 2 service rows — status as native JSON bool.
const hasyncServicesFixture = `{
  "total": 2, "rowCount": 2, "current": 1,
  "rows": [
    {"name": "openssh",  "description": "Secure Shell Daemon", "status": true,  "uid": "openssh"},
    {"name": "openvpn",  "description": "OpenVPN server",      "status": false, "id": "1", "uid": "openvpn_1"}
  ]
}`

func hasyncRegisterHandlers(t *testing.T, mux *http.ServeMux, versionBody, servicesBody string) {
	t.Helper()
	mux.HandleFunc("/api/core/hasync_status/version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(versionBody))
	})
	mux.HandleFunc("/api/core/hasync_status/services", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(servicesBody))
	})
}

// TestFetchHasyncStatus_Configured validates the happy path:
// VersionMatch when versions differ, 2 services, flexBool from native JSON bool.
func TestFetchHasyncStatus_Configured(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	hasyncRegisterHandlers(t, mux, hasyncVersionConfiguredFixture, hasyncServicesFixture)

	data, err := client.FetchHasyncStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Reachable {
		t.Fatal("expected Reachable=true for configured fixture")
	}
	if data.RemoteVersion != "26.1.3" {
		t.Errorf("RemoteVersion: got %q, want %q", data.RemoteVersion, "26.1.3")
	}
	if data.LocalVersion != "26.1.2" {
		t.Errorf("LocalVersion: got %q, want %q", data.LocalVersion, "26.1.2")
	}
	if data.VersionMatch {
		t.Error("expected VersionMatch=false when versions differ")
	}
	if len(data.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(data.Services))
	}

	// openssh: "status": true → Running == 1
	openssh := data.Services[0]
	if openssh.Name != "openssh" {
		t.Errorf("service[0].Name: got %q, want %q", openssh.Name, "openssh")
	}
	if openssh.Running != 1 {
		t.Errorf("openssh.Running: got %v, want 1 (from native JSON bool true)", openssh.Running)
	}

	// openvpn: "status": false → Running == 0
	openvpn := data.Services[1]
	if openvpn.Name != "openvpn" {
		t.Errorf("service[1].Name: got %q, want %q", openvpn.Name, "openvpn")
	}
	if openvpn.ID != "1" {
		t.Errorf("openvpn.ID: got %q, want %q", openvpn.ID, "1")
	}
	if openvpn.Running != 0 {
		t.Errorf("openvpn.Running: got %v, want 0 (from native JSON bool false)", openvpn.Running)
	}
}

// TestFetchHasyncStatus_VersionMatch validates that VersionMatch is true
// when firmware.version == firmware._my_version.
func TestFetchHasyncStatus_VersionMatch(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	hasyncRegisterHandlers(t, mux, hasyncVersionMatchFixture, hasyncServicesFixture)

	data, err := client.FetchHasyncStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.VersionMatch {
		t.Errorf("expected VersionMatch=true when versions match, got false (remote=%q local=%q)",
			data.RemoteVersion, data.LocalVersion)
	}
}

// TestFetchHasyncStatus_Unconfigured validates the error-envelope path:
// {"status":"error","message":"..."} → Reachable=false, nil error.
func TestFetchHasyncStatus_Unconfigured(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"error","message":"unable to connect to peer"}`))
	})
	defer server.Close()

	data, err := client.FetchHasyncStatus()
	if err != nil {
		t.Fatalf("expected nil error for unconfigured/unreachable, got: %v", err)
	}
	if data.Reachable {
		t.Error("expected Reachable=false for error envelope")
	}
}

// TestFetchHasyncStatus_NullBody validates that a literal JSON null response
// is treated as unconfigured/unreachable (Reachable=false, nil error).
func TestFetchHasyncStatus_NullBody(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`null`))
	})
	defer server.Close()

	data, err := client.FetchHasyncStatus()
	if err != nil {
		t.Fatalf("expected nil error for null body, got: %v", err)
	}
	if data.Reachable {
		t.Error("expected Reachable=false for null body")
	}
}

// TestFetchHasyncStatus_FlexBoolNativeBool is a targeted test proving flexBool
// correctly decodes a native JSON boolean (not a string "true"/"false").
func TestFetchHasyncStatus_FlexBoolNativeBool(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	// Minimal version fixture with one service using a native bool status.
	mux.HandleFunc("/api/core/hasync_status/version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(hasyncVersionMatchFixture))
	})
	mux.HandleFunc("/api/core/hasync_status/services", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":1,"rowCount":1,"current":1,"rows":[
			{"name":"sshd","description":"SSH","status":true,"uid":"sshd"}
		]}`))
	})

	data, err := client.FetchHasyncStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(data.Services))
	}
	if data.Services[0].Running != 1 {
		t.Errorf("expected Running==1 for native JSON bool true, got %v", data.Services[0].Running)
	}
}

// TestFetchHasyncStatus_UnconfiguredServices validates the unconfigured services
// shape (empty rows bootgrid) — produces empty Services slice, still Reachable.
func TestFetchHasyncStatus_UnconfiguredServices(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	hasyncRegisterHandlers(t, mux, hasyncVersionMatchFixture, `{"total":0,"rowCount":0,"current":1,"rows":[]}`)

	data, err := client.FetchHasyncStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Reachable {
		t.Fatal("expected Reachable=true")
	}
	if len(data.Services) != 0 {
		t.Errorf("expected 0 services for empty bootgrid, got %d", len(data.Services))
	}
}
