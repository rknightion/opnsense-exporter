package opnsense

import (
	"net/http"
	"testing"
)

// The fixtures below are REAL CAPTURES, not synthetic shapes.
//
// Until 2026-07-28 the testbed had no HA peer at all, so every configured-path
// fixture in this file was invented from source-reading and only the negative
// branches were ever pinned against something a box had actually sent (#460).
// A second OPNsense was then built on the isolated testbed bridge and both
// endpoints were captured live from each node in turn. Two things the old
// synthetic fixtures got wrong are corrected here, and both would have hidden a
// real regression:
//
//   - the services rows carry far more than name/description/status/id. Every
//     row also has "uid" and (nearly always) "pidfile" plus a nested "configd"
//     object, and some carry "php", "dns_ports", "locked", "mwexec", "nocheck".
//     A fixture with only the consumed keys cannot catch a decoder that chokes
//     on a nested object where it expected a scalar.
//   - "id" is NOT a small integer. Real values are config UUIDs (OpenVPN
//     instances), gateway names and short service-instance names. The old
//     "id": "1" made the id label look numeric, which it never is.
//
// Version strings are the ones the two live nodes actually reported: a
// development-channel build on one and the previous stable release on the
// other. Nothing here is a payload value that identifies a host — no addresses,
// no keys, no hostnames beyond OPNsense's own service names.

// hasyncVersionConfiguredFixture: configured, reachable, and the two nodes are
// on DIFFERENT releases → VersionMatch false. Captured from the devel-channel
// node while its peer ran the previous stable release.
const hasyncVersionConfiguredFixture = `{
  "response": {
    "base":     {"version": "26.7"},
    "firmware": {"version": "26.7.1_1", "_my_version": "27.1.a_40"},
    "kernel":   {"version": "26.7"}
  }
}`

// hasyncVersionMatchFixture: same pair before the release skew was introduced,
// when the peer was still an identical clone → VersionMatch true.
const hasyncVersionMatchFixture = `{
  "response": {
    "base":     {"version": "26.7"},
    "firmware": {"version": "27.1.a_40", "_my_version": "27.1.a_40"},
    "kernel":   {"version": "26.7"}
  }
}`

// hasyncServicesFixture: four rows lifted verbatim from a real 38-row bootgrid,
// chosen to cover every decode branch — status true and false, id absent and
// present, and the id-bearing rows using the two real id flavours (a config
// UUID and a short instance name). "status" is a native JSON bool on the wire;
// "running" is absent, because upstream has never emitted it (see the
// TestFetchHasyncStatus_RunningAliasNeverOnTheWire comment).
const hasyncServicesFixture = `{
  "total": 4, "rowCount": 4, "current": 1,
  "rows": [
    {"description": "Secure Shell", "configd": {"restart": ["openssh restart"], "start": ["openssh start"], "stop": ["openssh stop"]}, "pidfile": "/var/run/sshd.pid", "name": "openssh", "status": true, "uid": "openssh"},
    {"name": "unbound", "dns_ports": ["53"], "description": "Unbound", "php": {"restart": ["unbound_configure_do"], "start": ["unbound_configure_do"], "stop": ["unbound_service_stop"]}, "pidfile": "/var/run/unbound.pid", "status": true, "uid": "unbound"},
    {"description": "OpenVPN server test server", "pidfile": "/var/run/ovpn-instance-6f86d5cd-44f2-47ea-a882-f8773b65c190.pid", "configd": {"start": ["openvpn start 6f86d5cd-44f2-47ea-a882-f8773b65c190"], "restart": ["openvpn restart 6f86d5cd-44f2-47ea-a882-f8773b65c190"], "stop": ["openvpn stop 6f86d5cd-44f2-47ea-a882-f8773b65c190"]}, "id": "6f86d5cd-44f2-47ea-a882-f8773b65c190", "name": "openvpn", "status": true, "uid": "openvpn_6f86d5cd-44f2-47ea-a882-f8773b65c190"},
    {"configd": {"restart": ["kea restart"], "start": ["kea start"], "stop": ["kea stop"]}, "name": "kea-dhcp", "pidfile": "/var/run/kea/kea-ctrl-agent.kea-ctrl-agent.pid", "description": "KEA control agent", "id": "ca", "status": false, "uid": "kea-dhcp_ca"}
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
	if !data.Configured {
		t.Fatal("expected Configured=true for configured fixture")
	}
	if data.RemoteVersion != "26.7.1_1" {
		t.Errorf("RemoteVersion: got %q, want %q", data.RemoteVersion, "26.7.1_1")
	}
	if data.LocalVersion != "27.1.a_40" {
		t.Errorf("LocalVersion: got %q, want %q", data.LocalVersion, "27.1.a_40")
	}
	if data.VersionMatch {
		t.Error("expected VersionMatch=false when the two nodes run different releases")
	}
	if len(data.Services) != 4 {
		t.Fatalf("expected 4 services, got %d", len(data.Services))
	}

	// openssh: no "id", "status": true → ID empty, Running == 1.
	openssh := data.Services[0]
	if openssh.Name != "openssh" {
		t.Errorf("service[0].Name: got %q, want %q", openssh.Name, "openssh")
	}
	if openssh.ID != "" {
		t.Errorf("service[0].ID: got %q, want empty (single-instance rows carry no id)", openssh.ID)
	}
	if openssh.Running != 1 {
		t.Errorf("openssh.Running: got %v, want 1 (from native JSON bool true)", openssh.Running)
	}

	// openvpn: id is a config UUID, not the small integer the old synthetic
	// fixture implied.
	openvpn := data.Services[2]
	if openvpn.Name != "openvpn" {
		t.Errorf("service[2].Name: got %q, want %q", openvpn.Name, "openvpn")
	}
	if openvpn.ID != "6f86d5cd-44f2-47ea-a882-f8773b65c190" {
		t.Errorf("openvpn.ID: got %q, want the OpenVPN instance UUID", openvpn.ID)
	}
	if openvpn.Running != 1 {
		t.Errorf("openvpn.Running: got %v, want 1", openvpn.Running)
	}

	// kea-dhcp: "status": false → Running == 0, id is a short instance name.
	kea := data.Services[3]
	if kea.Name != "kea-dhcp" {
		t.Errorf("service[3].Name: got %q, want %q", kea.Name, "kea-dhcp")
	}
	if kea.ID != "ca" {
		t.Errorf("kea-dhcp.ID: got %q, want %q", kea.ID, "ca")
	}
	if kea.Running != 0 {
		t.Errorf("kea-dhcp.Running: got %v, want 0 (from native JSON bool false)", kea.Running)
	}
}

// TestFetchHasyncStatus_RunningAliasNeverOnTheWire pins what the live capture
// settled: hasyncServiceRow.Running is a purely DEFENSIVE alias. Upstream's
// list_services_xmlrpc sets "status" and has never set "running" on any
// release, confirmed against a real 38-row peer service list on 2026-07-28
// (#460) — the live schema canary reports rows[].running as a missing path for
// exactly that reason, and that is not drift.
//
// So the alias must stay inert. A row with "status": false and no "running" key
// reports stopped; if the effective-running expression is ever "simplified" to
// default the alias to true, or to prefer it over Status, every stopped service
// on every real box silently flips to 1.
func TestFetchHasyncStatus_RunningAliasNeverOnTheWire(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	hasyncRegisterHandlers(t, mux, hasyncVersionMatchFixture, hasyncServicesFixture)

	data, err := client.FetchHasyncStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, svc := range data.Services {
		if svc.Name != "kea-dhcp" {
			continue
		}
		found = true
		if svc.Running != 0 {
			t.Errorf("a row with status=false and no running key must report 0, got %v", svc.Running)
		}
	}
	if !found {
		t.Fatal("fixture no longer carries the stopped kea-dhcp row this test depends on")
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

// TestFetchHasyncStatus_ConfiguredUnreachable validates the error-envelope
// path for a configured peer that cannot be reached:
// {"status":"error","message":"..."} → Configured=true, Reachable=false.
//
// LIVE-CAPTURED 2026-07-28 (#460) from a box with hasync CONFIGURED and the
// peer's bridge link dropped — the body below is what the endpoint actually
// returned, timeout wording and all. This is the only branch of
// ha_xmlrpc_exec.php's "version" action that emits "status"/"message" at all:
// the success path echoes ['response' => $payload] with neither key, which is
// why the hasyncVersion missingOK exemption stays even now that a real peer
// exists.
func TestFetchHasyncStatus_ConfiguredUnreachable(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"error","message":"fetch error. remote host down? (Connection timed out after 60009 milliseconds)"}`))
	})
	defer server.Close()

	data, err := client.FetchHasyncStatus()
	if err != nil {
		t.Fatalf("expected nil error for configured but unreachable peer, got: %v", err)
	}
	if !data.Configured {
		t.Error("expected Configured=true for error envelope")
	}
	if data.Reachable {
		t.Error("expected Reachable=false for error envelope")
	}
}

// TestFetchHasyncStatus_ResponseString pins a fourth live "response" shape that
// no fixture covered before #460: a bare JSON STRING.
//
// When hasync is configured and the peer is REACHABLE but the XML-RPC
// credentials are rejected, the client does not throw, so ha_xmlrpc_exec.php
// takes its success path and echoes the fault text straight through as
// ['response' => 'Authentication failed']. Captured live on 2026-07-28 from a
// pair whose sync account existed on only one node.
//
// "response" is therefore polymorphic across four observed shapes — object
// (configured + reachable), bare false (single-node), null, and string (auth
// failure) — which is exactly why the endpoint is deliberately left as an
// unwrapped envelope rather than given an envelopeDescent. A refactor that
// decodes "response" into any/map[string]any would take a different branch here
// or return a non-nil error; both would report a live, answering peer as a
// scrape failure instead of an unreachable one.
func TestFetchHasyncStatus_ResponseString(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response":"Authentication failed"}`))
	})
	defer server.Close()

	data, err := client.FetchHasyncStatus()
	if err != nil {
		t.Fatalf("expected nil error for a string response, got: %v", err)
	}
	if data.Reachable {
		t.Error("expected Reachable=false when response is a bare string")
	}
	if !data.Configured {
		t.Error("expected Configured=true when response contains a peer error string")
	}
	if data.RemoteVersion != "" || data.LocalVersion != "" {
		t.Errorf("expected empty versions, got remote=%q local=%q", data.RemoteVersion, data.LocalVersion)
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
	if data.Configured {
		t.Error("expected Configured=false for null body")
	}
}

// TestFetchHasyncStatus_ResponseFalse pins the single-node / HA-unconfigured
// shape a real box returns (live-verified on OPNsense 26.1.8): {"response": false}.
// This is the highest-frequency real input for this endpoint and was previously
// only correct by accident of implementation (#156). A refactor that decodes
// "response" into any/map[string]any would successfully decode the bare false and
// take a different path or return a non-nil error; this test guards against that.
func TestFetchHasyncStatus_ResponseFalse(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response": false}`))
	})
	defer server.Close()

	data, err := client.FetchHasyncStatus()
	if err != nil {
		t.Fatalf("expected nil error for single-node {\"response\": false}, got: %v", err)
	}
	if data.Reachable {
		t.Error("expected Reachable=false for single-node {\"response\": false}")
	}
	if data.Configured {
		t.Error("expected Configured=false for single-node {\"response\": false}")
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
