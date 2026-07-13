package opnsense

import (
	"net/http"
	"testing"
)

// netbirdDaemonDownFixture is the verbatim dev-box capture (2026-07-13,
// os-netbird installed, daemon down): a bare JSON array, not an object.
const netbirdDaemonDownFixture = `[]`

// netbirdUnenrolledFixture is the verbatim dev-box capture (2026-07-13,
// os-netbird installed, daemon up, never enrolled).
const netbirdUnenrolledFixture = `{"peers":{"total":0,"connected":0,"details":null},"cliVersion":"0.72.2","daemonVersion":"0.72.2","daemonStatus":"NeedsLogin","management":{"url":"https://api.netbird.io:443","connected":false,"error":""},"signal":{"url":"","connected":false,"error":""},"relays":{"total":0,"available":0,"details":null},"netbirdIp":"","publicKey":"","usesKernelInterface":false,"wireguardPort":0,"fqdn":"","quantumResistance":false,"quantumResistancePermissive":false,"networks":null,"forwardingRules":0,"dnsServers":[],"events":[],"lazyConnectionEnabled":false,"profileName":"default","sshServer":{"enabled":false,"sessions":[]}}`

// netbirdEnrolledFixture is SOURCE-DERIVED (never observed live — no netbird
// enrollment was performed, see #211) from netbirdio/netbird's
// client/status/status.go OutputOverview/PeerStateDetailOutput structs (the
// exact Go types `netbird status --json` marshals). Two peers: one connected
// via a direct P2P path with a handshake/latency/transfer counters, one idle
// with no session (connectionType "-", zero transfer, zero-value handshake
// time — the shape ConvertToStatusOutputOverview/mapPeers produces for a
// disconnected peer).
const netbirdEnrolledFixture = `{
	"peers": {
		"total": 2,
		"connected": 1,
		"details": [
			{
				"fqdn": "peer-a.netbird.example.internal",
				"netbirdIp": "100.90.0.2",
				"publicKey": "pubkey-a=",
				"status": "Connected",
				"lastStatusUpdate": "2026-07-13T12:00:00Z",
				"connectionType": "P2P",
				"relayAddress": "",
				"lastWireguardHandshake": "2026-07-13T11:59:30Z",
				"transferReceived": 123456,
				"transferSent": 654321,
				"latency": 12500000,
				"quantumResistance": false,
				"networks": []
			},
			{
				"fqdn": "peer-b.netbird.example.internal",
				"netbirdIp": "100.90.0.3",
				"publicKey": "pubkey-b=",
				"status": "Idle",
				"lastStatusUpdate": "2026-07-13T10:00:00Z",
				"connectionType": "-",
				"relayAddress": "",
				"lastWireguardHandshake": "0001-01-01T00:00:00Z",
				"transferReceived": 0,
				"transferSent": 0,
				"latency": 0,
				"quantumResistance": false,
				"networks": []
			}
		]
	},
	"cliVersion": "0.72.2",
	"daemonVersion": "0.72.2",
	"daemonStatus": "Connected",
	"management": {"url": "https://api.netbird.io:443", "connected": true, "error": ""},
	"signal": {"url": "https://signal.netbird.example:443", "connected": true, "error": ""},
	"relays": {"total": 2, "available": 2, "details": []},
	"netbirdIp": "100.90.0.1",
	"publicKey": "pubkey-self=",
	"usesKernelInterface": true,
	"wireguardPort": 51820,
	"fqdn": "opnsense.netbird.example.internal",
	"quantumResistance": false,
	"quantumResistancePermissive": false,
	"networks": [],
	"forwardingRules": 0,
	"dnsServers": [],
	"events": [],
	"lazyConnectionEnabled": false,
	"profileName": "default",
	"sshServer": {"enabled": false, "sessions": []}
}`

func TestFetchNetbirdStatus_DaemonDown(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/netbird/status/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(netbirdDaemonDownFixture))
	})

	data, err := client.FetchNetbirdStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true (plugin installed, endpoint reachable)")
	}
	if data.DaemonUp {
		t.Error("expected DaemonUp=false for the bare-[] daemon-down payload")
	}
	if data.ManagementConnected || data.SignalConnected {
		t.Errorf("expected no connectivity when daemon is down: %+v", data)
	}
	if data.PeersTotal != 0 || data.PeersConnected != 0 || len(data.Peers) != 0 {
		t.Errorf("expected zero peer data when daemon is down: %+v", data)
	}
	if data.RelaysTotal != 0 || data.RelaysAvailable != 0 {
		t.Errorf("expected zero relay data when daemon is down: %+v", data)
	}
	if data.CliVersion != "" || data.DaemonVersion != "" {
		t.Errorf("expected no version info when daemon is down: %+v", data)
	}
}

func TestFetchNetbirdStatus_Unenrolled(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/netbird/status/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(netbirdUnenrolledFixture))
	})

	data, err := client.FetchNetbirdStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present || !data.DaemonUp {
		t.Fatalf("expected Present=true, DaemonUp=true: %+v", data)
	}
	if data.ManagementConnected || data.SignalConnected {
		t.Errorf("expected no connectivity when unenrolled: %+v", data)
	}
	if data.PeersTotal != 0 || data.PeersConnected != 0 || len(data.Peers) != 0 {
		t.Errorf("expected zero peers when unenrolled: %+v", data)
	}
	if data.CliVersion != "0.72.2" || data.DaemonVersion != "0.72.2" {
		t.Errorf("expected version info even when unenrolled: %+v", data)
	}
	if data.DaemonStatus != "NeedsLogin" {
		t.Errorf("expected daemonStatus NeedsLogin, got %q", data.DaemonStatus)
	}
}

func TestFetchNetbirdStatus_Enrolled(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/netbird/status/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(netbirdEnrolledFixture))
	})

	data, err := client.FetchNetbirdStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present || !data.DaemonUp {
		t.Fatalf("expected Present=true, DaemonUp=true: %+v", data)
	}
	if !data.ManagementConnected || !data.SignalConnected {
		t.Errorf("expected management/signal connected: %+v", data)
	}
	if data.RelaysTotal != 2 || data.RelaysAvailable != 2 {
		t.Errorf("expected 2/2 relays, got %d/%d", data.RelaysTotal, data.RelaysAvailable)
	}
	if data.PeersTotal != 2 || data.PeersConnected != 1 {
		t.Errorf("expected 2 peers / 1 connected, got %d/%d", data.PeersTotal, data.PeersConnected)
	}
	if len(data.Peers) != 2 {
		t.Fatalf("expected 2 decoded peers, got %d", len(data.Peers))
	}

	byFQDN := map[string]NetbirdPeer{}
	for _, p := range data.Peers {
		byFQDN[p.FQDN] = p
	}

	a, ok := byFQDN["peer-a.netbird.example.internal"]
	if !ok {
		t.Fatalf("peer-a missing; got %v", byFQDN)
	}
	if !a.Connected || !a.Direct {
		t.Errorf("expected peer-a connected+direct: %+v", a)
	}
	if a.ReceivedBytes != 123456 || a.TransmittedBytes != 654321 {
		t.Errorf("unexpected peer-a transfer counters: %+v", a)
	}
	if !a.HasHandshake || a.LastHandshakeSeconds != 1783943970 { // 2026-07-13T11:59:30Z
		t.Errorf("unexpected peer-a handshake: %+v", a)
	}
	if !a.HasLatency || a.LatencySeconds != 0.0125 { // 12_500_000ns
		t.Errorf("unexpected peer-a latency: %+v", a)
	}

	b, ok := byFQDN["peer-b.netbird.example.internal"]
	if !ok {
		t.Fatalf("peer-b missing; got %v", byFQDN)
	}
	if b.Connected {
		t.Errorf("expected peer-b not connected: %+v", b)
	}
	if b.Direct || b.HasHandshake || b.HasLatency {
		t.Errorf("expected peer-b to omit connected-only fields: %+v", b)
	}
	if b.ReceivedBytes != 0 || b.TransmittedBytes != 0 {
		t.Errorf("expected peer-b zero transfer: %+v", b)
	}
}

func TestFetchNetbirdStatus_PluginAbsent(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchNetbirdStatus()
	if err != nil {
		t.Fatalf("expected nil error on 404, got %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on 404")
	}
	if data.DaemonUp {
		t.Error("expected DaemonUp=false on 404")
	}
}
