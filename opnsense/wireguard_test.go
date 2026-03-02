package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchWireguardConfig_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"rows": [
				{
					"if": "wg0",
					"type": "interface",
					"status": "up",
					"name": "WG Tunnel 1",
					"ifname": "wg0",
					"latest-handshake": 0,
					"transfer-rx": 0,
					"transfer-tx": 0,
					"peer-status": ""
				},
				{
					"if": "wg0",
					"type": "peer",
					"status": "",
					"name": "Peer A",
					"ifname": "wg0",
					"latest-handshake": 1704067200.0,
					"transfer-rx": 123456789,
					"transfer-tx": 987654321,
					"peer-status": "online"
				},
				{
					"if": "wg0",
					"type": "peer",
					"status": "",
					"name": "Peer B",
					"ifname": "wg0",
					"latest-handshake": 0,
					"transfer-rx": 0,
					"transfer-tx": 0,
					"peer-status": "offline"
				},
				{
					"if": "wg1",
					"type": "interface",
					"status": "down",
					"name": "WG Tunnel 2",
					"ifname": "wg1",
					"latest-handshake": 0,
					"transfer-rx": 0,
					"transfer-tx": 0,
					"peer-status": ""
				}
			],
			"rowCount": 4,
			"total": 4,
			"current": 1
		}`))
	})
	defer server.Close()

	data, err := client.FetchWireguardConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have 2 interfaces and 2 peers
	if len(data.Interfaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(data.Interfaces))
	}
	if len(data.Peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(data.Peers))
	}

	// Check first interface
	iface1 := data.Interfaces[0]
	if iface1.Name != "WG Tunnel 1" {
		t.Errorf("expected name 'WG Tunnel 1', got %q", iface1.Name)
	}
	if iface1.Device != "wg0" {
		t.Errorf("expected device 'wg0', got %q", iface1.Device)
	}
	if iface1.DeviceName != "wg0" {
		t.Errorf("expected device name 'wg0', got %q", iface1.DeviceName)
	}
	if iface1.Status != WGInterfaceStatusUp {
		t.Errorf("expected WGInterfaceStatusUp, got %d", iface1.Status)
	}

	// Check second interface (down)
	iface2 := data.Interfaces[1]
	if iface2.Status != WGInterfaceStatusDown {
		t.Errorf("expected WGInterfaceStatusDown, got %d", iface2.Status)
	}

	// Check first peer (online)
	peer1 := data.Peers[0]
	if peer1.Name != "Peer A" {
		t.Errorf("expected name 'Peer A', got %q", peer1.Name)
	}
	if peer1.Status != WGPeerStatusUp {
		t.Errorf("expected WGPeerStatusUp, got %d", peer1.Status)
	}
	if peer1.LatestHandshake != 1704067200.0 {
		t.Errorf("expected LatestHandshake=1704067200.0, got %f", peer1.LatestHandshake)
	}
	if peer1.TransferRx != 123456789 {
		t.Errorf("expected TransferRx=123456789, got %f", peer1.TransferRx)
	}
	if peer1.TransferTx != 987654321 {
		t.Errorf("expected TransferTx=987654321, got %f", peer1.TransferTx)
	}

	// Check second peer (offline)
	peer2 := data.Peers[1]
	if peer2.Status != WGPeerStatusDown {
		t.Errorf("expected WGPeerStatusDown, got %d", peer2.Status)
	}
}

func TestFetchWireguardConfig_UnknownStatuses(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"if": "wg0",
					"type": "interface",
					"status": "weird",
					"name": "Unknown IF",
					"ifname": "wg0",
					"latest-handshake": 0,
					"transfer-rx": 0,
					"transfer-tx": 0,
					"peer-status": ""
				},
				{
					"if": "wg0",
					"type": "peer",
					"status": "",
					"name": "Unknown Peer",
					"ifname": "wg0",
					"latest-handshake": 0,
					"transfer-rx": 0,
					"transfer-tx": 0,
					"peer-status": "unknown_value"
				}
			],
			"rowCount": 2,
			"total": 2,
			"current": 1
		}`))
	})
	defer server.Close()

	data, err := client.FetchWireguardConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.Interfaces[0].Status != WGInterfaceStatusUnknown {
		t.Errorf("expected WGInterfaceStatusUnknown, got %d", data.Interfaces[0].Status)
	}
	if data.Peers[0].Status != WGPeerStatusUnknown {
		t.Errorf("expected WGPeerStatusUnknown, got %d", data.Peers[0].Status)
	}
}

func TestFetchWireguardConfig_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchWireguardConfig()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
