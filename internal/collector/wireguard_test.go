package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestWireguardCollector_Update(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"if": "wg0",
					"type": "interface",
					"status": "up",
					"name": "WireGuard Tunnel",
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
					"latest-handshake": 1700000000,
					"transfer-rx": 1048576,
					"transfer-tx": 2097152,
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
				}
			],
			"rowCount": 3,
			"total": 3,
			"current": 1
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &WireguardCollector{subsystem: WireguardSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 1 interface status + 2 peers * 4 metrics each (status, latestHandshake, transferRx, transferTx) = 1 + 8 = 9
	expectedCount := 9
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestWireguardCollector_Update_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [],
			"rowCount": 0,
			"total": 0,
			"current": 1
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &WireguardCollector{subsystem: WireguardSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics, got %d", len(metrics))
	}
}

func TestWireguardCollector_Name(t *testing.T) {
	c := &WireguardCollector{subsystem: WireguardSubsystem}
	if c.Name() != WireguardSubsystem {
		t.Errorf("expected %s, got %s", WireguardSubsystem, c.Name())
	}
}
