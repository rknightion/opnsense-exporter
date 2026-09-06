package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

// netbirdUnenrolledFixture mirrors the live dev-box capture (2026-07-13,
// os-netbird installed, daemon up, never enrolled): versions populated,
// nothing connected, no peers.
const netbirdUnenrolledFixture = `{"peers":{"total":0,"connected":0,"details":null},"cliVersion":"0.72.2","daemonVersion":"0.72.2","daemonStatus":"NeedsLogin","management":{"url":"https://api.netbird.io:443","connected":false,"error":""},"signal":{"url":"","connected":false,"error":""},"relays":{"total":0,"available":0,"details":null},"netbirdIp":"","publicKey":"","usesKernelInterface":false,"wireguardPort":0,"fqdn":"","quantumResistance":false,"quantumResistancePermissive":false,"networks":null,"forwardingRules":0,"dnsServers":[],"events":[],"lazyConnectionEnabled":false,"profileName":"default","sshServer":{"enabled":false,"sessions":[]}}`

// netbirdEnrolledFixture is SOURCE-DERIVED from netbirdio/netbird's
// client/status/status.go (never observed live — no enrollment; see #211):
// one connected P2P peer with handshake/latency/transfer, one idle peer.
const netbirdEnrolledFixture = `{
	"peers": {
		"total": 2,
		"connected": 1,
		"details": [
			{
				"fqdn": "peer-a.netbird.example.internal",
				"status": "Connected",
				"connectionType": "P2P",
				"lastWireguardHandshake": "2026-07-13T11:59:30Z",
				"transferReceived": 123456,
				"transferSent": 654321,
				"latency": 12500000
			},
			{
				"fqdn": "peer-b.netbird.example.internal",
				"status": "Idle",
				"connectionType": "-",
				"lastWireguardHandshake": "0001-01-01T00:00:00Z",
				"transferReceived": 0,
				"transferSent": 0,
				"latency": 0
			}
		]
	},
	"cliVersion": "0.72.2",
	"daemonVersion": "0.72.2",
	"daemonStatus": "Connected",
	"management": {"url": "https://api.netbird.io:443", "connected": true, "error": ""},
	"signal": {"url": "https://signal.netbird.example:443", "connected": true, "error": ""},
	"relays": {"total": 2, "available": 2, "details": []}
}`

func netbirdTestServer(t *testing.T, statusBody string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/netbird/status/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(statusBody))
	})
	mux.HandleFunc("/api/netbird/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	return httptest.NewServer(mux)
}

func TestNetbirdCollector_Update_Default(t *testing.T) {
	server := netbirdTestServer(t, netbirdUnenrolledFixture)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &netbirdCollector{subsystem: NetbirdSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	// management_connected + signal_connected + relays + relays_available +
	// peers + peers_connected + service_running + info + daemon_state = 9
	if len(metrics) != 9 {
		t.Fatalf("expected 9 metrics without details, got %d", len(metrics))
	}
	var sawDaemonState bool
	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "netbird_info") {
			labels := getMetricLabels(m)
			if labels["cli_version"] != "0.72.2" || labels["daemon_version"] != "0.72.2" {
				t.Errorf("bad info labels: %v", labels)
			}
		}
		if strings.Contains(desc, "management_connected") && getMetricValue(m) != 0 {
			t.Errorf("expected management_connected=0 when unenrolled, got %v", getMetricValue(m))
		}
		if strings.Contains(desc, "daemon_state") {
			sawDaemonState = true
			labels := getMetricLabels(m)
			if labels["state"] != "NeedsLogin" {
				t.Errorf("expected daemon_state=NeedsLogin, got %v", labels)
			}
			if getMetricValue(m) != 1 {
				t.Errorf("expected daemon_state value 1, got %v", getMetricValue(m))
			}
		}
	}
	if !sawDaemonState {
		t.Error("missing netbird_daemon_state series for the NeedsLogin fixture")
	}
}

func TestNetbirdCollector_Update_Details(t *testing.T) {
	server := netbirdTestServer(t, netbirdEnrolledFixture)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &netbirdCollector{subsystem: NetbirdSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)
	// 9 default (management/signal connected true, relays 2/2, peers 2/1,
	// service_running, info, daemon_state) + per-peer:
	//   peer-a (connected): connected/direct/rx/tx/last_handshake/latency (6)
	//   peer-b (idle): connected/rx/tx (3 — direct/handshake/latency omitted)
	// = 9 + 9 = 18
	if len(metrics) != 18 {
		t.Fatalf("expected 18 metrics with details, got %d", len(metrics))
	}

	var sawRxForA, sawDirectForB, sawLatencyForA bool
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		if strings.Contains(desc, "peer_received_bytes_total") && labels["fqdn"] == "peer-a.netbird.example.internal" {
			sawRxForA = true
			if getMetricValue(m) != 123456 {
				t.Errorf("expected rx 123456, got %v", getMetricValue(m))
			}
		}
		if strings.Contains(desc, "peer_latency_seconds") && labels["fqdn"] == "peer-a.netbird.example.internal" {
			sawLatencyForA = true
			if getMetricValue(m) != 0.0125 {
				t.Errorf("expected latency 0.0125s, got %v", getMetricValue(m))
			}
		}
		if strings.Contains(desc, "peer_connected") && labels["fqdn"] == "peer-b.netbird.example.internal" &&
			getMetricValue(m) != 0 {
			t.Errorf("expected peer-b connected=0, got %v", getMetricValue(m))
		}
		if strings.Contains(desc, "peer_direct") && labels["fqdn"] == "peer-b.netbird.example.internal" {
			sawDirectForB = true
		}
	}
	if !sawRxForA {
		t.Error("missing peer_received_bytes_total for peer-a")
	}
	if !sawLatencyForA {
		t.Error("missing peer_latency_seconds for peer-a")
	}
	if sawDirectForB {
		t.Error("peer_direct must not be emitted for a peer with no active connection")
	}
}

func TestNetbirdCollector_DaemonDown(t *testing.T) {
	server := netbirdTestServer(t, `[]`)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &netbirdCollector{subsystem: NetbirdSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	// 7 aggregates (no info: no version data when the daemon is down) + service_running = 7
	// No daemon_state either: the bare-[] fallback carries no daemonStatus.
	if len(metrics) != 7 {
		t.Fatalf("expected 7 metrics when daemon is down (no info metric), got %d", len(metrics))
	}
	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "netbird_info") {
			t.Error("info metric must not be emitted when the daemon is down (no version data)")
		}
		if strings.Contains(desc, "daemon_state") {
			t.Error("daemon_state metric must not be emitted when the daemon is down (no daemonStatus)")
		}
		if !strings.Contains(desc, "service_running") && getMetricValue(m) != 0 {
			t.Errorf("expected all aggregates at 0 when daemon is down: %s = %v", desc, getMetricValue(m))
		}
	}
}

// TestNetbirdCollector_DaemonStateUnknown covers #455's fallback bucket at the
// collector layer: a daemonStatus value outside netbird's closed vocabulary
// must still emit exactly one daemon_state series, canonicalized to
// "unknown" rather than the raw string.
func TestNetbirdCollector_DaemonStateUnknown(t *testing.T) {
	body := `{"peers":{"total":0,"connected":0,"details":null},"cliVersion":"0.99.0","daemonVersion":"0.99.0","daemonStatus":"SomeFutureState","management":{"connected":false},"signal":{"connected":false},"relays":{"total":0,"available":0}}`
	server := netbirdTestServer(t, body)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &netbirdCollector{subsystem: NetbirdSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	var sawDaemonState bool
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "daemon_state") {
			sawDaemonState = true
			labels := getMetricLabels(m)
			if labels["state"] != "unknown" {
				t.Errorf("expected daemon_state=unknown for an unrecognized value, got %v", labels)
			}
		}
	}
	if !sawDaemonState {
		t.Error("missing netbird_daemon_state series for an unrecognized daemonStatus")
	}
}

func TestNetbirdCollector_PluginAbsent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &netbirdCollector{subsystem: NetbirdSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when plugin absent, got %d", len(metrics))
	}
}
