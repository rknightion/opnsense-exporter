package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
)

func TestWireguardCollector_Update(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/wireguard/service/show", func(w http.ResponseWriter, r *http.Request) {
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
	})

	mux.HandleFunc("/api/wireguard/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "running"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	// Fixed "now" so handshake age is deterministic.
	// Peer A latest-handshake = 1700000000; fixedNow = 1700001000 → age = 1000s.
	fixedNow := time.Unix(1700001000, 0)

	c := &WireguardCollector{subsystem: WireguardSubsystem, now: func() time.Time { return fixedNow }}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 1 interface status
	// + Peer A: status, last_handshake, transfer_rx, transfer_tx, handshake_age = 5
	// + Peer B: status, last_handshake, transfer_rx, transfer_tx = 4 (no age, handshake==0)
	// + 1 serviceRunning
	// = 1 + 5 + 4 + 1 = 11
	expectedCount := 11
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Verify peer_last_handshake_seconds is a GAUGE (not a counter).
	// Verify peer_handshake_age_seconds value and absence for zero-handshake peer.
	var foundHandshakeAge bool
	var handshakeAgeValue float64
	var peerBHandshakeAge bool
	var lastHandshakeIsGauge bool

	for _, m := range metrics {
		d := &dto.Metric{}
		if err := m.Write(d); err != nil {
			t.Fatalf("failed to write metric: %v", err)
		}

		labels := getMetricLabels(m)

		// Check peer_last_handshake_seconds is a gauge (Gauge field populated, Counter nil).
		desc := m.Desc().String()
		if strings.Contains(desc, "peer_last_handshake_seconds") {
			if d.Gauge != nil && d.Counter == nil {
				lastHandshakeIsGauge = true
			}
		}

		// Check peer_handshake_age_seconds.
		if strings.Contains(desc, "peer_handshake_age_seconds") {
			if labels["peer_name"] == "Peer A" {
				foundHandshakeAge = true
				handshakeAgeValue = d.Gauge.GetValue()
			}
			if labels["peer_name"] == "Peer B" {
				peerBHandshakeAge = true
			}
		}
	}

	if !lastHandshakeIsGauge {
		t.Error("expected peer_last_handshake_seconds to be a gauge, but it was not")
	}

	if !foundHandshakeAge {
		t.Error("expected peer_handshake_age_seconds to be emitted for Peer A (handshake > 0)")
	} else {
		expectedAge := float64(fixedNow.Unix() - 1700000000) // = 1000
		if handshakeAgeValue != expectedAge {
			t.Errorf("expected peer_handshake_age_seconds = %v, got %v", expectedAge, handshakeAgeValue)
		}
	}

	if peerBHandshakeAge {
		t.Error("expected peer_handshake_age_seconds NOT to be emitted for Peer B (handshake == 0)")
	}
}

func TestWireguardCollector_Update_Empty(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/wireguard/service/show", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [],
			"rowCount": 0,
			"total": 0,
			"current": 1
		}`))
	})

	mux.HandleFunc("/api/wireguard/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "running"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &WireguardCollector{subsystem: WireguardSubsystem, now: time.Now}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 1 serviceRunning (no interfaces or peers)
	if len(metrics) != 1 {
		t.Errorf("expected 1 metrics, got %d", len(metrics))
	}
}

// TestWireguardCollector_DuplicatePeerName guards #85: two peers on the same
// device given the same free-form display name (OPNsense does not enforce
// per-interface peer-name uniqueness) collide on the peer label tuple and would
// fail the whole scrape; the collector must guarantee unique label tuples.
func TestWireguardCollector_DuplicatePeerName(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/wireguard/service/show", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{"if":"wg0","type":"peer","status":"","name":"Laptop","ifname":"wg0","latest-handshake":1700000000,"transfer-rx":10,"transfer-tx":20,"peer-status":"online"},
				{"if":"wg0","type":"peer","status":"","name":"Laptop","ifname":"wg0","latest-handshake":1700000001,"transfer-rx":30,"transfer-tx":40,"peer-status":"online"}
			],
			"rowCount": 2,
			"total": 2,
			"current": 1
		}`))
	})

	mux.HandleFunc("/api/wireguard/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "running"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &WireguardCollector{subsystem: WireguardSubsystem, now: time.Now}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)
}

func TestWireguardCollector_Name(t *testing.T) {
	c := &WireguardCollector{subsystem: WireguardSubsystem}
	if c.Name() != WireguardSubsystem {
		t.Errorf("expected %s, got %s", WireguardSubsystem, c.Name())
	}
}
