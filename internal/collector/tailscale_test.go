package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

func tailscaleTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tailscale/status/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"Version": "1.96.4",
			"BackendState": "Running",
			"Health": ["update available", "some peers are advertising routes but --accept-routes is false"],
			"Self": {"HostName":"opnsense","DNSName":"opnsense.example-tailnet.ts.net.","Relay":"lhr","Online":true,"RxBytes":0,"TxBytes":0,"CurAddr":"","LastHandshake":"0001-01-01T00:00:00Z"},
			"Peer": {
				"nodekey:aaa": {"HostName":"server-a","DNSName":"server-a.example-tailnet.ts.net.","OS":"linux","Online":true,"RxBytes":123456,"TxBytes":654321,"CurAddr":"192.0.2.10:41641","Relay":"lhr","LastHandshake":"2026-06-09T22:30:00Z"},
				"nodekey:bbb": {"HostName":"laptop-b","DNSName":"laptop-b.example-tailnet.ts.net.","OS":"macOS","Online":false,"RxBytes":0,"TxBytes":0,"CurAddr":"","Relay":"lhr","LastHandshake":"0001-01-01T00:00:00Z"}
			}
		}`))
	})
	mux.HandleFunc("/api/tailscale/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	return httptest.NewServer(mux)
}

func TestTailscaleCollector_Update_Default(t *testing.T) {
	server := tailscaleTestServer(t)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &tailscaleCollector{subsystem: TailscaleSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	// service_running + backend_running + info + peers_total + peers_with_active_session
	// + health_warnings = 6
	if len(metrics) != 6 {
		t.Fatalf("expected 6 metrics without details, got %d", len(metrics))
	}
	var sawHealthWarnings bool
	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "peers_with_active_session") && getMetricValue(m) != 1 {
			t.Errorf("expected peers_with_active_session=1, got %v", getMetricValue(m))
		}
		if strings.Contains(desc, "tailscale_info") {
			labels := getMetricLabels(m)
			if labels["version"] != "1.96.4" || labels["relay"] != "lhr" {
				t.Errorf("bad info labels: %v", labels)
			}
		}
		if strings.Contains(desc, "health_warnings") {
			sawHealthWarnings = true
			if getMetricValue(m) != 2 {
				t.Errorf("expected health_warnings=2, got %v", getMetricValue(m))
			}
		}
	}
	if !sawHealthWarnings {
		t.Error("expected a health_warnings metric")
	}
}

func TestTailscaleCollector_Update_Details(t *testing.T) {
	server := tailscaleTestServer(t)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &tailscaleCollector{subsystem: TailscaleSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)
	// 6 default + per-peer:
	//   server-a (handshake): session_active/direct/rx/tx/last_handshake (5)
	//   laptop-b (no handshake): session_active/rx/tx (3 — direct and
	//   last_handshake are omitted without a session)
	// = 14
	if len(metrics) != 14 {
		t.Fatalf("expected 14 metrics with details, got %d", len(metrics))
	}
	var sawRx, sawDirectForB bool
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		if strings.Contains(desc, "peer_rx_bytes_total") && labels["peer"] == "server-a" {
			sawRx = true
			if getMetricValue(m) != 123456 {
				t.Errorf("expected rx 123456, got %v", getMetricValue(m))
			}
		}
		if strings.Contains(desc, "peer_session_active") && labels["peer"] == "laptop-b" &&
			getMetricValue(m) != 0 {
			t.Errorf("expected laptop-b session_active=0, got %v", getMetricValue(m))
		}
		if strings.Contains(desc, "peer_direct") && labels["peer"] == "laptop-b" {
			sawDirectForB = true
		}
	}
	if !sawRx {
		t.Error("missing peer_rx_bytes_total for server-a")
	}
	if sawDirectForB {
		t.Error("peer_direct must not be emitted for peers without a handshake")
	}
}

func TestTailscaleCollector_PluginAbsent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &tailscaleCollector{subsystem: TailscaleSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when plugin absent, got %d", len(metrics))
	}
}
