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
	// service_running + backend_running + info + peers + peers_with_active_session
	// + health_warnings + the #583 reauth_required gauge = 7.
	// key_expiry_timestamp_seconds is NOT counted: the fixture's Self carries no
	// KeyExpiry (upstream omits it when the node key does not expire), and an
	// absent expiry must emit nothing rather than epoch 0.
	if len(metrics) != 7 {
		t.Fatalf("expected 7 metrics without details, got %d", len(metrics))
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
	// = 14, plus the #583 reauth_required gauge = 15 (see the count comment in
	// TestTailscaleCollector_Update_Default for why key_expiry is absent).
	if len(metrics) != 15 {
		t.Fatalf("expected 15 metrics with details, got %d", len(metrics))
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

// TestTailscaleCollector_ReauthAndKeyExpiry covers the two #583 node-local
// posture signals. Both describe the same outcome — the tunnel stops working —
// with completely different remedies, which is why BackendState alone is not
// enough: it says "not Running" without saying a human has to click a link.
func TestTailscaleCollector_ReauthAndKeyExpiry(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tailscale/status/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Version":"1.96.4","BackendState":"NeedsLogin",
			"AuthURL":"https://login.tailscale.com/a/SUPERSECRETTOKEN",
			"Self":{"HostName":"fw","Relay":"lhr","KeyExpiry":"2026-09-01T00:00:00Z"},
			"Peer":{},"Health":[]}`))
	})
	mux.HandleFunc("/api/tailscale/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := &tailscaleCollector{subsystem: TailscaleSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, newCollectorTestClient(t, server))
	assertNoDuplicateSeries(t, metrics)

	var sawReauth, sawExpiry bool
	for _, m := range metrics {
		switch {
		case hasFqName(m, "opnsense_tailscale_reauth_required"):
			sawReauth = true
			if v := getMetricValue(m); v != 1 {
				t.Errorf("reauth_required = %v, want 1", v)
			}
		case hasFqName(m, "opnsense_tailscale_key_expiry_timestamp_seconds"):
			sawExpiry = true
			if v := getMetricValue(m); v != 1788220800 {
				t.Errorf("key_expiry = %v, want 1788220800", v)
			}
		}
		// The AuthURL is a one-click credential. It must never reach a label,
		// on this metric or any other.
		for k, v := range getMetricLabels(m) {
			if strings.Contains(v, "login.tailscale.com") || strings.Contains(v, "SUPERSECRETTOKEN") {
				t.Fatalf("AuthURL leaked into label %s=%q on %s", k, v, m.Desc().String())
			}
		}
	}
	if !sawReauth || !sawExpiry {
		t.Errorf("missing metric(s): reauth=%v expiry=%v", sawReauth, sawExpiry)
	}
}

// TestTailscaleCollector_NoKeyExpiryEmitsNoSeries: a node with key expiry
// disabled omits KeyExpiry entirely (upstream declares it *time.Time with
// omitempty). Emitting 0 there would read as "the key expired in 1970" and
// page immediately and forever on a perfectly healthy tunnel. reauth_required
// is still emitted as a real 0 — the field is always on the wire.
func TestTailscaleCollector_NoKeyExpiryEmitsNoSeries(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tailscale/status/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Version":"1.96.4","BackendState":"Running","AuthURL":"",
			"Self":{"HostName":"fw","Relay":"lhr"},"Peer":{},"Health":[]}`))
	})
	mux.HandleFunc("/api/tailscale/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := &tailscaleCollector{subsystem: TailscaleSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, newCollectorTestClient(t, server))

	var sawReauth bool
	for _, m := range metrics {
		if hasFqName(m, "opnsense_tailscale_key_expiry_timestamp_seconds") {
			t.Fatalf("key_expiry must not be emitted when the node key does not expire (got %v)", getMetricValue(m))
		}
		if hasFqName(m, "opnsense_tailscale_reauth_required") {
			sawReauth = true
			if v := getMetricValue(m); v != 0 {
				t.Errorf("reauth_required = %v, want 0", v)
			}
		}
	}
	if !sawReauth {
		t.Error("reauth_required must be emitted as a real 0 on a healthy node")
	}
}
