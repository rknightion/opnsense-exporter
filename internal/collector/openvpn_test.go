package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestOpenVPNCollector_Update(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/openvpn/instances/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"uuid": "vpn-uuid-1",
					"description": "Site-to-Site VPN",
					"role": "Server",
					"dev_type": "tun",
					"enabled": "1"
				},
				{
					"uuid": "vpn-uuid-2",
					"description": "Road Warrior",
					"role": "Client",
					"dev_type": "tun",
					"enabled": "0"
				}
			],
			"rowCount": 2,
			"total": 2,
			"current": 1
		}`))
	})

	mux.HandleFunc("/api/openvpn/service/search_sessions", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"description": "Site-to-Site VPN",
					"username": "user1",
					"virtual_address": "10.0.0.2",
					"status": "ok"
				}
			],
			"rowCount": 1,
			"total": 1,
			"current": 1
		}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &openVPNCollector{subsystem: OpenVPNSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 2 instances + 1 session = 3
	expectedCount := 3
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestOpenVPNCollector_Update_NoSessions(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/openvpn/instances/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"uuid": "vpn-uuid-1",
					"description": "VPN Server",
					"role": "Server",
					"dev_type": "tun",
					"enabled": "1"
				}
			],
			"rowCount": 1,
			"total": 1,
			"current": 1
		}`))
	})

	mux.HandleFunc("/api/openvpn/service/search_sessions", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [],
			"rowCount": 0,
			"total": 0,
			"current": 1
		}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &openVPNCollector{subsystem: OpenVPNSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 1 instance + 0 sessions = 1
	expectedCount := 1
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestOpenVPNCollector_Name(t *testing.T) {
	c := &openVPNCollector{subsystem: OpenVPNSubsystem}
	if c.Name() != OpenVPNSubsystem {
		t.Errorf("expected %s, got %s", OpenVPNSubsystem, c.Name())
	}
}
