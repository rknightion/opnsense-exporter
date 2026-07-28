package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchOpenVPNInstances_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.Write([]byte(`{
			"rows": [
				{
					"uuid": "vpn-uuid-1",
					"description": "Road Warrior VPN",
					"role": "Server",
					"dev_type": "tun",
					"enabled": "1"
				},
				{
					"uuid": "vpn-uuid-2",
					"description": "Site-to-Site VPN",
					"role": "CLIENT",
					"dev_type": "tap",
					"enabled": "0"
				}
			],
			"rowCount": 2,
			"total": 2,
			"current": 1
		}`))
	})
	defer server.Close()

	data, err := client.FetchOpenVPNInstances()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Rows) != 2 {
		t.Fatalf("expected 2 instances, got %d", len(data.Rows))
	}

	// Check role lowercasing
	i1 := data.Rows[0]
	if i1.UUID != "vpn-uuid-1" {
		t.Errorf("expected UUID 'vpn-uuid-1', got %q", i1.UUID)
	}
	if i1.Description != "Road Warrior VPN" {
		t.Errorf("expected description 'Road Warrior VPN', got %q", i1.Description)
	}
	if i1.Role != "server" {
		t.Errorf("expected role 'server' (lowercased), got %q", i1.Role)
	}
	if i1.DevType != "tun" {
		t.Errorf("expected DevType 'tun', got %q", i1.DevType)
	}
	if i1.Enabled != 1 {
		t.Errorf("expected Enabled=1, got %d", i1.Enabled)
	}

	i2 := data.Rows[1]
	if i2.Role != "client" {
		t.Errorf("expected role 'client' (lowercased), got %q", i2.Role)
	}
	if i2.Enabled != 0 {
		t.Errorf("expected Enabled=0, got %d", i2.Enabled)
	}
}

func TestFetchOpenVPNInstances_InvalidEnabled(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"uuid": "vpn-uuid-1",
					"description": "Bad VPN",
					"role": "Server",
					"dev_type": "tun",
					"enabled": "not_a_number"
				}
			],
			"rowCount": 1,
			"total": 1,
			"current": 1
		}`))
	})
	defer server.Close()

	_, err := client.FetchOpenVPNInstances()
	if err == nil {
		t.Fatal("expected error for invalid enabled value")
	}
}

func TestFetchOpenVPNInstances_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchOpenVPNInstances()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestFetchOpenVPNSessions_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"rows": [
				{
					"description": "Road Warrior VPN",
					"username": "user1",
					"real_address": "203.0.113.10:51820",
					"virtual_address": "10.8.0.2",
					"status": "ok",
					"is_client": true
				},
				{
					"description": "Road Warrior VPN",
					"username": "user2",
					"virtual_address": "10.8.0.3",
					"status": "disconnected",
					"is_client": true
				},
				{
					"description": "Site-to-Site",
					"username": "",
					"virtual_address": "10.9.0.1",
					"status": "connected",
					"is_client": true
				}
			],
			"rowCount": 3,
			"total": 3,
			"current": 1
		}`))
	})
	defer server.Close()

	data, err := client.FetchOpenVPNSessions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Rows) != 3 {
		t.Fatalf("expected 3 sessions, got %d", len(data.Rows))
	}

	// Status "ok" -> 1 (server client_list rows)
	s1 := data.Rows[0]
	if s1.Username != "user1" {
		t.Errorf("expected username 'user1', got %q", s1.Username)
	}
	if s1.VirtualAddress != "10.8.0.2" {
		t.Errorf("expected virtual address '10.8.0.2', got %q", s1.VirtualAddress)
	}
	if s1.RealAddress != "203.0.113.10:51820" {
		t.Errorf("expected real address '203.0.113.10:51820', got %q", s1.RealAddress)
	}
	if s1.Status != 1 {
		t.Errorf("expected Status=1 for 'ok', got %d", s1.Status)
	}

	// Status "disconnected" -> 0
	s2 := data.Rows[1]
	if s2.Status != 0 {
		t.Errorf("expected Status=0 for 'disconnected', got %d", s2.Status)
	}

	// Status "connected" -> 1 (client / point-to-point state-machine value)
	s3 := data.Rows[2]
	if s3.Status != 1 {
		t.Errorf("expected Status=1 for 'connected', got %d", s3.Status)
	}
}

// TestFetchOpenVPNSessions_FiltersNonClientRows guards #88: the API mixes real
// client rows (is_client:true) with a synthetic zero-client running-instance row
// and an enabled-but-stopped stub row. Only client rows are sessions.
func TestFetchOpenVPNSessions_FiltersNonClientRows(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{"description":"RW VPN","username":"user1","real_address":"203.0.113.10:1194","virtual_address":"10.8.0.2","status":"ok","is_client":true},
				{"description":"Idle Server","username":"","real_address":"","virtual_address":"","status":"connected"},
				{"description":"Stopped Server","username":"","real_address":"","virtual_address":"","status":"failed"}
			],
			"rowCount": 3,
			"total": 3,
			"current": 1
		}`))
	})
	defer server.Close()

	data, err := client.FetchOpenVPNSessions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Rows) != 1 {
		t.Fatalf("expected 1 client session (idle/stopped rows filtered), got %d", len(data.Rows))
	}
	if data.Rows[0].Username != "user1" {
		t.Errorf("expected the surviving row to be the client row (user1), got %q", data.Rows[0].Username)
	}
}

func TestFetchOpenVPNSessions_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchOpenVPNSessions()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

// TestFetchOpenVPNSessions_TrafficFields guards #212: real per-client session
// rows (is_client:true) additionally carry cumulative byte counters, a
// connected-since unix timestamp (the double-underscore-mangled
// "connected_since__time_t_" field), and a TLS common_name. The live dev-box
// payload (26.7-devel, verified 2026-07-13) sends bytes_received/bytes_sent
// as quoted numeric strings and connected_since__time_t_ as a quoted numeric
// string too, so json.Number (via numToInt) must accept both shapes.
func TestFetchOpenVPNSessions_TrafficFields(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"description": "Road Warrior",
					"username": "UNDEF",
					"common_name": "ovpn-client",
					"real_address": "udp4:203.0.113.10:1194",
					"virtual_address": "10.8.0.2",
					"status": "ok",
					"is_client": true,
					"bytes_received": "477913",
					"bytes_sent": "484828",
					"connected_since__time_t_": "1783879957"
				}
			],
			"rowCount": 1,
			"total": 1,
			"current": 1
		}`))
	})
	defer server.Close()

	data, err := client.FetchOpenVPNSessions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Rows) != 1 {
		t.Fatalf("expected 1 session, got %d", len(data.Rows))
	}

	s := data.Rows[0]
	if s.BytesReceived != 477913 {
		t.Errorf("expected BytesReceived=477913, got %d", s.BytesReceived)
	}
	if s.BytesTransmitted != 484828 {
		t.Errorf("expected BytesTransmitted=484828, got %d", s.BytesTransmitted)
	}
	if s.ConnectedSince != 1783879957 {
		t.Errorf("expected ConnectedSince=1783879957, got %d", s.ConnectedSince)
	}
	if s.CommonName != "ovpn-client" {
		t.Errorf("expected CommonName='ovpn-client', got %q", s.CommonName)
	}
	// common_name present and non-UNDEF username -> Identity() prefers common_name.
	if id := s.Identity(); id != "ovpn-client" {
		t.Errorf("expected Identity()='ovpn-client', got %q", id)
	}
}

// TestFetchOpenVPNSessions_TrafficFieldsNumeric confirms the numeric-JSON shape
// (rather than a quoted string) also decodes correctly, since KindNumeric
// fields must tolerate both wire shapes across OPNsense releases.
func TestFetchOpenVPNSessions_TrafficFieldsNumeric(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"description": "Road Warrior",
					"username": "user1",
					"common_name": null,
					"real_address": "203.0.113.10:1194",
					"virtual_address": "10.8.0.2",
					"status": "ok",
					"is_client": true,
					"bytes_received": 477913,
					"bytes_sent": 484828,
					"connected_since__time_t_": 1783879957
				}
			],
			"rowCount": 1,
			"total": 1,
			"current": 1
		}`))
	})
	defer server.Close()

	data, err := client.FetchOpenVPNSessions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := data.Rows[0]
	if s.BytesReceived != 477913 {
		t.Errorf("expected BytesReceived=477913, got %d", s.BytesReceived)
	}
	if s.BytesTransmitted != 484828 {
		t.Errorf("expected BytesTransmitted=484828, got %d", s.BytesTransmitted)
	}
	if s.ConnectedSince != 1783879957 {
		t.Errorf("expected ConnectedSince=1783879957, got %d", s.ConnectedSince)
	}
	if s.CommonName != "" {
		t.Errorf("expected CommonName='' (null common_name), got %q", s.CommonName)
	}
	// common_name absent -> Identity() falls back to username.
	if id := s.Identity(); id != "user1" {
		t.Errorf("expected Identity()='user1' (fallback), got %q", id)
	}
}

// TestFetchOpenVPNSessions_TrafficFieldsAbsent guards backwards compatibility:
// older OPNsense releases (or the local client-role instance's own status row,
// which never has is_client:true and is already filtered out) may omit these
// fields entirely. Absent fields must decode to their zero value rather than
// failing the scrape.
func TestFetchOpenVPNSessions_TrafficFieldsAbsent(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"description": "Legacy VPN",
					"username": "user1",
					"real_address": "203.0.113.10:1194",
					"virtual_address": "10.8.0.2",
					"status": "ok",
					"is_client": true
				}
			],
			"rowCount": 1,
			"total": 1,
			"current": 1
		}`))
	})
	defer server.Close()

	data, err := client.FetchOpenVPNSessions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := data.Rows[0]
	if s.BytesReceived != 0 {
		t.Errorf("expected BytesReceived=0 when absent, got %d", s.BytesReceived)
	}
	if s.BytesTransmitted != 0 {
		t.Errorf("expected BytesTransmitted=0 when absent, got %d", s.BytesTransmitted)
	}
	if s.ConnectedSince != 0 {
		t.Errorf("expected ConnectedSince=0 when absent, got %d", s.ConnectedSince)
	}
	if s.CommonName != "" {
		t.Errorf("expected CommonName='' when absent, got %q", s.CommonName)
	}
	if id := s.Identity(); id != "user1" {
		t.Errorf("expected Identity()='user1' (fallback), got %q", id)
	}
}

// TestFetchOpenVPNSessions_VirtualIPv6Address guards #483: openVPNSessions rows
// carry virtual_ipv6_address as a peer field alongside virtual_address (both
// come from the same OpenVPN status-3 CLIENT_LIST row, per
// scripts/openvpn/ovpn_status.py). All three real-world shapes must decode
// correctly: v4-only (virtual_ipv6_address absent), dual-stack (both present),
// and v6-only (virtual_address absent, e.g. an IPv6-only tunnel).
func TestFetchOpenVPNSessions_VirtualIPv6Address(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"description": "Road Warrior VPN",
					"username": "v4only",
					"real_address": "203.0.113.10:1194",
					"virtual_address": "10.8.0.2",
					"status": "ok",
					"is_client": true
				},
				{
					"description": "Road Warrior VPN",
					"username": "dualstack",
					"real_address": "203.0.113.11:1194",
					"virtual_address": "10.8.0.3",
					"virtual_ipv6_address": "fd00:8::3",
					"status": "ok",
					"is_client": true
				},
				{
					"description": "Road Warrior VPN",
					"username": "v6only",
					"real_address": "203.0.113.12:1194",
					"virtual_ipv6_address": "fd00:8::4",
					"status": "ok",
					"is_client": true
				}
			],
			"rowCount": 3,
			"total": 3,
			"current": 1
		}`))
	})
	defer server.Close()

	data, err := client.FetchOpenVPNSessions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Rows) != 3 {
		t.Fatalf("expected 3 sessions, got %d", len(data.Rows))
	}

	byUser := make(map[string]Sessions, 3)
	for _, s := range data.Rows {
		byUser[s.Username] = s
	}

	v4only := byUser["v4only"]
	if v4only.VirtualAddress != "10.8.0.2" {
		t.Errorf("expected v4only VirtualAddress='10.8.0.2', got %q", v4only.VirtualAddress)
	}
	if v4only.VirtualIPv6Address != "" {
		t.Errorf("expected v4only VirtualIPv6Address='' (absent), got %q", v4only.VirtualIPv6Address)
	}

	dual := byUser["dualstack"]
	if dual.VirtualAddress != "10.8.0.3" {
		t.Errorf("expected dualstack VirtualAddress='10.8.0.3', got %q", dual.VirtualAddress)
	}
	if dual.VirtualIPv6Address != "fd00:8::3" {
		t.Errorf("expected dualstack VirtualIPv6Address='fd00:8::3', got %q", dual.VirtualIPv6Address)
	}

	v6only := byUser["v6only"]
	if v6only.VirtualAddress != "" {
		t.Errorf("expected v6only VirtualAddress='' (absent), got %q", v6only.VirtualAddress)
	}
	if v6only.VirtualIPv6Address != "fd00:8::4" {
		t.Errorf("expected v6only VirtualIPv6Address='fd00:8::4', got %q", v6only.VirtualIPv6Address)
	}
}
