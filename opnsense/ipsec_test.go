package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchIPsecPhase1_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	// Phase1 endpoint (GET)
	mux.HandleFunc("/api/ipsec/sessions/search_phase1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET for phase1, got %s", r.Method)
		}
		w.Write([]byte(`{
			"rows": [
				{
					"phase1desc": "Office VPN",
					"connected": true,
					"ikeid": "100",
					"name": "office-vpn",
					"install-time": "3600",
					"bytes-in": 123456,
					"bytes-out": 654321,
					"packets-in": 1000,
					"packets-out": 2000
				},
				{
					"phase1desc": "Backup VPN",
					"connected": false,
					"ikeid": "200",
					"name": "backup-vpn",
					"install-time": "invalid",
					"bytes-in": 0,
					"bytes-out": 0,
					"packets-in": 0,
					"packets-out": 0
				}
			],
			"rowCount": 2,
			"total": 2,
			"current": 1
		}`))
	})

	// Phase2 endpoint (POST) - returns data based on ikeid
	mux.HandleFunc("/api/ipsec/sessions/search_phase2", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST for phase2, got %s", r.Method)
		}
		// Return different data based on the request (all calls get same response for simplicity)
		w.Write([]byte(`{
			"rows": [
				{
					"phase2desc": "Tunnel 1",
					"name": "tunnel-1",
					"spi-in": "0xaabbccdd",
					"spi-out": "0x11223344",
					"install-time": "1800",
					"rekey-time": "900",
					"life-time": "3600",
					"bytes-in": "50000",
					"bytes-out": "40000",
					"packets-in": "500",
					"packets-out": "400"
				},
				{
					"phase2desc": "Tunnel 2",
					"name": "tunnel-2",
					"spi-in": "0xeeff0011",
					"spi-out": "0x22334455",
					"install-time": "invalid",
					"rekey-time": "",
					"life-time": "7200",
					"bytes-in": "abc",
					"bytes-out": "0",
					"packets-in": "0",
					"packets-out": "0"
				}
			]
		}`))
	})

	data, err := client.FetchIPsecPhase1()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Rows) != 2 {
		t.Fatalf("expected 2 phase1 rows, got %d", len(data.Rows))
	}

	// First phase1: connected
	p1 := data.Rows[0]
	if p1.Phase1desc != "Office VPN" {
		t.Errorf("expected Phase1desc 'Office VPN', got %q", p1.Phase1desc)
	}
	if p1.Connected != 1 {
		t.Errorf("expected Connected=1 (true), got %d", p1.Connected)
	}
	if p1.IkeId != "100" {
		t.Errorf("expected IkeId '100', got %q", p1.IkeId)
	}
	if p1.InstallTime != 3600 {
		t.Errorf("expected InstallTime=3600, got %d", p1.InstallTime)
	}
	if p1.BytesIn != 123456 {
		t.Errorf("expected BytesIn=123456, got %d", p1.BytesIn)
	}
	if p1.BytesOut != 654321 {
		t.Errorf("expected BytesOut=654321, got %d", p1.BytesOut)
	}

	// Check phase2 data
	if len(p1.Phase2) != 2 {
		t.Fatalf("expected 2 phase2 entries, got %d", len(p1.Phase2))
	}

	ph2_1 := p1.Phase2[0]
	if ph2_1.Phase2desc != "Tunnel 1" {
		t.Errorf("expected Phase2desc 'Tunnel 1', got %q", ph2_1.Phase2desc)
	}
	if ph2_1.SpiIn != "0xaabbccdd" {
		t.Errorf("expected SpiIn '0xaabbccdd', got %q", ph2_1.SpiIn)
	}
	if ph2_1.InstallTime != 1800 {
		t.Errorf("expected Phase2 InstallTime=1800, got %d", ph2_1.InstallTime)
	}
	if ph2_1.RekeyTime != 900 {
		t.Errorf("expected Phase2 RekeyTime=900, got %d", ph2_1.RekeyTime)
	}
	if ph2_1.BytesIn != 50000 {
		t.Errorf("expected Phase2 BytesIn=50000, got %d", ph2_1.BytesIn)
	}
	if ph2_1.PacketsOut != 400 {
		t.Errorf("expected Phase2 PacketsOut=400, got %d", ph2_1.PacketsOut)
	}

	// Check invalid values fall back to 0
	ph2_2 := p1.Phase2[1]
	if ph2_2.InstallTime != 0 {
		t.Errorf("expected Phase2 InstallTime=0 for 'invalid', got %d", ph2_2.InstallTime)
	}
	if ph2_2.RekeyTime != 0 {
		t.Errorf("expected Phase2 RekeyTime=0 for empty string, got %d", ph2_2.RekeyTime)
	}
	if ph2_2.BytesIn != 0 {
		t.Errorf("expected Phase2 BytesIn=0 for 'abc', got %d", ph2_2.BytesIn)
	}

	// Second phase1: not connected
	p2 := data.Rows[1]
	if p2.Connected != 0 {
		t.Errorf("expected Connected=0 (false), got %d", p2.Connected)
	}
	if p2.InstallTime != 0 {
		t.Errorf("expected InstallTime=0 for 'invalid', got %d", p2.InstallTime)
	}
}

func TestFetchIPsecPhase1_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchIPsecPhase1()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestFetchIPsecPhase2_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.Write([]byte(`{
			"rows": [
				{
					"phase2desc": "Tunnel A",
					"name": "tunnel-a",
					"spi-in": "0x1234",
					"spi-out": "0x5678",
					"install-time": "100",
					"rekey-time": "50",
					"life-time": "200",
					"bytes-in": "1000",
					"bytes-out": "2000",
					"packets-in": "10",
					"packets-out": "20"
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchIPsecPhase2("42")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(data.Rows))
	}
	if data.Rows[0].Phase2desc != "Tunnel A" {
		t.Errorf("expected Phase2desc 'Tunnel A', got %q", data.Rows[0].Phase2desc)
	}
}
