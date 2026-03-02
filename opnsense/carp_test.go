package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchCARPStatus_WithVIPs(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/diagnostics/interface/get_vip_status" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Write([]byte(`{
			"rows": [
				{
					"interface": "LAN",
					"vhid": "1",
					"advbase": "1",
					"advskew": "0",
					"status": "MASTER",
					"status_txt": "MASTER",
					"vip": "10.0.0.1",
					"subnet": "24"
				},
				{
					"interface": "WAN",
					"vhid": "2",
					"advbase": "2",
					"advskew": "100",
					"status": "BACKUP",
					"status_txt": "BACKUP",
					"vip": "192.168.1.1",
					"subnet": "24"
				}
			],
			"carp": {
				"demotion": "0",
				"allow": "1",
				"maintenancemode": false
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchCARPStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Global fields
	if data.Demotion != 0 {
		t.Errorf("expected Demotion=0, got %d", data.Demotion)
	}
	if !data.Allow {
		t.Error("expected Allow=true")
	}
	if data.MaintenanceMode {
		t.Error("expected MaintenanceMode=false")
	}

	// VIPs
	if len(data.VIPs) != 2 {
		t.Fatalf("expected 2 VIPs, got %d", len(data.VIPs))
	}

	v1 := data.VIPs[0]
	if v1.Interface != "LAN" {
		t.Errorf("expected Interface='LAN', got %q", v1.Interface)
	}
	if v1.VHID != "1" {
		t.Errorf("expected VHID='1', got %q", v1.VHID)
	}
	if v1.VIP != "10.0.0.1" {
		t.Errorf("expected VIP='10.0.0.1', got %q", v1.VIP)
	}
	if v1.Status != 1 {
		t.Errorf("expected Status=1 (MASTER), got %d", v1.Status)
	}
	if v1.Advbase != 1 {
		t.Errorf("expected Advbase=1, got %d", v1.Advbase)
	}
	if v1.Advskew != 0 {
		t.Errorf("expected Advskew=0, got %d", v1.Advskew)
	}

	v2 := data.VIPs[1]
	if v2.Interface != "WAN" {
		t.Errorf("expected Interface='WAN', got %q", v2.Interface)
	}
	if v2.VHID != "2" {
		t.Errorf("expected VHID='2', got %q", v2.VHID)
	}
	if v2.VIP != "192.168.1.1" {
		t.Errorf("expected VIP='192.168.1.1', got %q", v2.VIP)
	}
	if v2.Status != 0 {
		t.Errorf("expected Status=0 (BACKUP), got %d", v2.Status)
	}
	if v2.Advbase != 2 {
		t.Errorf("expected Advbase=2, got %d", v2.Advbase)
	}
	if v2.Advskew != 100 {
		t.Errorf("expected Advskew=100, got %d", v2.Advskew)
	}
}

func TestFetchCARPStatus_Empty(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 0,
			"rowCount": 0,
			"current": 1,
			"rows": [],
			"carp": {
				"demotion": "5",
				"allow": "0",
				"maintenancemode": true,
				"status_msg": "Could not locate any defined CARP interfaces."
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchCARPStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.VIPs) != 0 {
		t.Errorf("expected 0 VIPs, got %d", len(data.VIPs))
	}
	if data.Demotion != 5 {
		t.Errorf("expected Demotion=5, got %d", data.Demotion)
	}
	if data.Allow {
		t.Error("expected Allow=false")
	}
	if !data.MaintenanceMode {
		t.Error("expected MaintenanceMode=true")
	}
}

func TestFetchCARPStatus_StatusMapping(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected int
	}{
		{"MASTER maps to 1", "MASTER", 1},
		{"BACKUP maps to 0", "BACKUP", 0},
		{"INIT maps to 2", "INIT", 2},
		{"unknown maps to -1", "UNKNOWN", -1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
				resp := carpStatusResponse{
					Rows: []carpVIPRow{
						{
							Interface: "LAN",
							VHID:      "1",
							Advbase:   "1",
							Advskew:   "0",
							Status:    tc.status,
							StatusTxt: tc.status,
							VIP:       "10.0.0.1",
							Subnet:    "24",
						},
					},
					Carp: carpInfo{
						Demotion: "0",
						Allow:    "1",
					},
				}
				w.Write(mustMarshal(t, resp))
			})
			defer server.Close()

			data, err := client.FetchCARPStatus()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if data.VIPs[0].Status != tc.expected {
				t.Errorf("status %q: expected %d, got %d", tc.status, tc.expected, data.VIPs[0].Status)
			}
		})
	}
}

func TestFetchCARPStatus_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchCARPStatus()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
