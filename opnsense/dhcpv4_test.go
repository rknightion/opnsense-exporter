package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchDHCPv4Leases_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dhcpv4/leases/searchLease", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"total": 3,
			"rowCount": 3,
			"current": 1,
			"rows": [
				{
					"address": "192.168.1.10",
					"mac": "aa:bb:cc:dd:ee:01",
					"type": "static",
					"state": "active",
					"status": "online",
					"hostname": "desktop1",
					"descr": "Main desktop",
					"starts": "",
					"ends": "",
					"if": "em0",
					"if_descr": "LAN",
					"man": "Dell Inc."
				},
				{
					"address": "192.168.1.20",
					"mac": "aa:bb:cc:dd:ee:02",
					"type": "dynamic",
					"state": "active",
					"status": "online",
					"hostname": "laptop1",
					"descr": "",
					"starts": "2024/01/01 10:00:00",
					"ends": "2024/01/01 22:00:00",
					"if": "em0",
					"if_descr": "LAN",
					"man": ""
				},
				{
					"address": "10.0.0.50",
					"mac": "aa:bb:cc:dd:ee:03",
					"type": "dynamic",
					"state": "expired",
					"status": "offline",
					"hostname": "iot-sensor",
					"descr": "",
					"starts": "2024/01/01 08:00:00",
					"ends": "2024/01/01 09:00:00",
					"if": "em1",
					"if_descr": "IOT",
					"man": ""
				}
			],
			"interfaces": {"em0": "LAN", "em1": "IOT"}
		}`))
	})

	data, err := client.FetchDHCPv4Leases()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.TotalLeases != 3 {
		t.Errorf("expected TotalLeases=3, got %d", data.TotalLeases)
	}
	if data.ReservedCount != 1 {
		t.Errorf("expected ReservedCount=1, got %d", data.ReservedCount)
	}
	if data.DynamicCount != 2 {
		t.Errorf("expected DynamicCount=2, got %d", data.DynamicCount)
	}
	if len(data.Leases) != 3 {
		t.Fatalf("expected 3 leases, got %d", len(data.Leases))
	}

	// Check LeasesByInterface grouping
	if data.LeasesByInterface["LAN"] != 2 {
		t.Errorf("expected LeasesByInterface['LAN']=2, got %d", data.LeasesByInterface["LAN"])
	}
	if data.LeasesByInterface["IOT"] != 1 {
		t.Errorf("expected LeasesByInterface['IOT']=1, got %d", data.LeasesByInterface["IOT"])
	}

	// Check static lease fields
	l1 := data.Leases[0]
	if l1.Type != "static" {
		t.Errorf("expected type 'static', got %q", l1.Type)
	}
	if l1.Address != "192.168.1.10" {
		t.Errorf("expected address '192.168.1.10', got %q", l1.Address)
	}
	if l1.MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("expected mac 'aa:bb:cc:dd:ee:01', got %q", l1.MAC)
	}
	if l1.Hostname != "desktop1" {
		t.Errorf("expected hostname 'desktop1', got %q", l1.Hostname)
	}
	if l1.IfDescr != "LAN" {
		t.Errorf("expected IfDescr 'LAN', got %q", l1.IfDescr)
	}
	if l1.Status != "online" {
		t.Errorf("expected status 'online', got %q", l1.Status)
	}
	if l1.State != "active" {
		t.Errorf("expected state 'active', got %q", l1.State)
	}

	// Check dynamic lease
	l2 := data.Leases[1]
	if l2.Type != "dynamic" {
		t.Errorf("expected type 'dynamic', got %q", l2.Type)
	}
}

func TestFetchDHCPv4Leases_Empty(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dhcpv4/leases/searchLease", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 0,
			"rowCount": 0,
			"current": 1,
			"rows": [],
			"interfaces": {}
		}`))
	})

	data, err := client.FetchDHCPv4Leases()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.TotalLeases != 0 {
		t.Errorf("expected TotalLeases=0, got %d", data.TotalLeases)
	}
	if data.ReservedCount != 0 {
		t.Errorf("expected ReservedCount=0, got %d", data.ReservedCount)
	}
	if data.DynamicCount != 0 {
		t.Errorf("expected DynamicCount=0, got %d", data.DynamicCount)
	}
	if len(data.LeasesByInterface) != 0 {
		t.Errorf("expected empty LeasesByInterface, got %v", data.LeasesByInterface)
	}
}

func TestFetchDHCPv4Leases_ArrayQuirks(t *testing.T) {
	// OPNsense PHP serializes empty fields as [] instead of "" or {}.
	// All flexString fields must tolerate [] gracefully (decoded as "").
	// interfaces arriving as [] must be treated as an empty map.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dhcpv4/leases/searchLease", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 2,
			"rowCount": 2,
			"current": 1,
			"rows": [
				{
					"address": "192.168.1.10",
					"mac": [],
					"type": "static",
					"state": "active",
					"status": [],
					"hostname": [],
					"descr": [],
					"starts": [],
					"ends": [],
					"if": [],
					"if_descr": "LAN",
					"man": []
				},
				{
					"address": "192.168.1.20",
					"mac": "aa:bb:cc:dd:ee:02",
					"type": "dynamic",
					"state": "active",
					"status": "online",
					"hostname": "laptop1",
					"descr": "",
					"starts": "",
					"ends": "",
					"if": "em0",
					"if_descr": "LAN",
					"man": ""
				}
			],
			"interfaces": []
		}`))
	})

	data, err := client.FetchDHCPv4Leases()
	if err != nil {
		t.Fatalf("unexpected error when fields are []: %v", err)
	}

	if data.TotalLeases != 2 {
		t.Errorf("expected TotalLeases=2, got %d", data.TotalLeases)
	}
	if len(data.Leases) != 2 {
		t.Fatalf("expected 2 leases, got %d", len(data.Leases))
	}

	// Row with mac:[] must decode to empty string (not panic).
	if data.Leases[0].MAC != "" {
		t.Errorf("expected empty mac from [], got %q", data.Leases[0].MAC)
	}
	// static type must still count as reserved.
	if data.ReservedCount != 1 {
		t.Errorf("expected ReservedCount=1, got %d", data.ReservedCount)
	}
	if data.DynamicCount != 1 {
		t.Errorf("expected DynamicCount=1, got %d", data.DynamicCount)
	}
}

func TestFetchDHCPv4Leases_ServerError(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dhcpv4/leases/searchLease", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})

	_, err := client.FetchDHCPv4Leases()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
