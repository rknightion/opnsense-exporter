package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchDnsmasqLeases_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"total": 4,
			"rowCount": 4,
			"current": 1,
			"rows": [
				{
					"expire": 3600,
					"hwaddr": "aa:bb:cc:dd:ee:f1",
					"iaid": "",
					"address": "192.168.1.10",
					"hostname": "desktop1",
					"client_id": "",
					"if": "em0",
					"if_descr": "LAN",
					"if_name": "em0",
					"mac_info": "",
					"is_reserved": "1"
				},
				{
					"expire": 7200,
					"hwaddr": "aa:bb:cc:dd:ee:f2",
					"iaid": "",
					"address": "192.168.1.11",
					"hostname": "laptop1",
					"client_id": "",
					"if": "em0",
					"if_descr": "LAN",
					"if_name": "em0",
					"mac_info": "",
					"is_reserved": "0"
				},
				{
					"expire": 1800,
					"hwaddr": "aa:bb:cc:dd:ee:f3",
					"iaid": "",
					"address": "10.0.0.50",
					"hostname": "iot-device",
					"client_id": "",
					"if": "em1",
					"if_descr": "IOT",
					"if_name": "em1",
					"mac_info": "",
					"is_reserved": "1"
				},
				{
					"expire": 900,
					"hwaddr": "aa:bb:cc:dd:ee:f4",
					"iaid": "",
					"address": "10.0.0.51",
					"hostname": "sensor",
					"client_id": "",
					"if": "em1",
					"if_descr": "IOT",
					"if_name": "em1",
					"mac_info": "",
					"is_reserved": "0"
				}
			],
			"interfaces": {"em0": "LAN", "em1": "IOT"}
		}`))
	})
	defer server.Close()

	data, err := client.FetchDnsmasqLeases()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.TotalLeases != 4 {
		t.Errorf("expected TotalLeases=4, got %d", data.TotalLeases)
	}
	if data.ReservedCount != 2 {
		t.Errorf("expected ReservedCount=2, got %d", data.ReservedCount)
	}
	if data.DynamicCount != 2 {
		t.Errorf("expected DynamicCount=2, got %d", data.DynamicCount)
	}
	if len(data.Leases) != 4 {
		t.Fatalf("expected 4 leases, got %d", len(data.Leases))
	}

	// Check LeasesByInterface grouping
	if data.LeasesByInterface["LAN"] != 2 {
		t.Errorf("expected LeasesByInterface['LAN']=2, got %d", data.LeasesByInterface["LAN"])
	}
	if data.LeasesByInterface["IOT"] != 2 {
		t.Errorf("expected LeasesByInterface['IOT']=2, got %d", data.LeasesByInterface["IOT"])
	}

	// Check reserved lease
	l1 := data.Leases[0]
	if !l1.IsReserved {
		t.Error("expected first lease to be reserved")
	}
	if l1.Address != "192.168.1.10" {
		t.Errorf("expected address '192.168.1.10', got %q", l1.Address)
	}
	if l1.IfDescr != "LAN" {
		t.Errorf("expected IfDescr 'LAN', got %q", l1.IfDescr)
	}

	// Check dynamic lease
	l2 := data.Leases[1]
	if l2.IsReserved {
		t.Error("expected second lease to be dynamic (not reserved)")
	}
}

func TestFetchDnsmasqLeases_EmptyResponse(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 0,
			"rowCount": 0,
			"current": 1,
			"rows": [],
			"interfaces": {}
		}`))
	})
	defer server.Close()

	data, err := client.FetchDnsmasqLeases()
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

func TestFetchDnsmasqLeases_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchDnsmasqLeases()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
