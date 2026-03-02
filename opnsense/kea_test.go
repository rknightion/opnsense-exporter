package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchKeaLeases4_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/kea/leases4/search", func(w http.ResponseWriter, r *http.Request) {
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
					"hwaddr": "aa:bb:cc:dd:ee:01",
					"hostname": "desktop1",
					"expire": 1772401221,
					"if_descr": "LAN",
					"is_reserved": "1"
				},
				{
					"address": "192.168.1.20",
					"hwaddr": "aa:bb:cc:dd:ee:02",
					"hostname": "laptop1",
					"expire": 1772402000,
					"if_descr": "LAN",
					"is_reserved": "0"
				},
				{
					"address": "10.0.0.50",
					"hwaddr": "aa:bb:cc:dd:ee:03",
					"hostname": "iot-sensor",
					"expire": 1772403000,
					"if_descr": "IOT",
					"is_reserved": "0"
				}
			],
			"interfaces": {"em0": "LAN", "em1": "IOT"}
		}`))
	})

	data, err := client.FetchKeaLeases4()
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

	// Check reserved lease
	l1 := data.Leases[0]
	if !l1.IsReserved {
		t.Error("expected first lease to be reserved")
	}
	if l1.Address != "192.168.1.10" {
		t.Errorf("expected address '192.168.1.10', got %q", l1.Address)
	}
	if l1.Hostname != "desktop1" {
		t.Errorf("expected hostname 'desktop1', got %q", l1.Hostname)
	}
	if l1.HWAddr != "aa:bb:cc:dd:ee:01" {
		t.Errorf("expected hwaddr 'aa:bb:cc:dd:ee:01', got %q", l1.HWAddr)
	}
	if l1.IfDescr != "LAN" {
		t.Errorf("expected IfDescr 'LAN', got %q", l1.IfDescr)
	}
	if l1.Expire != 1772401221 {
		t.Errorf("expected expire 1772401221, got %d", l1.Expire)
	}

	// Check dynamic lease
	l2 := data.Leases[1]
	if l2.IsReserved {
		t.Error("expected second lease to be dynamic (not reserved)")
	}
}

func TestFetchKeaLeases4_Empty(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/kea/leases4/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 0,
			"rowCount": 0,
			"current": 1,
			"rows": [],
			"interfaces": {}
		}`))
	})

	data, err := client.FetchKeaLeases4()
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

func TestFetchKeaLeases6_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/kea/leases6/search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"total": 2,
			"rowCount": 2,
			"current": 1,
			"rows": [
				{
					"address": "fd00::10",
					"hwaddr": "aa:bb:cc:dd:ee:10",
					"hostname": "server1",
					"expire": 1772501000,
					"if_descr": "LAN",
					"is_reserved": "1"
				},
				{
					"address": "fd00::20",
					"hwaddr": "aa:bb:cc:dd:ee:20",
					"hostname": "workstation1",
					"expire": 1772502000,
					"if_descr": "LAN",
					"is_reserved": "0"
				}
			],
			"interfaces": {"em0": "LAN"}
		}`))
	})

	data, err := client.FetchKeaLeases6()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.TotalLeases != 2 {
		t.Errorf("expected TotalLeases=2, got %d", data.TotalLeases)
	}
	if data.ReservedCount != 1 {
		t.Errorf("expected ReservedCount=1, got %d", data.ReservedCount)
	}
	if data.DynamicCount != 1 {
		t.Errorf("expected DynamicCount=1, got %d", data.DynamicCount)
	}
	if len(data.Leases) != 2 {
		t.Fatalf("expected 2 leases, got %d", len(data.Leases))
	}

	// Check v6 addresses
	if data.Leases[0].Address != "fd00::10" {
		t.Errorf("expected address 'fd00::10', got %q", data.Leases[0].Address)
	}
	if data.Leases[1].Address != "fd00::20" {
		t.Errorf("expected address 'fd00::20', got %q", data.Leases[1].Address)
	}

	if data.LeasesByInterface["LAN"] != 2 {
		t.Errorf("expected LeasesByInterface['LAN']=2, got %d", data.LeasesByInterface["LAN"])
	}
}

func TestFetchKeaLeases4_ServerError(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/kea/leases4/search", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})

	_, err := client.FetchKeaLeases4()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
