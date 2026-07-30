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
					"mac_info": "Dell Inc.",
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
	if l1.Device != "em0" {
		t.Errorf("expected Device 'em0', got %q", l1.Device)
	}
	if l1.Vendor != "Dell Inc." {
		t.Errorf("expected Vendor 'Dell Inc.', got %q", l1.Vendor)
	}

	// Check dynamic lease
	l2 := data.Leases[1]
	if l2.IsReserved {
		t.Error("expected second lease to be dynamic (not reserved)")
	}
	// mac_info empty (unknown OUI) must stay empty, matching Kea's Vendor
	// behaviour exactly rather than being forced to a sentinel (#556).
	if l2.Vendor != "" {
		t.Errorf("expected empty Vendor for unknown OUI, got %q", l2.Vendor)
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

func TestFetchDnsmasqLeases_ArrayQuirks(t *testing.T) {
	// OPNsense PHP serializes is_reserved as a JSON array: a NON-EMPTY array
	// (e.g. ["hwaddr"], the live 26.1 shape) means reserved, an empty array ([])
	// means dynamic. Older releases used the string "1"/"0". interfaces arriving
	// as [] must be treated as an empty map.
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 3,
			"rowCount": 3,
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
					"is_reserved": []
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
					"is_reserved": "1"
				},
				{
					"expire": 7200,
					"hwaddr": "aa:bb:cc:dd:ee:f3",
					"iaid": "",
					"address": "192.168.1.12",
					"hostname": "printer1",
					"client_id": "",
					"if": "em0",
					"if_descr": "LAN",
					"if_name": "em0",
					"mac_info": "",
					"is_reserved": ["hwaddr"]
				}
			],
			"interfaces": []
		}`))
	})
	defer server.Close()

	data, err := client.FetchDnsmasqLeases()
	if err != nil {
		t.Fatalf("unexpected error when fields are []: %v", err)
	}

	if data.TotalLeases != 3 {
		t.Errorf("expected TotalLeases=3, got %d", data.TotalLeases)
	}
	if len(data.Leases) != 3 {
		t.Fatalf("expected 3 leases, got %d", len(data.Leases))
	}

	// Row with is_reserved:[] must be treated as not-reserved.
	if data.Leases[0].IsReserved {
		t.Error("expected first lease (is_reserved:[]) to be not reserved")
	}
	// Row with is_reserved:"1" must still be reserved.
	if !data.Leases[1].IsReserved {
		t.Error("expected second lease (is_reserved:\"1\") to be reserved")
	}
	// Row with is_reserved:["hwaddr"] (live 26.1 reserved shape) must be reserved.
	if !data.Leases[2].IsReserved {
		t.Error("expected third lease (is_reserved:[\"hwaddr\"]) to be reserved")
	}

	if data.ReservedCount != 2 {
		t.Errorf("expected ReservedCount=2, got %d", data.ReservedCount)
	}
	if data.DynamicCount != 1 {
		t.Errorf("expected DynamicCount=1, got %d", data.DynamicCount)
	}
}

func TestFetchDnsmasqLeases_EmptyIfFallsBackToUnknownDevice(t *testing.T) {
	// dnsmasqLeaseRow.If is a plain string (not flexString); an empty "if"
	// must fall back to the "unknown" device sentinel, never an empty label
	// value (#556).
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1,
			"rowCount": 1,
			"current": 1,
			"rows": [
				{
					"expire": 3600,
					"hwaddr": "aa:bb:cc:dd:ee:f1",
					"iaid": "",
					"address": "192.168.1.10",
					"hostname": "desktop1",
					"client_id": "",
					"if": "",
					"if_descr": "",
					"if_name": "",
					"mac_info": "",
					"is_reserved": "0"
				}
			],
			"interfaces": {}
		}`))
	})
	defer server.Close()

	data, err := client.FetchDnsmasqLeases()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Leases) != 1 {
		t.Fatalf("expected 1 lease, got %d", len(data.Leases))
	}
	if data.Leases[0].Device != "unknown" {
		t.Errorf("expected Device 'unknown' for empty if, got %q", data.Leases[0].Device)
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

func TestFetchDnsmasqRanges_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dnsmasq/settings/searchRange", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{"uuid":"ff727ea1","interface":"lan","%interface":"LAN","start_addr":"10.0.0.110","end_addr":"10.0.0.240","subnet_mask":"","constructor":"","mode":"","prefix_len":"","lease_time":"21600","domain":"example.net","description":""},
				{"uuid":"9fa2ada0","interface":"opt2","%interface":"IOT","start_addr":"10.0.50.110","end_addr":"10.0.50.240","subnet_mask":"","constructor":"","mode":"","prefix_len":"","lease_time":"21600","domain":"iot.example.net","description":""},
				{"uuid":"deadbeef","interface":"opt9","%interface":"V6RA","start_addr":"","end_addr":"","subnet_mask":"","constructor":"opt9","mode":"slaac","prefix_len":"64","lease_time":"","domain":"","description":"constructed v6 range"}
			],
			"rowCount": 3, "total": 3, "current": 1
		}`))
	})

	ranges, err := client.FetchDnsmasqRanges()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// constructed v6 row has no parseable start/end -> skipped
	if len(ranges) != 2 {
		t.Fatalf("expected 2 ranges, got %d", len(ranges))
	}
	if ranges[0].Interface != "LAN" || ranges[0].PoolSize != 131 {
		t.Errorf("unexpected range[0]: %+v", ranges[0])
	}
}
