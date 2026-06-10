package opnsense

import (
	"net/http"
	"testing"
)

const dhcpv6LeasesFixture = `{
  "total": 2,
  "rowCount": 2,
  "current": 1,
  "rows": [
    {"address": "2001:db8::1000", "type": "dynamic", "lease_type": "ia-na",
     "iaid": "0", "duid": "00:01:00:01:aa:bb:cc:dd:ee:ff:00:11",
     "cltt": "2026/06/09 08:00:00", "ends": "2026/06/09 10:00:00", "descr": "",
     "if": "lan", "if_descr": "LAN", "state": "active", "status": "online",
     "mac": "ee:ff:00:11:22:33", "man": "ExampleCorp"},
    {"address": "2001:db8::53", "type": "static", "lease_type": "",
     "iaid": "", "duid": "00:03:00:01:aa:bb:cc:dd:ee:00", "cltt": "", "ends": "",
     "descr": "dns server", "if": "lan", "if_descr": "LAN",
     "state": "active", "status": "offline", "mac": "", "man": ""}
  ],
  "interfaces": {"lan": "LAN"}
}`

const dhcpv6PrefixFixture = `{
  "total": 1,
  "rowCount": 1,
  "current": 1,
  "rows": [
    {"lease_type": "ia-pd", "iaid": "0", "duid": "00:01:00:01:aa:bb:cc:dd:ee:ff:00:11",
     "cltt": "2026/06/09 08:00:00", "prefix": "2001:db8:100::/56",
     "ends": "2026/06/09 10:00:00", "state": "active"}
  ]
}`

func TestFetchDHCPv6Leases_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dhcpv6/leases/searchLease", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(dhcpv6LeasesFixture))
	})

	data, err := client.FetchDHCPv6Leases()
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
	if data.LeasesByInterface["LAN"] != 2 {
		t.Errorf("expected LeasesByInterface[LAN]=2, got %d", data.LeasesByInterface["LAN"])
	}
	if len(data.Leases) != 2 {
		t.Fatalf("expected 2 leases, got %d", len(data.Leases))
	}

	// Verify dynamic lease fields
	var dynLease, statLease DHCPv6Lease
	for _, l := range data.Leases {
		if l.Type == "dynamic" {
			dynLease = l
		} else {
			statLease = l
		}
	}

	if dynLease.Address != "2001:db8::1000" {
		t.Errorf("expected dynamic address 2001:db8::1000, got %q", dynLease.Address)
	}
	if dynLease.MAC != "ee:ff:00:11:22:33" {
		t.Errorf("expected mac ee:ff:00:11:22:33, got %q", dynLease.MAC)
	}
	if dynLease.DUID != "00:01:00:01:aa:bb:cc:dd:ee:ff:00:11" {
		t.Errorf("expected duid, got %q", dynLease.DUID)
	}
	if dynLease.State != "active" {
		t.Errorf("expected state active, got %q", dynLease.State)
	}
	if dynLease.Status != "online" {
		t.Errorf("expected status online, got %q", dynLease.Status)
	}
	if dynLease.IfDescr != "LAN" {
		t.Errorf("expected if_descr LAN, got %q", dynLease.IfDescr)
	}
	if dynLease.LeaseType != "ia-na" {
		t.Errorf("expected lease_type ia-na, got %q", dynLease.LeaseType)
	}

	// Static lease has empty MAC
	if statLease.MAC != "" {
		t.Errorf("expected empty MAC for static lease, got %q", statLease.MAC)
	}
	if statLease.Type != "static" {
		t.Errorf("expected static type, got %q", statLease.Type)
	}
}

func TestFetchDHCPv6Leases_404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchDHCPv6Leases()
	if err != nil {
		t.Fatalf("expected nil error on 404, got: %v", err)
	}
	if data.TotalLeases != 0 || len(data.Leases) != 0 {
		t.Errorf("expected empty data on 404, got: %+v", data)
	}
}

func TestFetchDHCPv6Leases_ArrayQuirk(t *testing.T) {
	// OPNsense PHP may serialize empty optional fields as [] (not a string).
	response := `{
		"total": 1,
		"rowCount": 1,
		"current": 1,
		"rows": [
			{
				"address": "2001:db8::1",
				"type": "dynamic",
				"lease_type": "ia-na",
				"duid": [],
				"descr": [],
				"if": "lan",
				"if_descr": "LAN",
				"state": "active",
				"status": "online",
				"mac": [],
				"man": [],
				"iaid": [],
				"iaid_duid": [],
				"cltt": [],
				"ends": []
			}
		],
		"interfaces": []
	}`

	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dhcpv6/leases/searchLease", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(response))
	})

	data, err := client.FetchDHCPv6Leases()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.TotalLeases != 1 {
		t.Errorf("expected TotalLeases=1, got %d", data.TotalLeases)
	}
	// IfDescr is non-empty from if_descr field, LeasesByInterface should have LAN=1
	if data.LeasesByInterface["LAN"] != 1 {
		t.Errorf("expected LeasesByInterface[LAN]=1, got %d", data.LeasesByInterface["LAN"])
	}
}

func TestFetchDHCPv6Prefixes_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dhcpv6/leases/searchPrefix", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(dhcpv6PrefixFixture))
	})

	data, err := client.FetchDHCPv6Prefixes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Total != 1 {
		t.Errorf("expected Total=1, got %d", data.Total)
	}
	if data.Active != 1 {
		t.Errorf("expected Active=1, got %d", data.Active)
	}
}

func TestFetchDHCPv6Prefixes_404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchDHCPv6Prefixes()
	if err != nil {
		t.Fatalf("expected nil error on 404, got: %v", err)
	}
	if data.Total != 0 || data.Active != 0 {
		t.Errorf("expected empty data on 404, got: %+v", data)
	}
}

func TestFetchDHCPv6Prefixes_ActiveCount(t *testing.T) {
	// Multiple prefixes with mixed states
	response := `{
		"total": 3,
		"rowCount": 3,
		"current": 1,
		"rows": [
			{"prefix": "2001:db8:100::/56", "state": "active", "duid": "a", "iaid": "0", "lease_type": "ia-pd", "cltt": "", "ends": ""},
			{"prefix": "2001:db8:200::/56", "state": "expired", "duid": "b", "iaid": "0", "lease_type": "ia-pd", "cltt": "", "ends": ""},
			{"prefix": "2001:db8:300::/56", "state": "active", "duid": "c", "iaid": "0", "lease_type": "ia-pd", "cltt": "", "ends": ""}
		]
	}`

	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dhcpv6/leases/searchPrefix", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(response))
	})

	data, err := client.FetchDHCPv6Prefixes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Total != 3 {
		t.Errorf("expected Total=3, got %d", data.Total)
	}
	if data.Active != 2 {
		t.Errorf("expected Active=2, got %d", data.Active)
	}
}
