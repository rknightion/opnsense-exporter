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

func TestFetchKeaLeases4_KeaDisabled(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	// When Kea is not enabled, OPNsense returns "interfaces" as an empty
	// JSON array [] instead of an object {}. The collector must handle this
	// gracefully rather than failing with a JSON unmarshal error.
	mux.HandleFunc("/api/kea/leases4/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 0,
			"rowCount": 0,
			"current": 1,
			"rows": [],
			"interfaces": []
		}`))
	})

	data, err := client.FetchKeaLeases4()
	if err != nil {
		t.Fatalf("unexpected error when Kea is disabled: %v", err)
	}

	if data.TotalLeases != 0 {
		t.Errorf("expected TotalLeases=0, got %d", data.TotalLeases)
	}
	if len(data.Leases) != 0 {
		t.Errorf("expected 0 leases, got %d", len(data.Leases))
	}
}

func TestFetchKeaLeases6_IsReservedArray(t *testing.T) {
	// OPNsense PHP serializes is_reserved as a JSON array: a NON-EMPTY array
	// (e.g. ["hwaddr"], the live 26.1 reserved shape) means reserved, an empty
	// array ([]) means dynamic. Older releases used the string "1"/"0".
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/kea/leases6/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 3,
			"rowCount": 3,
			"current": 1,
			"rows": [
				{
					"address": "fd00::10",
					"hwaddr": "aa:bb:cc:dd:ee:10",
					"hostname": "server1",
					"expire": 1772501000,
					"if_descr": "LAN",
					"is_reserved": []
				},
				{
					"address": "fd00::20",
					"hwaddr": "aa:bb:cc:dd:ee:20",
					"hostname": "workstation1",
					"expire": 1772502000,
					"if_descr": "LAN",
					"is_reserved": "1"
				},
				{
					"address": "fd00::30",
					"hwaddr": "aa:bb:cc:dd:ee:30",
					"hostname": "printer1",
					"expire": 1772503000,
					"if_descr": "LAN",
					"is_reserved": ["hwaddr"]
				}
			]
		}`))
	})

	data, err := client.FetchKeaLeases6()
	if err != nil {
		t.Fatalf("unexpected error when is_reserved is []: %v", err)
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

// Some OPNsense/Kea versions return expire as a quoted string (upstream #105,
// open PR #109). The whole response must still decode.
func TestFetchKeaLeases4_StringExpireVariant(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 2,
			"rowCount": 2,
			"current": 1,
			"rows": [
				{
					"address": "10.0.0.50",
					"hwaddr": "aa:bb:cc:dd:ee:ff",
					"hostname": "stringy",
					"expire": "1750000000",
					"if_descr": "LAN",
					"is_reserved": "1"
				},
				{
					"address": "10.0.0.51",
					"hwaddr": "11:22:33:44:55:66",
					"hostname": "inty",
					"expire": 1750000001,
					"if_descr": "LAN",
					"is_reserved": []
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchKeaLeases4()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Leases) != 2 {
		t.Fatalf("expected 2 leases, got %d", len(data.Leases))
	}
	if data.Leases[0].Expire != 1750000000 {
		t.Errorf("expected string expire parsed to 1750000000, got %d", data.Leases[0].Expire)
	}
	if !data.Leases[0].IsReserved {
		t.Error("expected first lease reserved")
	}
	if data.Leases[1].Expire != 1750000001 {
		t.Errorf("expected numeric expire 1750000001, got %d", data.Leases[1].Expire)
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

func TestFetchKeaSubnets6_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/kea/dhcpv6/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{"uuid":"99d70a8d","subnet":"2001:db8:100::/64","pools":"2001:db8:100::1000 - 2001:db8:100::1fff","interface":"opt3","%interface":"MGMT"},
				{"uuid":"0c511ead","subnet":"2001:db8::/64","pools":"2001:db8::1000 - 2001:db8::1fff","interface":"lan","%interface":"LAN"}
			],
			"rowCount": 2, "total": 2, "current": 1
		}`))
	})

	subnets, err := client.FetchKeaSubnets6()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(subnets) != 2 {
		t.Fatalf("expected 2 subnets, got %d", len(subnets))
	}
	if subnets[0].Subnet != "2001:db8:100::/64" || subnets[0].Interface != "MGMT" || subnets[0].PoolSize != 4096 {
		t.Errorf("unexpected subnet[0]: %+v", subnets[0])
	}
	if subnets[0].UUID != "99d70a8d" {
		t.Errorf("expected UUID '99d70a8d', got %q", subnets[0].UUID)
	}
}

// TestFetchKeaLeases6_TypeAndState covers issue #208: per-row `type`
// (DHCPv6 IA_NA/IA_PD) and `state` (0=active, 1=declined,
// 2=expired-reclaimed) breakdowns, plus the top-level `stats` object
// (confirmed live on OPNsense 26.7/26.1.11 — dev-box comment 2026-07-13).
func TestFetchKeaLeases6_TypeAndState(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/kea/leases6/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 4,
			"rowCount": 4,
			"current": 1,
			"rows": [
				{"address":"fd00::10","hwaddr":"aa:bb:cc:dd:ee:01","hostname":"h1","expire":1,"if_descr":"LAN","is_reserved":"0","type":"IA_NA","state":0},
				{"address":"fd00::20","hwaddr":"aa:bb:cc:dd:ee:02","hostname":"h2","expire":2,"if_descr":"LAN","is_reserved":"0","type":"IA_PD","state":0},
				{"address":"fd00::30","hwaddr":"aa:bb:cc:dd:ee:03","hostname":"h3","expire":3,"if_descr":"LAN","is_reserved":"0","type":"IA_NA","state":1},
				{"address":"fd00::40","hwaddr":"aa:bb:cc:dd:ee:04","hostname":"h4","expire":4,"if_descr":"LAN","is_reserved":"0","type":"IA_NA","state":2}
			],
			"stats": {"active": 2, "inactive": 2, "total": 4},
			"interfaces": {"em0": "LAN"}
		}`))
	})

	data, err := client.FetchKeaLeases6()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.LeasesByType["IA_NA"] != 3 {
		t.Errorf("expected LeasesByType[IA_NA]=3, got %d", data.LeasesByType["IA_NA"])
	}
	if data.LeasesByType["IA_PD"] != 1 {
		t.Errorf("expected LeasesByType[IA_PD]=1, got %d", data.LeasesByType["IA_PD"])
	}
	if data.LeasesByState["active"] != 2 {
		t.Errorf("expected LeasesByState[active]=2, got %d", data.LeasesByState["active"])
	}
	if data.LeasesByState["declined"] != 1 {
		t.Errorf("expected LeasesByState[declined]=1, got %d", data.LeasesByState["declined"])
	}
	if data.LeasesByState["expired-reclaimed"] != 1 {
		t.Errorf("expected LeasesByState[expired-reclaimed]=1, got %d", data.LeasesByState["expired-reclaimed"])
	}

	if data.Leases[0].Type != "IA_NA" || data.Leases[0].State != 0 {
		t.Errorf("unexpected lease[0]: type=%q state=%d", data.Leases[0].Type, data.Leases[0].State)
	}
	if data.Leases[1].Type != "IA_PD" {
		t.Errorf("expected lease[1].Type=IA_PD, got %q", data.Leases[1].Type)
	}

	if data.StatsActive != 2 || data.StatsInactive != 2 || data.StatsTotal != 4 {
		t.Errorf("expected top-level stats active=2 inactive=2 total=4, got active=%d inactive=%d total=%d",
			data.StatsActive, data.StatsInactive, data.StatsTotal)
	}
}

// TestFetchKeaLeases_StatsIsAuthoritativeNotRowDerived proves the exported
// StatsActive/StatsInactive/StatsTotal come from Kea's own top-level `stats`
// object rather than being re-derived by counting rows -- the two
// deliberately disagree in this fixture (rows describe only 1 lease; stats
// claims a much larger pool), which is exactly why the stats block is
// authoritative: bootgrid rows can page, the stats block is computed by Kea
// over the full lease population and never truncated (#557).
func TestFetchKeaLeases_StatsIsAuthoritativeNotRowDerived(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/kea/leases4/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1,
			"rowCount": 1,
			"current": 1,
			"rows": [
				{"address":"10.0.0.5","hwaddr":"aa:bb:cc:dd:ee:01","hostname":"h1","expire":1,"if_descr":"LAN","is_reserved":"0","type":"","state":0}
			],
			"stats": {"active": 900, "inactive": 100, "total": 1000}
		}`))
	})

	data, err := client.FetchKeaLeases4()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Leases) != 1 {
		t.Fatalf("expected 1 decoded row, got %d", len(data.Leases))
	}
	if data.StatsActive != 900 || data.StatsInactive != 100 || data.StatsTotal != 1000 {
		t.Errorf("expected stats active=900 inactive=100 total=1000 (independent of the 1 decoded row), got active=%d inactive=%d total=%d",
			data.StatsActive, data.StatsInactive, data.StatsTotal)
	}
}

// TestFetchKeaLeases_StatsAbsent proves an older/degenerate response with no
// `stats` object leaves the stats fields at their zero value rather than
// erroring, since flexInt already tolerates an absent key.
func TestFetchKeaLeases_StatsAbsent(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/kea/leases4/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total": 0, "rowCount": 0, "current": 1, "rows": []}`))
	})

	data, err := client.FetchKeaLeases4()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.StatsActive != 0 || data.StatsInactive != 0 || data.StatsTotal != 0 {
		t.Errorf("expected zero-valued stats when absent, got active=%d inactive=%d total=%d",
			data.StatsActive, data.StatsInactive, data.StatsTotal)
	}
}

// TestFetchKeaLeases4_NoTypeField covers the DHCPv4 side: get_kea_leases.py
// always sends type:"" for v4 (Kea has no lease-type concept there), so
// LeasesByType must stay empty — the dhcp6-only by_type metric has nothing
// to emit for v4.
func TestFetchKeaLeases4_NoTypeField(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/kea/leases4/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1,
			"rowCount": 1,
			"current": 1,
			"rows": [
				{"address":"10.0.0.5","hwaddr":"aa:bb:cc:dd:ee:01","hostname":"h1","expire":1,"if_descr":"LAN","is_reserved":"0","type":"","state":0}
			]
		}`))
	})

	data, err := client.FetchKeaLeases4()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.LeasesByType) != 0 {
		t.Errorf("expected empty LeasesByType for DHCPv4, got %v", data.LeasesByType)
	}
	if data.LeasesByState["active"] != 1 {
		t.Errorf("expected LeasesByState[active]=1, got %d", data.LeasesByState["active"])
	}
}

func TestFetchKeaPdPools_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/kea/dhcpv6/searchPdPool", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"rows": [
				{"subnet":"sub6-uuid","%subnet":"opt1 fd00:1::/64","prefix":"fd00:1:1000::","prefix_len":56,"delegated_len":60}
			],
			"rowCount": 1, "total": 1, "current": 1
		}`))
	})

	pools, err := client.FetchKeaPdPools()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pools) != 1 {
		t.Fatalf("expected 1 pool, got %d", len(pools))
	}
	p := pools[0]
	if p.SubnetUUID != "sub6-uuid" {
		t.Errorf("expected SubnetUUID 'sub6-uuid', got %q", p.SubnetUUID)
	}
	if p.SubnetDisplay != "opt1 fd00:1::/64" {
		t.Errorf("expected SubnetDisplay 'opt1 fd00:1::/64', got %q", p.SubnetDisplay)
	}
	if p.Prefix != "fd00:1:1000::" {
		t.Errorf("expected Prefix 'fd00:1:1000::', got %q", p.Prefix)
	}
	// delegated_len(60) - prefix_len(56) = 4 -> 2^4 = 16
	if p.Capacity != 16 {
		t.Errorf("expected Capacity=16, got %v", p.Capacity)
	}
}

func TestFetchKeaPdPools_Empty(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/kea/dhcpv6/searchPdPool", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})

	pools, err := client.FetchKeaPdPools()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pools) != 0 {
		t.Errorf("expected 0 pools, got %d", len(pools))
	}
}

func TestFetchKeaPdPools_InvalidPrefixLengths(t *testing.T) {
	// A delegated length shorter than the pool's own prefix is invalid Kea
	// config; contribute 0 rather than a negative/garbage capacity.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/kea/dhcpv6/searchPdPool", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{"subnet":"sub6-uuid","%subnet":"opt1 fd00:1::/64","prefix":"fd00:1::","prefix_len":64,"delegated_len":56}
			],
			"rowCount": 1, "total": 1, "current": 1
		}`))
	})

	pools, err := client.FetchKeaPdPools()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pools) != 1 {
		t.Fatalf("expected 1 pool, got %d", len(pools))
	}
	if pools[0].Capacity != 0 {
		t.Errorf("expected Capacity=0 for invalid lengths, got %v", pools[0].Capacity)
	}
}

func TestKeaPoolUsedBySubnet(t *testing.T) {
	subnets := []KeaSubnet{
		{UUID: "u1", Subnet: "10.0.0.0/24", Interface: "LAN"},
		{UUID: "u2", Subnet: "192.168.1.0/24", Interface: "OPT1"},
	}
	leases := []KeaLease{
		{Address: "10.0.0.50"},
		{Address: "10.0.0.51"},
		{Address: "192.168.1.5"},
		{Address: "172.16.0.1"},             // matches no subnet
		{Address: "not-an-ip"},              // unparseable, skipped
		{Address: "fd00::1", Type: "IA_PD"}, // PD lease, excluded regardless of address
	}

	used := KeaPoolUsedBySubnet(leases, subnets)
	if used["10.0.0.0/24"] != 2 {
		t.Errorf("expected 10.0.0.0/24 used=2, got %d", used["10.0.0.0/24"])
	}
	if used["192.168.1.0/24"] != 1 {
		t.Errorf("expected 192.168.1.0/24 used=1, got %d", used["192.168.1.0/24"])
	}
}

func TestKeaPoolUsedBySubnet_ExcludesPDLeases(t *testing.T) {
	subnets := []KeaSubnet{
		{UUID: "u1", Subnet: "fd00:1::/64", Interface: "LAN"},
	}
	leases := []KeaLease{
		{Address: "fd00:1::10", Type: "IA_NA"},
		{Address: "fd00:1::20", Type: "IA_PD"}, // excluded: PD prefix, not an address lease
	}

	used := KeaPoolUsedBySubnet(leases, subnets)
	if used["fd00:1::/64"] != 1 {
		t.Errorf("expected fd00:1::/64 used=1 (IA_PD excluded), got %d", used["fd00:1::/64"])
	}
}

func TestKeaPoolUsedBySubnet_ZeroFillsUnmatchedSubnets(t *testing.T) {
	subnets := []KeaSubnet{
		{UUID: "u1", Subnet: "10.0.0.0/24", Interface: "LAN"},
	}
	used := KeaPoolUsedBySubnet(nil, subnets)
	if got, ok := used["10.0.0.0/24"]; !ok || got != 0 {
		t.Errorf("expected zero-filled entry for 10.0.0.0/24, got %d (ok=%v)", got, ok)
	}
}

func TestKeaPoolUsedBySubnet_UnparseableSubnetCIDRSkipped(t *testing.T) {
	subnets := []KeaSubnet{
		{UUID: "u1", Subnet: "not-a-cidr", Interface: "LAN"},
	}
	leases := []KeaLease{{Address: "10.0.0.5"}}
	used := KeaPoolUsedBySubnet(leases, subnets)
	// The bad subnet still gets its zero-filled entry (so the series exists),
	// but never matches leases.
	if got := used["not-a-cidr"]; got != 0 {
		t.Errorf("expected 0 for unparseable subnet, got %d", got)
	}
}

// TestFetchKeaLeases4_RealDevBoxCapture replays the literal live payload
// captured on the dev box (issue #208, 2026-07-13, p1-devbox-core:
// captures/kea/leases4_search_with_data.json) — a real active DHCPv4 lease
// after fixing a legacy-dhcpd/Kea port-67 conflict on the box. Confirms
// type:"" and state:0 (JSON number) on a genuinely live lease, is_reserved:[]
// (dynamic), and that `stats`/`interfaces` decode as siblings of `rows` with
// `interfaces` as a populated JSON OBJECT.
func TestFetchKeaLeases4_RealDevBoxCapture(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/kea/leases4/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":1,"rowCount":1,"current":1,"rows":[{"address":"172.16.9.100","prefix_len":128,"type":"","hwaddr":"bc:24:11:a5:a6:34","duid":"","client_id":"","iaid":"","valid_lifetime":4000,"expire":1783968374,"hostname":"exporter-traffgen","state":0,"if":"vtnet2","if_descr":"TESTLAN","is_reserved":[],"if_name":"opt1","mac_info":"Proxmox Server Solutions GmbH"}],"stats":{"active":1,"inactive":0,"total":1},"interfaces":{"opt1":"TESTLAN"}}`))
	})

	data, err := client.FetchKeaLeases4()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.TotalLeases != 1 || data.DynamicCount != 1 || data.ReservedCount != 0 {
		t.Errorf("unexpected counts: total=%d dynamic=%d reserved=%d", data.TotalLeases, data.DynamicCount, data.ReservedCount)
	}
	if len(data.Leases) != 1 {
		t.Fatalf("expected 1 lease, got %d", len(data.Leases))
	}
	l := data.Leases[0]
	if l.Type != "" {
		t.Errorf("expected empty Type on a real v4 lease, got %q", l.Type)
	}
	if l.State != 0 {
		t.Errorf("expected State=0, got %d", l.State)
	}
	if l.IfDescr != "TESTLAN" {
		t.Errorf("expected IfDescr=TESTLAN, got %q", l.IfDescr)
	}
	if data.LeasesByState["active"] != 1 {
		t.Errorf("expected LeasesByState[active]=1, got %d", data.LeasesByState["active"])
	}
	if len(data.LeasesByType) != 0 {
		t.Errorf("expected empty LeasesByType (v4 has no type), got %v", data.LeasesByType)
	}
	// #482: mac_info (OUI vendor lookup), client_id (raw DHCPv4 option 61) and
	// valid_lifetime (Kea's valid-lft) as captured on the real dev-box lease.
	if l.Vendor != "Proxmox Server Solutions GmbH" {
		t.Errorf("expected Vendor 'Proxmox Server Solutions GmbH', got %q", l.Vendor)
	}
	if l.ClientID != "" {
		t.Errorf("expected empty ClientID (client sent no option 61), got %q", l.ClientID)
	}
	if l.ValidLifetime != 4000 {
		t.Errorf("expected ValidLifetime=4000, got %d", l.ValidLifetime)
	}
}

// TestFetchKeaPdPools_RealDevBoxCapture replays the literal live PD pool
// payload captured on the dev box (issue #208, 2026-07-13, p1-devbox-core:
// captures/kea/dhcpv6_search_pd_pool.json) — a real PD pool added via
// kea/dhcpv6/addPdPool, confirmed via Kea's own stats
// (subnet[1].pd-pool[0].total-pds == 64 after reload). Confirms subnet is
// the parent subnet6's uuid, %subnet is "<descr> <cidr>" space-separated,
// and prefix_len/delegated_len arrive as JSON STRINGS on this box (not
// numbers) — flexInt must tolerate that.
func TestFetchKeaPdPools_RealDevBoxCapture(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/kea/dhcpv6/searchPdPool", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[{"uuid":"fbbea24d-f96b-4bd7-9394-5084912a818f","subnet":"ab25acc5-fd49-47c4-ae2d-1eea0fa1b871","%subnet":"TESTLAN fd09:172:16:9::/64","prefix":"fd09:172:16:100::","prefix_len":"56","delegated_len":"62","description":"Test PD pool"}],"rowCount":1,"total":1,"current":1}`))
	})

	pools, err := client.FetchKeaPdPools()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pools) != 1 {
		t.Fatalf("expected 1 pool, got %d", len(pools))
	}
	p := pools[0]
	if p.SubnetUUID != "ab25acc5-fd49-47c4-ae2d-1eea0fa1b871" {
		t.Errorf("expected SubnetUUID from real capture, got %q", p.SubnetUUID)
	}
	if p.SubnetDisplay != "TESTLAN fd09:172:16:9::/64" {
		t.Errorf("expected SubnetDisplay 'TESTLAN fd09:172:16:9::/64', got %q", p.SubnetDisplay)
	}
	if p.Prefix != "fd09:172:16:100::" {
		t.Errorf("expected Prefix 'fd09:172:16:100::', got %q", p.Prefix)
	}
	// delegated_len("62") - prefix_len("56") = 6 -> 2^6 = 64, matching Kea's
	// own reported total-pds==64 for this pool.
	if p.Capacity != 64 {
		t.Errorf("expected Capacity=64 (matches Kea's own total-pds), got %v", p.Capacity)
	}
}

// TestFetchKeaLeases4_VendorClientIDValidLifetime covers issue #482:
// mac_info (decoded as Vendor), client_id and valid_lifetime on the DHCPv4
// endpoint. The empty-value case is the NORMAL case (mac_info is empty
// whenever the OUI is unknown, e.g. MAC randomisation; client_id is empty
// whenever the client never sent DHCPv4 option 61), so the fixture pins one
// lease with all three empty and one with all three populated.
func TestFetchKeaLeases4_VendorClientIDValidLifetime(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/kea/leases4/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 2,
			"rowCount": 2,
			"current": 1,
			"rows": [
				{
					"address": "10.0.0.5",
					"hwaddr": "aa:bb:cc:dd:ee:01",
					"hostname": "randomised-client",
					"expire": 1,
					"if_descr": "LAN",
					"is_reserved": "0",
					"mac_info": "",
					"client_id": "",
					"valid_lifetime": 0
				},
				{
					"address": "10.0.0.6",
					"hwaddr": "aa:bb:cc:dd:ee:02",
					"hostname": "known-client",
					"expire": 2,
					"if_descr": "LAN",
					"is_reserved": "0",
					"mac_info": "Apple, Inc.",
					"client_id": "0100112233",
					"valid_lifetime": 7200
				}
			]
		}`))
	})

	data, err := client.FetchKeaLeases4()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Leases) != 2 {
		t.Fatalf("expected 2 leases, got %d", len(data.Leases))
	}

	empty := data.Leases[0]
	if empty.Vendor != "" {
		t.Errorf("expected empty Vendor for unknown OUI, got %q", empty.Vendor)
	}
	if empty.ClientID != "" {
		t.Errorf("expected empty ClientID when no option 61 sent, got %q", empty.ClientID)
	}
	if empty.ValidLifetime != 0 {
		t.Errorf("expected ValidLifetime=0, got %d", empty.ValidLifetime)
	}

	known := data.Leases[1]
	if known.Vendor != "Apple, Inc." {
		t.Errorf("expected Vendor 'Apple, Inc.', got %q", known.Vendor)
	}
	if known.ClientID != "0100112233" {
		t.Errorf("expected ClientID '0100112233', got %q", known.ClientID)
	}
	if known.ValidLifetime != 7200 {
		t.Errorf("expected ValidLifetime=7200, got %d", known.ValidLifetime)
	}
}

// TestFetchKeaLeases6_VendorValidLifetime_ClientIDAlwaysEmpty covers issue
// #482 on the DHCPv6 endpoint. mac_info and valid_lifetime are populated by
// the same shared row-builder as v4 (LeasesController.php's OUI lookup runs
// unconditionally; get_kea_leases.py emits valid_lifetime from Kea's
// valid-lft for both protocols). client_id is different: it comes straight
// from Kea's own lease dict (`lease.get("client-id", "")`), and Kea's
// lease6-get-all response has no "client-id" key at all (DHCPv6 identifies
// clients by DUID, not option 61) — so client_id is permanently "" on every
// v6 row, confirmed against upstream's get_kea_leases.py source. This is
// verified here as an explicit negative so the field is never mistaken for
// "just needs a live client that sends it".
func TestFetchKeaLeases6_VendorValidLifetime_ClientIDAlwaysEmpty(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/kea/leases6/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1,
			"rowCount": 1,
			"current": 1,
			"rows": [
				{
					"address": "fd00::10",
					"hwaddr": "aa:bb:cc:dd:ee:10",
					"hostname": "server1",
					"expire": 1772501000,
					"if_descr": "LAN",
					"is_reserved": "0",
					"mac_info": "Google, Inc.",
					"client_id": "",
					"valid_lifetime": 3600
				}
			]
		}`))
	})

	data, err := client.FetchKeaLeases6()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Leases) != 1 {
		t.Fatalf("expected 1 lease, got %d", len(data.Leases))
	}

	l := data.Leases[0]
	if l.Vendor != "Google, Inc." {
		t.Errorf("expected Vendor 'Google, Inc.', got %q", l.Vendor)
	}
	if l.ValidLifetime != 3600 {
		t.Errorf("expected ValidLifetime=3600, got %d", l.ValidLifetime)
	}
	if l.ClientID != "" {
		t.Errorf("expected ClientID always empty on DHCPv6 (no option-61 concept), got %q", l.ClientID)
	}
}
