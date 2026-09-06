package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

func keaTestMux(t *testing.T, v4Response, v6Response string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	registerEmptyKeaReservationHandlers(mux)
	mux.HandleFunc("/api/kea/leases4/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(v4Response))
	})
	mux.HandleFunc("/api/kea/leases6/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(v6Response))
	})
	// Stubs for new pool-size and service-status endpoints (empty rows / running).
	mux.HandleFunc("/api/kea/dhcpv4/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	mux.HandleFunc("/api/kea/dhcpv6/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	mux.HandleFunc("/api/kea/dhcpv6/searchPdPool", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	mux.HandleFunc("/api/kea/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	return mux
}

func registerEmptyKeaReservationHandlers(mux *http.ServeMux) {
	empty := func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	}
	mux.HandleFunc("/api/kea/dhcpv4/searchReservation", empty)
	mux.HandleFunc("/api/kea/dhcpv6/searchReservation", empty)
}

func TestKeaCollector_Update(t *testing.T) {
	v4Response := `{
		"total": 2,
		"rowCount": 2,
		"current": 1,
		"rows": [
			{
				"address": "192.168.1.10",
				"hwaddr": "00:11:22:33:44:55",
				"hostname": "desktop",
				"expire": 1772401000,
				"if_descr": "LAN",
				"is_reserved": "1"
			},
			{
				"address": "192.168.1.20",
				"hwaddr": "AA:BB:CC:DD:EE:FF",
				"hostname": "phone",
				"expire": 1772402000,
				"if_descr": "LAN",
				"is_reserved": "0"
			}
		],
		"interfaces": {"em0": "LAN"},
		"stats": {"active": 2, "inactive": 0, "total": 2}
	}`

	v6Response := `{
		"total": 1,
		"rowCount": 1,
		"current": 1,
		"rows": [
			{
				"address": "fd00::10",
				"hwaddr": "11:22:33:44:55:66",
				"hostname": "server1",
				"expire": 1772501000,
				"if_descr": "LAN",
				"is_reserved": "0"
			}
		],
		"interfaces": {"em0": "LAN"},
		"stats": {"active": 1, "inactive": 0, "total": 1}
	}`

	mux := keaTestMux(t, v4Response, v6Response)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &keaCollector{subsystem: KeaSubsystem}
	c.Register("opnsense", "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// v4: 1 leasesTotal + 1 reservedTotal + 1 dynamicTotal + 1 leasesByIface (LAN)
	//     + 1 leasesByState (active) + 3 lease_pool_stats (active/inactive/total) = 8
	// v6: same shape = 8 (no leasesByType: rows carry no "type")
	// + 1 kea_service_running = 17
	expectedCount := 17
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Verify some v4 metric values
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		value := getMetricValue(m)

		if hasFqName(m, "opnsense_kea_dhcp4_leases") && labels["opnsense_instance"] == "test" {
			if value != 2 {
				t.Errorf("expected dhcp4_leases=2, got %v", value)
			}
		}
		if hasFqName(m, "opnsense_kea_dhcp4_leases_reserved") && labels["opnsense_instance"] == "test" {
			if value != 1 {
				t.Errorf("expected dhcp4_leases_reserved=1, got %v", value)
			}
		}
		if hasFqName(m, "opnsense_kea_dhcp4_leases_dynamic") && labels["opnsense_instance"] == "test" {
			if value != 1 {
				t.Errorf("expected dhcp4_leases_dynamic=1, got %v", value)
			}
		}
		if hasFqName(m, "opnsense_kea_dhcp6_leases") && labels["opnsense_instance"] == "test" {
			if value != 1 {
				t.Errorf("expected dhcp6_leases=1, got %v", value)
			}
		}
		if strings.Contains(desc, "dhcp4_leases_by_state") {
			if labels["state"] != "active" || value != 2 {
				t.Errorf("expected dhcp4_leases_by_state{state=active}=2, got state=%q value=%v", labels["state"], value)
			}
		}
		if strings.Contains(desc, "dhcp6_leases_by_state") {
			if labels["state"] != "active" || value != 1 {
				t.Errorf("expected dhcp6_leases_by_state{state=active}=1, got state=%q value=%v", labels["state"], value)
			}
		}
	}

	v4PoolStats := map[string]float64{}
	v6PoolStats := map[string]float64{}
	for _, m := range metrics {
		labels := getMetricLabels(m)
		value := getMetricValue(m)
		switch {
		case hasFqName(m, "opnsense_kea_dhcp4_lease_pool_stats"):
			v4PoolStats[labels["pool_state"]] = value
		case hasFqName(m, "opnsense_kea_dhcp6_lease_pool_stats"):
			v6PoolStats[labels["pool_state"]] = value
		}
	}
	if v4PoolStats["active"] != 2 || v4PoolStats["inactive"] != 0 || v4PoolStats["total"] != 2 {
		t.Errorf("expected dhcp4_lease_pool_stats active=2 inactive=0 total=2, got %+v", v4PoolStats)
	}
	if v6PoolStats["active"] != 1 || v6PoolStats["inactive"] != 0 || v6PoolStats["total"] != 1 {
		t.Errorf("expected dhcp6_lease_pool_stats active=1 inactive=0 total=1, got %+v", v6PoolStats)
	}
}

func TestKeaCollector_Update_WithDetails(t *testing.T) {
	v4Response := `{
		"total": 2,
		"rowCount": 2,
		"current": 1,
		"rows": [
			{
				"address": "192.168.1.10",
				"hwaddr": "00:11:22:33:44:55",
				"hostname": "desktop",
				"expire": 1772401000,
				"if_descr": "LAN",
				"is_reserved": "1"
			},
			{
				"address": "192.168.1.20",
				"hwaddr": "AA:BB:CC:DD:EE:FF",
				"hostname": "phone",
				"expire": 1772402000,
				"if_descr": "LAN",
				"is_reserved": "0"
			}
		],
		"interfaces": {"em0": "LAN"}
	}`

	v6Response := `{
		"total": 1,
		"rowCount": 1,
		"current": 1,
		"rows": [
			{
				"address": "fd00::10",
				"hwaddr": "11:22:33:44:55:66",
				"hostname": "server1",
				"expire": 1772501000,
				"if_descr": "LAN",
				"is_reserved": "0"
			}
		],
		"interfaces": {"em0": "LAN"}
	}`

	mux := keaTestMux(t, v4Response, v6Response)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &keaCollector{subsystem: KeaSubsystem}
	c.Register("opnsense", "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)

	// v4: 3 summary + 1 leasesByIface (LAN) + 1 leasesByState (active) + 2 leaseInfo + 3 lease_pool_stats = 10
	// v6: 3 summary + 1 leasesByIface (LAN) + 1 leasesByState (active) + 1 leaseInfo + 3 lease_pool_stats = 9
	// + 1 kea_service_running = 20
	expectedCount := 20
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Verify a detail metric exists with correct labels
	foundDetail := false
	for _, m := range metrics {
		labels := getMetricLabels(m)
		if labels["address"] == "192.168.1.10" && labels["hostname"] == "desktop" {
			foundDetail = true
			if labels["hwaddr"] != "00:11:22:33:44:55" {
				t.Errorf("expected hwaddr '00:11:22:33:44:55', got %q", labels["hwaddr"])
			}
			if labels["interface"] != "LAN" {
				t.Errorf("expected interface 'LAN', got %q", labels["interface"])
			}
			value := getMetricValue(m)
			if value != 1772401000 {
				t.Errorf("expected expire value 1772401000, got %v", value)
			}
		}
	}
	if !foundDetail {
		t.Error("expected to find detail metric for address 192.168.1.10")
	}
}

func TestKeaCollector_Update_Empty(t *testing.T) {
	emptyResponse := `{
		"total": 0,
		"rowCount": 0,
		"current": 1,
		"rows": [],
		"interfaces": {}
	}`

	mux := keaTestMux(t, emptyResponse, emptyResponse)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &keaCollector{subsystem: KeaSubsystem}
	c.Register("opnsense", "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// v4: 3 summary (total=0, reserved=0, dynamic=0), no leasesByIface, no leasesByState (no rows), 3 lease_pool_stats
	// v6: 3 summary (total=0, reserved=0, dynamic=0), no leasesByIface, no leasesByState (no rows), 3 lease_pool_stats
	// + 1 kea_service_running = 13
	expectedCount := 13
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Verify all values are 0 — service stub returns "running" (value=1);
	// all lease-based metrics are 0; service_running itself is 1 so skip it
	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "kea_service_running") {
			continue
		}
		value := getMetricValue(m)
		if value != 0 {
			t.Errorf("expected metric value 0, got %v for %s", value, desc)
		}
	}
}

func TestKeaCollector_Update_KeaDisabled(t *testing.T) {
	// When Kea is not enabled, OPNsense returns "interfaces": [] instead of {}.
	// The collector must handle this without errors and emit zero-value metrics.
	keaDisabledResponse := `{
		"total": 0,
		"rowCount": 0,
		"current": 1,
		"rows": [],
		"interfaces": []
	}`

	// Build mux manually (not via keaTestMux) so we can set service status to
	// "stopped" — all emitted metric values should be zero.
	mux := http.NewServeMux()
	registerEmptyKeaReservationHandlers(mux)
	mux.HandleFunc("/api/kea/leases4/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(keaDisabledResponse))
	})
	mux.HandleFunc("/api/kea/leases6/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(keaDisabledResponse))
	})
	mux.HandleFunc("/api/kea/dhcpv4/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	mux.HandleFunc("/api/kea/dhcpv6/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	mux.HandleFunc("/api/kea/dhcpv6/searchPdPool", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	mux.HandleFunc("/api/kea/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"stopped"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &keaCollector{subsystem: KeaSubsystem}
	c.Register("opnsense", "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// v4: 3 summary (total=0, reserved=0, dynamic=0), no leasesByIface, no leasesByState, 3 lease_pool_stats
	// v6: 3 summary (total=0, reserved=0, dynamic=0), no leasesByIface, no leasesByState, 3 lease_pool_stats
	// + 1 kea_service_running (value=0, stopped) = 13
	expectedCount := 13
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	for _, m := range metrics {
		value := getMetricValue(m)
		if value != 0 {
			t.Errorf("expected metric value 0, got %v", value)
		}
	}
}

func TestKeaCollector_Name(t *testing.T) {
	c := &keaCollector{subsystem: KeaSubsystem}
	if c.Name() != KeaSubsystem {
		t.Errorf("expected %s, got %s", KeaSubsystem, c.Name())
	}
}

func TestKeaCollector_PoolAndService(t *testing.T) {
	mux := http.NewServeMux()
	registerEmptyKeaReservationHandlers(mux)
	mux.HandleFunc("/api/kea/leases4/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	mux.HandleFunc("/api/kea/leases6/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	mux.HandleFunc("/api/kea/dhcpv4/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[{"uuid":"u1","subnet":"10.0.0.0/24","pools":"10.0.0.110 - 10.0.0.240","interface":"lan","%interface":"LAN"}],"rowCount":1,"total":1,"current":1}`))
	})
	mux.HandleFunc("/api/kea/dhcpv6/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	mux.HandleFunc("/api/kea/dhcpv6/searchPdPool", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	mux.HandleFunc("/api/kea/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &keaCollector{subsystem: KeaSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	var sawPool, sawService, sawPoolUsed bool
	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "kea_dhcp4_pool_size") {
			sawPool = true
			labels := getMetricLabels(m)
			if labels["subnet"] != "10.0.0.0/24" || labels["interface"] != "LAN" || getMetricValue(m) != 131 {
				t.Errorf("bad pool_size: value=%v labels=%v", getMetricValue(m), labels)
			}
		}
		if strings.Contains(desc, "kea_dhcp4_pool_used") {
			sawPoolUsed = true
			labels := getMetricLabels(m)
			if labels["subnet"] != "10.0.0.0/24" || getMetricValue(m) != 0 {
				t.Errorf("bad pool_used: value=%v labels=%v", getMetricValue(m), labels)
			}
		}
		if strings.Contains(desc, "kea_service_running") {
			sawService = true
			if getMetricValue(m) != 1 {
				t.Errorf("expected service_running=1, got %v", getMetricValue(m))
			}
		}
	}
	if !sawPool || !sawService || !sawPoolUsed {
		t.Errorf("missing metrics: pool=%v service=%v poolUsed=%v", sawPool, sawService, sawPoolUsed)
	}
}

func TestKeaCollector_PoolUsed_MatchesLeaseAddress(t *testing.T) {
	// A configured subnet with one matching v4 lease and one out-of-range
	// lease: pool_used must count only the matching address.
	mux := http.NewServeMux()
	registerEmptyKeaReservationHandlers(mux)
	mux.HandleFunc("/api/kea/leases4/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":2,"rowCount":2,"current":1,"rows":[
			{"address":"10.0.0.150","hwaddr":"aa:bb:cc:dd:ee:01","hostname":"h1","expire":1,"if_descr":"LAN","is_reserved":"0"},
			{"address":"192.168.99.5","hwaddr":"aa:bb:cc:dd:ee:02","hostname":"h2","expire":2,"if_descr":"WAN","is_reserved":"0"}
		]}`))
	})
	mux.HandleFunc("/api/kea/leases6/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	mux.HandleFunc("/api/kea/dhcpv4/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[{"uuid":"u1","subnet":"10.0.0.0/24","pools":"10.0.0.110 - 10.0.0.240","interface":"lan","%interface":"LAN"}],"rowCount":1,"total":1,"current":1}`))
	})
	mux.HandleFunc("/api/kea/dhcpv6/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	mux.HandleFunc("/api/kea/dhcpv6/searchPdPool", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	mux.HandleFunc("/api/kea/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &keaCollector{subsystem: KeaSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	found := false
	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "kea_dhcp4_pool_used") {
			found = true
			labels := getMetricLabels(m)
			if labels["subnet"] != "10.0.0.0/24" || getMetricValue(m) != 1 {
				t.Errorf("expected pool_used{subnet=10.0.0.0/24}=1, got labels=%v value=%v", labels, getMetricValue(m))
			}
		}
	}
	if !found {
		t.Error("expected a kea_dhcp4_pool_used metric")
	}
}

func TestKeaCollector_PdPoolCapacity(t *testing.T) {
	mux := http.NewServeMux()
	registerEmptyKeaReservationHandlers(mux)
	mux.HandleFunc("/api/kea/leases4/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	mux.HandleFunc("/api/kea/leases6/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	mux.HandleFunc("/api/kea/dhcpv4/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	mux.HandleFunc("/api/kea/dhcpv6/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[{"uuid":"sub6-uuid","subnet":"fd00:1::/64","pools":"fd00:1::1000 - fd00:1::1fff","interface":"opt1","%interface":"TESTLAN"}],"rowCount":1,"total":1,"current":1}`))
	})
	mux.HandleFunc("/api/kea/dhcpv6/searchPdPool", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[{"subnet":"sub6-uuid","%subnet":"opt1 fd00:1::/64","prefix":"fd00:1:1000::","prefix_len":56,"delegated_len":60}],"rowCount":1,"total":1,"current":1}`))
	})
	mux.HandleFunc("/api/kea/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &keaCollector{subsystem: KeaSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	found := false
	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "kea_dhcp6_pd_pool_size") {
			found = true
			labels := getMetricLabels(m)
			// delegated_len(60) - prefix_len(56) = 4 bits -> 2^4 = 16
			if labels["subnet"] != "fd00:1::/64" || labels["prefix"] != "fd00:1:1000::" || getMetricValue(m) != 16 {
				t.Errorf("bad pd_pool_size: labels=%v value=%v", labels, getMetricValue(m))
			}
		}
	}
	if !found {
		t.Error("expected a kea_dhcp6_pd_pool_size metric")
	}
}

func TestKeaCollector_PdPoolCapacity_UUIDJoinMiss_FallsBackToDisplay(t *testing.T) {
	// When the PD pool's subnet UUID has no matching subnet row (e.g. a stale
	// reference), the subnet label must fall back to parsing the CIDR out of
	// OPNsense's own "%subnet" display string ("<if-key> <cidr>"), never drop
	// the series.
	mux := http.NewServeMux()
	registerEmptyKeaReservationHandlers(mux)
	mux.HandleFunc("/api/kea/leases4/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	mux.HandleFunc("/api/kea/leases6/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	mux.HandleFunc("/api/kea/dhcpv4/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	mux.HandleFunc("/api/kea/dhcpv6/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	mux.HandleFunc("/api/kea/dhcpv6/searchPdPool", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[{"subnet":"missing-uuid","%subnet":"opt1 fd00:2::/64","prefix":"fd00:2:1000::","prefix_len":56,"delegated_len":64}],"rowCount":1,"total":1,"current":1}`))
	})
	mux.HandleFunc("/api/kea/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &keaCollector{subsystem: KeaSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	found := false
	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "kea_dhcp6_pd_pool_size") {
			found = true
			labels := getMetricLabels(m)
			if labels["subnet"] != "fd00:2::/64" {
				t.Errorf("expected subnet label parsed from %%subnet fallback, got %q", labels["subnet"])
			}
		}
	}
	if !found {
		t.Error("expected a kea_dhcp6_pd_pool_size metric")
	}
}

// TestKeaCollector_PdPoolCapacity_RealDevBoxCapture replays the literal live
// subnet6 + PD pool payloads captured on the dev box (issue #208,
// 2026-07-13, p1-devbox-core: captures/kea/dhcpv6_search_subnet.json +
// captures/kea/dhcpv6_search_pd_pool.json — a real PD pool added via
// kea/dhcpv6/addPdPool, confirmed via Kea's own stats
// subnet[1].pd-pool[0].total-pds==64). End-to-end: the UUID join must
// resolve the PD pool's "subnet" label to the real subnet's CIDR
// (fd09:172:16:9::/64), not the raw uuid or the %subnet fallback.
func TestKeaCollector_PdPoolCapacity_RealDevBoxCapture(t *testing.T) {
	mux := http.NewServeMux()
	registerEmptyKeaReservationHandlers(mux)
	mux.HandleFunc("/api/kea/leases4/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	mux.HandleFunc("/api/kea/leases6/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	mux.HandleFunc("/api/kea/dhcpv4/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	mux.HandleFunc("/api/kea/dhcpv6/searchSubnet", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[{"uuid":"ab25acc5-fd49-47c4-ae2d-1eea0fa1b871","subnet":"fd09:172:16:9::/64","pools":"fd09:172:16:9::1000-fd09:172:16:9::1fff","interface":"opt1","%interface":"TESTLAN"}],"rowCount":1,"total":1,"current":1}`))
	})
	mux.HandleFunc("/api/kea/dhcpv6/searchPdPool", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[{"uuid":"fbbea24d-f96b-4bd7-9394-5084912a818f","subnet":"ab25acc5-fd49-47c4-ae2d-1eea0fa1b871","%subnet":"TESTLAN fd09:172:16:9::/64","prefix":"fd09:172:16:100::","prefix_len":"56","delegated_len":"62","description":"Test PD pool"}],"rowCount":1,"total":1,"current":1}`))
	})
	mux.HandleFunc("/api/kea/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &keaCollector{subsystem: KeaSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	found := false
	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "kea_dhcp6_pd_pool_size") {
			found = true
			labels := getMetricLabels(m)
			if labels["subnet"] != "fd09:172:16:9::/64" {
				t.Errorf("expected UUID-joined subnet 'fd09:172:16:9::/64', got %q", labels["subnet"])
			}
			if labels["prefix"] != "fd09:172:16:100::" {
				t.Errorf("expected prefix 'fd09:172:16:100::', got %q", labels["prefix"])
			}
			// delegated_len("62") - prefix_len("56") = 6 -> 2^6 = 64, matching
			// Kea's own reported total-pds==64 for this pool.
			if getMetricValue(m) != 64 {
				t.Errorf("expected capacity=64, got %v", getMetricValue(m))
			}
		}
	}
	if !found {
		t.Error("expected a kea_dhcp6_pd_pool_size metric")
	}
}

// TestKeaCollector_Update_WithDetails_VendorClientIDValidLifetime covers
// issue #482: the mac_info (as `vendor`), `client_id` and `valid_lifetime`
// labels on the gated per-lease info metrics. Two v4 leases are covered
// deliberately: one with all three fields empty (the NORMAL case — mac_info
// is empty on an unknown OUI, client_id is empty whenever the client never
// sent DHCPv4 option 61) and one with all three populated, so an
// all-empty lease still produces exactly one well-formed series rather than
// a dropped or malformed one. The v6 lease carries `vendor` and
// `valid_lifetime` but must NOT carry a `client_id` label at all — DHCPv6
// has no option-61 concept, so it is dropped rather than emitted as an
// always-empty label.
func TestKeaCollector_Update_WithDetails_VendorClientIDValidLifetime(t *testing.T) {
	v4Response := `{
		"total": 2,
		"rowCount": 2,
		"current": 1,
		"rows": [
			{
				"address": "192.168.1.10",
				"hwaddr": "00:11:22:33:44:55",
				"hostname": "randomised-client",
				"expire": 1772401000,
				"if_descr": "LAN",
				"is_reserved": "1",
				"mac_info": "",
				"client_id": "",
				"valid_lifetime": 0
			},
			{
				"address": "192.168.1.20",
				"hwaddr": "AA:BB:CC:DD:EE:FF",
				"hostname": "known-client",
				"expire": 1772402000,
				"if_descr": "LAN",
				"is_reserved": "0",
				"mac_info": "Apple, Inc.",
				"client_id": "0100112233",
				"valid_lifetime": 7200
			}
		],
		"interfaces": {"em0": "LAN"}
	}`

	v6Response := `{
		"total": 1,
		"rowCount": 1,
		"current": 1,
		"rows": [
			{
				"address": "fd00::10",
				"hwaddr": "11:22:33:44:55:66",
				"hostname": "server1",
				"expire": 1772501000,
				"if_descr": "LAN",
				"is_reserved": "0",
				"mac_info": "Google, Inc.",
				"client_id": "",
				"valid_lifetime": 3600
			}
		],
		"interfaces": {"em0": "LAN"}
	}`

	mux := keaTestMux(t, v4Response, v6Response)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &keaCollector{subsystem: KeaSubsystem}
	c.Register("opnsense", "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	var sawEmptyV4Detail, sawKnownV4Detail, sawV6Detail bool
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)

		if strings.Contains(desc, "dhcp4_lease_info") && labels["address"] == "192.168.1.10" {
			sawEmptyV4Detail = true
			if labels["vendor"] != "" {
				t.Errorf("expected empty vendor label for unknown OUI, got %q", labels["vendor"])
			}
			if labels["client_id"] != "" {
				t.Errorf("expected empty client_id label, got %q", labels["client_id"])
			}
			if labels["valid_lifetime"] != "0" {
				t.Errorf("expected valid_lifetime label '0', got %q", labels["valid_lifetime"])
			}
		}
		if strings.Contains(desc, "dhcp4_lease_info") && labels["address"] == "192.168.1.20" {
			sawKnownV4Detail = true
			if labels["vendor"] != "Apple, Inc." {
				t.Errorf("expected vendor label 'Apple, Inc.', got %q", labels["vendor"])
			}
			if labels["client_id"] != "0100112233" {
				t.Errorf("expected client_id label '0100112233', got %q", labels["client_id"])
			}
			if labels["valid_lifetime"] != "7200" {
				t.Errorf("expected valid_lifetime label '7200', got %q", labels["valid_lifetime"])
			}
		}
		if strings.Contains(desc, "dhcp6_lease_info") && labels["address"] == "fd00::10" {
			sawV6Detail = true
			if labels["vendor"] != "Google, Inc." {
				t.Errorf("expected vendor label 'Google, Inc.', got %q", labels["vendor"])
			}
			if labels["valid_lifetime"] != "3600" {
				t.Errorf("expected valid_lifetime label '3600', got %q", labels["valid_lifetime"])
			}
			if _, ok := labels["client_id"]; ok {
				t.Errorf("expected NO client_id label on dhcp6_lease_info (DHCPv6 has no option-61 concept), got %q", labels["client_id"])
			}
		}
	}
	if !sawEmptyV4Detail {
		t.Error("expected to find the all-empty-fields v4 detail metric")
	}
	if !sawKnownV4Detail {
		t.Error("expected to find the fully-populated v4 detail metric")
	}
	if !sawV6Detail {
		t.Error("expected to find the v6 detail metric")
	}
}

// TestKeaCollector_Update_WithDetails_PrefixLen guards #584: prefix_len (the
// IA_PD delegated block size) must land as a label on dhcp6_lease_info ONLY
// -- never on dhcp4_lease_info, since Kea's lease4-get-all has no
// prefix-length concept and get_kea_leases.py's shared row-builder papers
// over that with a hardcoded, meaningless 128 on every v4 row.
func TestKeaCollector_Update_WithDetails_PrefixLen(t *testing.T) {
	v4Response := `{
		"total": 1,
		"rowCount": 1,
		"current": 1,
		"rows": [
			{
				"address": "192.168.1.10",
				"hwaddr": "00:11:22:33:44:55",
				"hostname": "v4-client",
				"expire": 1772401000,
				"if_descr": "LAN",
				"is_reserved": "0",
				"prefix_len": 128
			}
		],
		"interfaces": {"em0": "LAN"}
	}`

	v6Response := `{
		"total": 1,
		"rowCount": 1,
		"current": 1,
		"rows": [
			{
				"address": "fd00:172:16:9::",
				"hwaddr": "11:22:33:44:55:66",
				"hostname": "pd-client",
				"expire": 1772501000,
				"if_descr": "LAN",
				"is_reserved": "0",
				"type": "IA_PD",
				"prefix_len": "56"
			}
		],
		"interfaces": {"em0": "LAN"}
	}`

	mux := keaTestMux(t, v4Response, v6Response)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &keaCollector{subsystem: KeaSubsystem}
	c.Register("opnsense", "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	var sawV4Detail, sawV6Detail bool
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)

		if strings.Contains(desc, "dhcp4_lease_info") && labels["address"] == "192.168.1.10" {
			sawV4Detail = true
			if _, ok := labels["prefix_len"]; ok {
				t.Errorf("expected NO prefix_len label on dhcp4_lease_info (meaningless on v4), got %q", labels["prefix_len"])
			}
		}
		if strings.Contains(desc, "dhcp6_lease_info") && labels["address"] == "fd00:172:16:9::" {
			sawV6Detail = true
			if labels["prefix_len"] != "56" {
				t.Errorf("expected prefix_len label '56', got %q", labels["prefix_len"])
			}
		}
	}
	if !sawV4Detail {
		t.Error("expected to find the v4 detail metric")
	}
	if !sawV6Detail {
		t.Error("expected to find the v6 detail metric")
	}
}

// TestKeaCollector_Update_WithDetails_DuplicateSeriesGuard covers the
// cardinality risk flagged in #482: adding labels to a per-lease metric
// changes series identity, and a duplicate label tuple fails the WHOLE
// scrape (assertNoDuplicateSeries mirrors what a checked registry's
// Gather() would reject). Two v4 leases share every pre-existing label
// (hostname, hwaddr, interface) and differ ONLY in address plus the three
// new fields, pinning that the new labels never collapse two distinct
// leases onto one series or split what should be one series into two.
func TestKeaCollector_Update_WithDetails_DuplicateSeriesGuard(t *testing.T) {
	v4Response := `{
		"total": 2,
		"rowCount": 2,
		"current": 1,
		"rows": [
			{
				"address": "192.168.1.10",
				"hwaddr": "00:11:22:33:44:55",
				"hostname": "shared-name",
				"expire": 1772401000,
				"if_descr": "LAN",
				"is_reserved": "0",
				"mac_info": "",
				"client_id": "",
				"valid_lifetime": 0
			},
			{
				"address": "192.168.1.11",
				"hwaddr": "00:11:22:33:44:55",
				"hostname": "shared-name",
				"expire": 1772401000,
				"if_descr": "LAN",
				"is_reserved": "0",
				"mac_info": "Apple, Inc.",
				"client_id": "0100112233",
				"valid_lifetime": 7200
			}
		],
		"interfaces": {"em0": "LAN"}
	}`
	emptyV6 := `{"total":0,"rowCount":0,"current":1,"rows":[]}`

	mux := keaTestMux(t, v4Response, emptyV6)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &keaCollector{subsystem: KeaSubsystem}
	c.Register("opnsense", "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	detailCount := 0
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "dhcp4_lease_info") {
			detailCount++
		}
	}
	if detailCount != 2 {
		t.Errorf("expected 2 distinct dhcp4_lease_info series, got %d", detailCount)
	}
}
