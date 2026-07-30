package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestDnsmasqCollector_Update_NoDetails(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/dnsmasq/leases/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 3,
			"rowCount": 3,
			"current": 1,
			"rows": [
				{
					"expire": 1700001000,
					"hwaddr": "00:11:22:33:44:55",
					"iaid": "",
					"address": "192.168.1.10",
					"hostname": "desktop",
					"client_id": "",
					"if": "igb1",
					"if_descr": "LAN",
					"if_name": "igb1",
					"mac_info": "",
					"is_reserved": "1"
				},
				{
					"expire": 1700002000,
					"hwaddr": "AA:BB:CC:DD:EE:FF",
					"iaid": "",
					"address": "192.168.1.20",
					"hostname": "phone",
					"client_id": "",
					"if": "igb1",
					"if_descr": "LAN",
					"if_name": "igb1",
					"mac_info": "",
					"is_reserved": "0"
				},
				{
					"expire": 1700003000,
					"hwaddr": "11:22:33:44:55:66",
					"iaid": "",
					"address": "10.0.0.10",
					"hostname": "iot-device",
					"client_id": "",
					"if": "igb2",
					"if_descr": "IOT",
					"if_name": "igb2",
					"mac_info": "",
					"is_reserved": "0"
				}
			],
			"interfaces": {"igb1": "LAN", "igb2": "IOT"}
		}`))
	})

	mux.HandleFunc("/api/dnsmasq/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "running"}`))
	})
	mux.HandleFunc("/api/dnsmasq/settings/searchRange", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[
			{"uuid":"u1","interface":"igb1","%interface":"LAN","start_addr":"192.168.1.100","end_addr":"192.168.1.200"},
			{"uuid":"u2","interface":"igb2","%interface":"IOT","start_addr":"10.0.0.100","end_addr":"10.0.0.150"}
		],"rowCount":2,"total":2,"current":1}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &dnsmasqCollector{subsystem: DnsmasqSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	// detailsEnabled is false by default

	metrics := collectMetrics(t, c, client)

	// 1 leasesTotal + 1 reservedTotal + 1 dynamicTotal + 2 leasesByIface (LAN, IOT) + 1 serviceRunning + 2 pool_size (LAN, IOT) = 8
	expectedCount := 8
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestDnsmasqCollector_Update_WithDetails(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/dnsmasq/leases/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 2,
			"rowCount": 2,
			"current": 1,
			"rows": [
				{
					"expire": 1700001000,
					"hwaddr": "00:11:22:33:44:55",
					"iaid": "",
					"address": "192.168.1.10",
					"hostname": "desktop",
					"client_id": "",
					"if": "igb1",
					"if_descr": "LAN",
					"if_name": "igb1",
					"mac_info": "Dell Inc.",
					"is_reserved": "1"
				},
				{
					"expire": 1700002000,
					"hwaddr": "AA:BB:CC:DD:EE:FF",
					"iaid": "",
					"address": "192.168.1.20",
					"hostname": "phone",
					"client_id": "",
					"if": "igb1",
					"if_descr": "LAN",
					"if_name": "igb1",
					"mac_info": "",
					"is_reserved": "0"
				}
			],
			"interfaces": {"igb1": "LAN"}
		}`))
	})

	mux.HandleFunc("/api/dnsmasq/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "running"}`))
	})
	mux.HandleFunc("/api/dnsmasq/settings/searchRange", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[
			{"uuid":"u1","interface":"igb1","%interface":"LAN","start_addr":"192.168.1.100","end_addr":"192.168.1.200"}
		],"rowCount":1,"total":1,"current":1}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &dnsmasqCollector{subsystem: DnsmasqSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)

	// 1 leasesTotal + 1 reservedTotal + 1 dynamicTotal + 1 leasesByIface (LAN) + 2 leaseInfo + 1 serviceRunning + 1 pool_size (LAN) = 8
	expectedCount := 8
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	foundReserved := false
	for _, m := range metrics {
		if !strings.Contains(m.Desc().String(), "lease_info") {
			continue
		}
		labels := getMetricLabels(m)
		if labels["address"] != "192.168.1.10" {
			continue
		}
		foundReserved = true
		if labels["device"] != "igb1" {
			t.Errorf("expected device 'igb1', got %q", labels["device"])
		}
		if labels["vendor"] != "Dell Inc." {
			t.Errorf("expected vendor 'Dell Inc.', got %q", labels["vendor"])
		}
	}
	if !foundReserved {
		t.Error("expected lease_info for 192.168.1.10")
	}
}

func TestDnsmasqCollector_Name(t *testing.T) {
	c := &dnsmasqCollector{subsystem: DnsmasqSubsystem}
	if c.Name() != DnsmasqSubsystem {
		t.Errorf("expected %s, got %s", DnsmasqSubsystem, c.Name())
	}
}

func TestDnsmasqCollector_PoolSize(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/dnsmasq/leases/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	mux.HandleFunc("/api/dnsmasq/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	mux.HandleFunc("/api/dnsmasq/settings/searchRange", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[
			{"uuid":"u1","interface":"lan","%interface":"LAN","start_addr":"10.0.0.110","end_addr":"10.0.0.240"},
			{"uuid":"u2","interface":"lan","%interface":"LAN","start_addr":"10.0.0.50","end_addr":"10.0.0.59"}
		],"rowCount":2,"total":2,"current":1}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &dnsmasqCollector{subsystem: DnsmasqSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	var sawPool bool
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "dnsmasq_pool_size") {
			sawPool = true
			labels := getMetricLabels(m)
			// two LAN ranges summed: 131 + 10 = 141
			if labels["interface"] != "LAN" || getMetricValue(m) != 141 {
				t.Errorf("bad pool_size: value=%v labels=%v", getMetricValue(m), labels)
			}
		}
	}
	if !sawPool {
		t.Error("missing dnsmasq_pool_size metric")
	}
}
