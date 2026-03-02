package collector

import (
	"net/http"
	"net/http/httptest"
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

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &dnsmasqCollector{subsystem: DnsmasqSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	// detailsEnabled is false by default

	metrics := collectMetrics(t, c, client)

	// 1 leasesTotal + 1 reservedTotal + 1 dynamicTotal + 2 leasesByIface (LAN, IOT) + 1 serviceRunning = 6
	expectedCount := 6
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
				}
			],
			"interfaces": {"igb1": "LAN"}
		}`))
	})

	mux.HandleFunc("/api/dnsmasq/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "running"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &dnsmasqCollector{subsystem: DnsmasqSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)

	// 1 leasesTotal + 1 reservedTotal + 1 dynamicTotal + 1 leasesByIface (LAN) + 2 leaseInfo + 1 serviceRunning = 7
	expectedCount := 7
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestDnsmasqCollector_Name(t *testing.T) {
	c := &dnsmasqCollector{subsystem: DnsmasqSubsystem}
	if c.Name() != DnsmasqSubsystem {
		t.Errorf("expected %s, got %s", DnsmasqSubsystem, c.Name())
	}
}
