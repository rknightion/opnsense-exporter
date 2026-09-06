package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestArpTableCollector_Update(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"mac": "00:11:22:33:44:55",
					"ip": "192.168.1.1",
					"intf": "igb0",
					"type": "ethernet",
					"manufacturer": "TestCorp",
					"hostname": "gateway",
					"intf_description": "LAN",
					"permanent": false,
					"expired": false,
					"expires": 1200
				},
				{
					"mac": "AA:BB:CC:DD:EE:FF",
					"ip": "192.168.1.2",
					"intf": "igb0",
					"type": "ethernet",
					"manufacturer": "OtherCorp",
					"hostname": "server",
					"intf_description": "LAN",
					"permanent": true,
					"expired": false,
					"expires": 0
				}
			],
			"total": 2,
			"rowCount": 2,
			"current": 1
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	// Details ON: aggregate (1) + 2 per-entry = 3 metrics.
	c := &arpTableCollector{subsystem: ArpTableSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)

	var total *float64
	perEntry := 0
	for _, m := range metrics {
		if hasFqName(m, "opnsense_arp_table_table_entries") {
			v := getMetricValue(m)
			total = &v
			continue
		}
		perEntry++
		if getMetricValue(m) != 1 {
			t.Errorf("expected per-entry metric value 1, got %f", getMetricValue(m))
		}
	}
	if total == nil || *total != 2 {
		t.Errorf("table_entries = %v, want 2", total)
	}
	if perEntry != 2 {
		t.Errorf("expected 2 per-entry ARP metrics with details on, got %d", perEntry)
	}
}

// TestArpTableCollector_DetailsGating covers #125: details off (default) emits only the
// aggregate; details on adds the per-entry series.
func TestArpTableCollector_DetailsGating(t *testing.T) {
	body := `{"rows":[{"mac":"00:11:22:33:44:55","ip":"192.168.1.1","intf_description":"LAN"}],"total":1,"rowCount":1,"current":1}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(body))
	}))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	// Default (details off): only the aggregate.
	off := &arpTableCollector{subsystem: ArpTableSubsystem}
	off.Register(namespace, "test", promslog.NewNopLogger())
	m := collectMetrics(t, off, client)
	if len(m) != 1 || !hasFqName(m[0], "opnsense_arp_table_table_entries") {
		t.Errorf("details-off should emit only the aggregate, got %d metrics", len(m))
	}

	// Details on: aggregate + per-entry.
	on := &arpTableCollector{subsystem: ArpTableSubsystem}
	on.Register(namespace, "test", promslog.NewNopLogger())
	on.SetDetailsEnabled(true)
	m = collectMetrics(t, on, client)
	var sawPerEntry bool
	for _, x := range m {
		if hasFqName(x, "opnsense_arp_table_entries") && !hasFqName(x, "opnsense_arp_table_table_entries") {
			sawPerEntry = true
		}
	}
	if !sawPerEntry {
		t.Error("details-on should emit per-entry opnsense_arp_table_entries series")
	}
}

func TestArpTableCollector_Name(t *testing.T) {
	c := &arpTableCollector{subsystem: ArpTableSubsystem}
	if c.Name() != ArpTableSubsystem {
		t.Errorf("expected %s, got %s", ArpTableSubsystem, c.Name())
	}
}

// #534: manufacturer is populated on the overwhelming majority of entries while
// hostname is empty on every one, so the label set has to carry it. #544 adds
// the raw device alongside the description.
func TestArpTableCollector_ManufacturerAndDeviceLabels(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"total":2,"rowCount":2,"current":1,"rows":[
		 {"mac":"48:25:67:13:97:33","ip":"10.0.0.139","intf":"ixl0","type":"ethernet",
		  "manufacturer":"Poly","hostname":"","intf_description":"LAN",
		  "permanent":false,"expired":false,"expires":1192},
		 {"mac":"00:11:32:aa:bb:cc","ip":"10.0.50.10","intf":"ixl0_vlan50","type":"ethernet",
		  "manufacturer":"","hostname":"","intf_description":"IOT",
		  "permanent":false,"expired":false,"expires":900}
		]}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &arpTableCollector{subsystem: ArpTableSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	seen := 0
	for _, m := range collectMetrics(t, c, client) {
		if !hasFqName(m, "opnsense_arp_table_entries") {
			continue
		}
		labels := getMetricLabels(m)
		switch labels["ip"] {
		case "10.0.0.139":
			seen++
			if labels["manufacturer"] != "Poly" {
				t.Errorf("manufacturer = %q, want Poly", labels["manufacturer"])
			}
			if labels["device"] != "ixl0" {
				t.Errorf("device = %q, want ixl0", labels["device"])
			}
		case "10.0.50.10":
			seen++
			// An unresolved OUI must still emit the series with an empty label.
			if labels["manufacturer"] != "" {
				t.Errorf("manufacturer = %q, want empty", labels["manufacturer"])
			}
			// The VLAN case: device and description genuinely differ.
			if labels["device"] != "ixl0_vlan50" || labels["interface_description"] != "IOT" {
				t.Errorf("device/description = %q/%q", labels["device"], labels["interface_description"])
			}
		}
	}
	if seen != 2 {
		t.Fatalf("matched %d per-entry series, want 2", seen)
	}
}
