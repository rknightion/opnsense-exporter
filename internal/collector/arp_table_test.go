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
		if hasFqName(m, "opnsense_arp_table_entries_total") {
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
		t.Errorf("entries_total = %v, want 2", total)
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
	if len(m) != 1 || !hasFqName(m[0], "opnsense_arp_table_entries_total") {
		t.Errorf("details-off should emit only the aggregate, got %d metrics", len(m))
	}

	// Details on: aggregate + per-entry.
	on := &arpTableCollector{subsystem: ArpTableSubsystem}
	on.Register(namespace, "test", promslog.NewNopLogger())
	on.SetDetailsEnabled(true)
	m = collectMetrics(t, on, client)
	var sawPerEntry bool
	for _, x := range m {
		if hasFqName(x, "opnsense_arp_table_entries") && !hasFqName(x, "opnsense_arp_table_entries_total") {
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
