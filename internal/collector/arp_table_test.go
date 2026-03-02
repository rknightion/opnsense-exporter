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

	c := &arpTableCollector{subsystem: ArpTableSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 2 ARP entries = 2 metrics
	expectedCount := 2
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// All ARP entries have a value of 1
	for _, m := range metrics {
		if getMetricValue(m) != 1 {
			t.Errorf("expected metric value 1, got %f", getMetricValue(m))
		}
	}
}

func TestArpTableCollector_Name(t *testing.T) {
	c := &arpTableCollector{subsystem: ArpTableSubsystem}
	if c.Name() != ArpTableSubsystem {
		t.Errorf("expected %s, got %s", ArpTableSubsystem, c.Name())
	}
}
