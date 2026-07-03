package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestCarpCollector_Update_WithVIPs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"interface": "LAN",
					"vhid": "1",
					"advbase": "1",
					"advskew": "0",
					"status": "MASTER",
					"status_txt": "MASTER",
					"subnet": "10.0.0.1"
				},
				{
					"interface": "WAN",
					"vhid": "2",
					"advbase": "2",
					"advskew": "100",
					"status": "BACKUP",
					"status_txt": "BACKUP",
					"subnet": "192.168.1.1"
				}
			],
			"carp": {
				"demotion": "0",
				"allow": "1",
				"maintenancemode": false
			}
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &carpCollector{subsystem: CARPSubsystem}
	c.Register("opnsense", "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 4 global (demotion, allow, maintenance_mode, vips_total) + 2 VIPs * 3 metrics each (status, advbase, advskew) = 10
	expectedCount := 10
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Verify global metric values
	// metrics[0] = demotion
	if v := getMetricValue(metrics[0]); v != 0 {
		t.Errorf("expected demotion=0, got %f", v)
	}
	// metrics[1] = allow
	if v := getMetricValue(metrics[1]); v != 1.0 {
		t.Errorf("expected allow=1, got %f", v)
	}
	// metrics[2] = maintenance_mode
	if v := getMetricValue(metrics[2]); v != 0 {
		t.Errorf("expected maintenance_mode=0, got %f", v)
	}
	// metrics[3] = vips_total
	if v := getMetricValue(metrics[3]); v != 2 {
		t.Errorf("expected vips_total=2, got %f", v)
	}

	// Verify first VIP labels
	labels := getMetricLabels(metrics[4])
	if labels["interface"] != "LAN" {
		t.Errorf("expected interface='LAN', got %q", labels["interface"])
	}
	if labels["vhid"] != "1" {
		t.Errorf("expected vhid='1', got %q", labels["vhid"])
	}
	if labels["vip"] != "10.0.0.1" {
		t.Errorf("expected vip='10.0.0.1', got %q", labels["vip"])
	}

	// Verify first VIP status value (MASTER = 1)
	if v := getMetricValue(metrics[4]); v != 1 {
		t.Errorf("expected vip_status=1 (MASTER), got %f", v)
	}
	// Verify first VIP advbase value
	if v := getMetricValue(metrics[5]); v != 1 {
		t.Errorf("expected vip_advbase_seconds=1, got %f", v)
	}
	// Verify first VIP advskew value
	if v := getMetricValue(metrics[6]); v != 0 {
		t.Errorf("expected vip_advskew=0, got %f", v)
	}

	// Verify second VIP status value (BACKUP = 0)
	if v := getMetricValue(metrics[7]); v != 0 {
		t.Errorf("expected vip_status=0 (BACKUP), got %f", v)
	}
}

func TestCarpCollector_Update_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 0,
			"rowCount": 0,
			"current": 1,
			"rows": [],
			"carp": {
				"demotion": "0",
				"allow": "1",
				"maintenancemode": false,
				"status_msg": "Could not locate any defined CARP interfaces."
			}
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &carpCollector{subsystem: CARPSubsystem}
	c.Register("opnsense", "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 4 global metrics only (demotion, allow, maintenance_mode, vips_total)
	expectedCount := 4
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// vips_total should be 0
	if v := getMetricValue(metrics[3]); v != 0 {
		t.Errorf("expected vips_total=0, got %f", v)
	}
}

// TestCarpCollector_MultiAddressVHIDStaysDistinct reproduces the #166 duplicate:
// getVipStatusAction emits one row per address (ipv4 + ipv6) for a vhid, sharing
// interface/vhid. With the VIP address sourced from "subnet", the two rows keep
// distinct (interface, vhid, vip) tuples instead of colliding on an empty vip and
// 500-ing the whole scrape.
func TestCarpCollector_MultiAddressVHIDStaysDistinct(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{"interface":"LAN","vhid":"1","advbase":"1","advskew":"0","status":"MASTER","status_txt":"MASTER","subnet":"10.0.0.1"},
				{"interface":"LAN","vhid":"1","advbase":"1","advskew":"0","status":"MASTER","status_txt":"MASTER","subnet":"fd00::1"}
			],
			"carp": {"demotion":"0","allow":"1","maintenancemode":false}
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &carpCollector{subsystem: CARPSubsystem}
	c.Register("opnsense", "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	vips := map[string]bool{}
	for _, m := range metrics {
		l := getMetricLabels(m)
		if v, ok := l["vip"]; ok {
			if v == "" {
				t.Errorf("expected a non-empty vip label (from subnet), got empty: %v", l)
			}
			vips[v] = true
		}
	}
	if len(vips) != 2 {
		t.Errorf("expected 2 distinct vip addresses, got %d: %v", len(vips), vips)
	}
}

func TestCarpCollector_Name(t *testing.T) {
	c := &carpCollector{subsystem: CARPSubsystem}
	if c.Name() != CARPSubsystem {
		t.Errorf("expected %s, got %s", CARPSubsystem, c.Name())
	}
}
