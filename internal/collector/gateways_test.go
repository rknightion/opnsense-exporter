package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
)

func TestGatewaysCollector_Update_EnabledWithMonitor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1,
			"rowCount": 1,
			"current": 1,
			"rows": [
				{
					"disabled": false,
					"name": "WAN_GW",
					"descr": "WAN Gateway",
					"interface": "igb0",
					"ipprotocol": "inet",
					"gateway": "1.2.3.4",
					"defaultgw": true,
					"fargw": "",
					"monitor_disable": "0",
					"monitor_noroute": "0",
					"monitor": "1.1.1.1",
					"force_down": "0",
					"priority": 255,
					"weight": "1",
					"latencylow": "200",
					"current_latencylow": "",
					"latencyhigh": "500",
					"current_latencyhigh": "",
					"losslow": "10",
					"current_losslow": "",
					"losshigh": "20",
					"current_losshigh": "",
					"interval": "1",
					"current_interval": "",
					"time_period": "60",
					"current_time_period": "",
					"loss_interval": "4",
					"current_loss_interval": "",
					"data_length": "",
					"current_data_length": "",
					"uuid": "abc-123",
					"if": "wan",
					"attribute": 1,
					"dynamic": false,
					"virtual": false,
					"upstream": true,
					"interface_descr": "WAN",
					"status": "Online",
					"delay": "1.2 ms",
					"stddev": "0.3 ms",
					"loss": "0.0 %",
					"label_class": "success"
				}
			]
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &gatewaysCollector{subsystem: GatewaysSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// For an enabled gateway with monitoring enabled:
	// 1 info + 1 monitor + 10 monitoring metrics (rtt, rttd, rttLow, rttHigh, loss, lossLow, lossHigh, interval, period, timeout) + 1 status
	// + 3 new unconditional (force_down, virtual, dynamic) + 1 priority = 17
	expectedCount := 17
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestGatewaysCollector_Update_Disabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1,
			"rowCount": 1,
			"current": 1,
			"rows": [
				{
					"disabled": true,
					"name": "WAN_GW_DISABLED",
					"descr": "Disabled Gateway",
					"interface": "igb1",
					"ipprotocol": "inet",
					"gateway": "10.0.0.1",
					"defaultgw": false,
					"fargw": "",
					"monitor_disable": "1",
					"monitor_noroute": "0",
					"monitor": "",
					"force_down": "0",
					"priority": 255,
					"weight": "1",
					"latencylow": "",
					"current_latencylow": "200",
					"latencyhigh": "",
					"current_latencyhigh": "500",
					"losslow": "",
					"current_losslow": "10",
					"losshigh": "",
					"current_losshigh": "20",
					"interval": "",
					"current_interval": "1",
					"time_period": "",
					"current_time_period": "60",
					"loss_interval": "",
					"current_loss_interval": "4",
					"data_length": "",
					"current_data_length": "",
					"uuid": "def-456",
					"if": "opt1",
					"attribute": 2,
					"dynamic": false,
					"virtual": false,
					"upstream": false,
					"interface_descr": "OPT1",
					"status": "Offline",
					"delay": "",
					"stddev": "",
					"loss": "",
					"label_class": "danger"
				}
			]
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &gatewaysCollector{subsystem: GatewaysSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Disabled gateway: 1 info + 3 new unconditional (force_down, virtual, dynamic) + 1 priority = 5
	// (no monitor, no monitoring metrics, no status)
	expectedCount := 5
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestGatewaysCollector_Update_EnabledWithoutMonitor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1,
			"rowCount": 1,
			"current": 1,
			"rows": [
				{
					"disabled": false,
					"name": "WAN_GW_NOMON",
					"descr": "Gateway No Monitor",
					"interface": "igb0",
					"ipprotocol": "inet",
					"gateway": "1.2.3.4",
					"defaultgw": false,
					"fargw": "",
					"monitor_disable": "1",
					"monitor_noroute": "0",
					"monitor": "",
					"force_down": "0",
					"priority": 255,
					"weight": "1",
					"latencylow": "200",
					"current_latencylow": "",
					"latencyhigh": "500",
					"current_latencyhigh": "",
					"losslow": "10",
					"current_losslow": "",
					"losshigh": "20",
					"current_losshigh": "",
					"interval": "1",
					"current_interval": "",
					"time_period": "60",
					"current_time_period": "",
					"loss_interval": "4",
					"current_loss_interval": "",
					"data_length": "",
					"current_data_length": "",
					"uuid": "ghi-789",
					"if": "wan",
					"attribute": 1,
					"dynamic": false,
					"virtual": false,
					"upstream": true,
					"interface_descr": "WAN",
					"status": "Online",
					"delay": "",
					"stddev": "",
					"loss": "",
					"label_class": "success"
				}
			]
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &gatewaysCollector{subsystem: GatewaysSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Enabled but monitor disabled: 1 info + 1 monitor + 3 new unconditional (force_down, virtual, dynamic) + 1 priority = 6
	expectedCount := 6
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestGatewaysCollector_Update_NewMetrics_BoolFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1,
			"rowCount": 1,
			"current": 1,
			"rows": [
				{
					"disabled": false,
					"name": "VPN_GW",
					"descr": "VPN Gateway",
					"interface": "tun0",
					"ipprotocol": "inet",
					"gateway": "10.10.0.1",
					"defaultgw": false,
					"fargw": "1",
					"monitor_disable": "1",
					"monitor_noroute": "0",
					"monitor": "",
					"force_down": "1",
					"priority": 10,
					"weight": "1",
					"latencylow": "200",
					"current_latencylow": "",
					"latencyhigh": "500",
					"current_latencyhigh": "",
					"losslow": "10",
					"current_losslow": "",
					"losshigh": "20",
					"current_losshigh": "",
					"interval": "1",
					"current_interval": "",
					"time_period": "60",
					"current_time_period": "",
					"loss_interval": "4",
					"current_loss_interval": "",
					"data_length": "",
					"current_data_length": "",
					"uuid": "zzz-999",
					"if": "vpn",
					"attribute": 0,
					"dynamic": true,
					"virtual": true,
					"upstream": false,
					"interface_descr": "VPN",
					"status": "Online",
					"delay": "",
					"stddev": "",
					"loss": "",
					"label_class": "success"
				}
			]
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &gatewaysCollector{subsystem: GatewaysSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Enabled, monitor disabled, force_down=true, virtual=true, dynamic=true, priority=10
	// 1 info + 3 bool metrics + 1 priority + 1 monitor = 6
	expectedCount := 6
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// metrics[0] = info
	// metrics[1] = force_down (should be 1.0)
	if v := getMetricValue(metrics[1]); v != 1.0 {
		t.Errorf("expected force_down=1 (force_down true), got %f", v)
	}
	labels := getMetricLabels(metrics[1])
	if labels["name"] != "VPN_GW" {
		t.Errorf("expected name='VPN_GW', got %q", labels["name"])
	}
	if labels["address"] != "10.10.0.1" {
		t.Errorf("expected address='10.10.0.1', got %q", labels["address"])
	}

	// metrics[2] = virtual (should be 1.0)
	if v := getMetricValue(metrics[2]); v != 1.0 {
		t.Errorf("expected virtual=1 (virtual true), got %f", v)
	}

	// metrics[3] = dynamic (should be 1.0)
	if v := getMetricValue(metrics[3]); v != 1.0 {
		t.Errorf("expected dynamic=1 (dynamic true), got %f", v)
	}

	// metrics[4] = priority (should be 10.0)
	if v := getMetricValue(metrics[4]); v != 10.0 {
		t.Errorf("expected priority=10, got %f", v)
	}
	priorityLabels := getMetricLabels(metrics[4])
	if priorityLabels["name"] != "VPN_GW" {
		t.Errorf("expected name='VPN_GW', got %q", priorityLabels["name"])
	}
	if priorityLabels["address"] != "10.10.0.1" {
		t.Errorf("expected address='10.10.0.1', got %q", priorityLabels["address"])
	}
}

func TestGatewaysCollector_Update_NewMetrics_ZeroBools(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1,
			"rowCount": 1,
			"current": 1,
			"rows": [
				{
					"disabled": false,
					"name": "LAN_GW",
					"descr": "LAN Gateway",
					"interface": "em0",
					"ipprotocol": "inet",
					"gateway": "192.168.1.1",
					"defaultgw": false,
					"fargw": "",
					"monitor_disable": "1",
					"monitor_noroute": "0",
					"monitor": "",
					"force_down": "0",
					"priority": 255,
					"weight": "1",
					"latencylow": "200",
					"current_latencylow": "",
					"latencyhigh": "500",
					"current_latencyhigh": "",
					"losslow": "10",
					"current_losslow": "",
					"losshigh": "20",
					"current_losshigh": "",
					"interval": "1",
					"current_interval": "",
					"time_period": "60",
					"current_time_period": "",
					"loss_interval": "4",
					"current_loss_interval": "",
					"data_length": "",
					"current_data_length": "",
					"uuid": "lan-001",
					"if": "lan",
					"attribute": 0,
					"dynamic": false,
					"virtual": false,
					"upstream": false,
					"interface_descr": "LAN",
					"status": "Online",
					"delay": "",
					"stddev": "",
					"loss": "",
					"label_class": "success"
				}
			]
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &gatewaysCollector{subsystem: GatewaysSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Enabled, monitor disabled, force_down=false, virtual=false, dynamic=false, priority=255
	// 1 info + 3 bool metrics + 1 priority + 1 monitor = 6
	expectedCount := 6
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// metrics[1] = force_down (should be 0.0)
	if v := getMetricValue(metrics[1]); v != 0.0 {
		t.Errorf("expected force_down=0, got %f", v)
	}
	// metrics[2] = virtual (should be 0.0)
	if v := getMetricValue(metrics[2]); v != 0.0 {
		t.Errorf("expected virtual=0, got %f", v)
	}
	// metrics[3] = dynamic (should be 0.0)
	if v := getMetricValue(metrics[3]); v != 0.0 {
		t.Errorf("expected dynamic=0, got %f", v)
	}
	// metrics[4] = priority (should be 255.0)
	if v := getMetricValue(metrics[4]); v != 255.0 {
		t.Errorf("expected priority=255, got %f", v)
	}
}

func TestGatewaysCollector_Update_Priority_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1,
			"rowCount": 1,
			"current": 1,
			"rows": [
				{
					"disabled": false,
					"name": "WAN_GW_NOPRI",
					"descr": "No Priority Gateway",
					"interface": "igb0",
					"ipprotocol": "inet",
					"gateway": "5.6.7.8",
					"defaultgw": false,
					"fargw": "",
					"monitor_disable": "1",
					"monitor_noroute": "0",
					"monitor": "",
					"force_down": "0",
					"priority": "",
					"weight": "1",
					"latencylow": "200",
					"current_latencylow": "",
					"latencyhigh": "500",
					"current_latencyhigh": "",
					"losslow": "10",
					"current_losslow": "",
					"losshigh": "20",
					"current_losshigh": "",
					"interval": "1",
					"current_interval": "",
					"time_period": "60",
					"current_time_period": "",
					"loss_interval": "4",
					"current_loss_interval": "",
					"data_length": "",
					"current_data_length": "",
					"uuid": "nopri-001",
					"if": "wan",
					"attribute": 0,
					"dynamic": false,
					"virtual": false,
					"upstream": false,
					"interface_descr": "WAN",
					"status": "Online",
					"delay": "",
					"stddev": "",
					"loss": "",
					"label_class": "success"
				}
			]
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &gatewaysCollector{subsystem: GatewaysSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Enabled, monitor disabled, priority="" (empty) — priority metric must be skipped
	// 1 info + 3 bool metrics (force_down, virtual, dynamic) + 1 monitor = 5 (no priority)
	expectedCount := 5
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics (priority skipped when empty), got %d", expectedCount, len(metrics))
	}

	// Verify force_down, virtual, dynamic are all 0 (false)
	for i, name := range []string{"force_down", "virtual", "dynamic"} {
		if v := getMetricValue(metrics[i+1]); v != 0.0 {
			t.Errorf("expected %s=0, got %f", name, v)
		}
	}
}

func TestGatewaysCollector_Name(t *testing.T) {
	c := &gatewaysCollector{subsystem: GatewaysSubsystem}
	if c.Name() != GatewaysSubsystem {
		t.Errorf("expected %s, got %s", GatewaysSubsystem, c.Name())
	}
}

// TestGatewaysCollector_InfoLabels_DeviceInterface verifies the device/interface
// label mapping, pinned against real OPNsense 26.1 data: the API returns
// "interface" as the OPNsense interface assignment (e.g. opt7) and "if" as the
// OS network device (e.g. pppoe0). The "device" label must carry the OS device
// (JSON "if") and the "interface" label must carry the OPNsense assignment
// (JSON "interface"). Note the struct field names are misleadingly inverted.
func TestGatewaysCollector_InfoLabels_DeviceInterface(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1,
			"rowCount": 1,
			"current": 1,
			"rows": [
				{
					"disabled": false,
					"name": "WAN_GW",
					"descr": "WAN Gateway",
					"interface": "opt7",
					"ipprotocol": "inet",
					"gateway": "1.2.3.4",
					"defaultgw": true,
					"fargw": "",
					"monitor_disable": "1",
					"monitor_noroute": "0",
					"monitor": "",
					"force_down": "0",
					"priority": 255,
					"weight": "1",
					"latencylow": "200",
					"current_latencylow": "",
					"latencyhigh": "500",
					"current_latencyhigh": "",
					"losslow": "10",
					"current_losslow": "",
					"losshigh": "20",
					"current_losshigh": "",
					"interval": "1",
					"current_interval": "",
					"time_period": "60",
					"current_time_period": "",
					"loss_interval": "4",
					"current_loss_interval": "",
					"data_length": "",
					"current_data_length": "",
					"uuid": "abc-123",
					"if": "pppoe0",
					"attribute": 1,
					"dynamic": false,
					"virtual": false,
					"upstream": true,
					"interface_descr": "AAISP",
					"status": "Online",
					"delay": "",
					"stddev": "",
					"loss": "",
					"label_class": "success"
				}
			]
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &gatewaysCollector{subsystem: GatewaysSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Find the info metric (there should be exactly 1 since monitor is disabled).
	var infoMetric interface{ Write(*dto.Metric) error }
	for _, m := range metrics {
		labels := getMetricLabels(m)
		if _, ok := labels["device"]; ok {
			infoMetric = m
			break
		}
	}
	if infoMetric == nil {
		t.Fatal("could not find info metric with 'device' label")
	}

	labels := getMetricLabels(infoMetric.(prometheus.Metric))
	// JSON "if" (pppoe0) is the OS device → "device" label.
	if got := labels["device"]; got != "pppoe0" {
		t.Errorf("device label: expected %q (OS device, JSON \"if\"), got %q", "pppoe0", got)
	}
	// JSON "interface" (opt7) is the OPNsense assignment → "interface" label.
	if got := labels["interface"]; got != "opt7" {
		t.Errorf("interface label: expected %q (OPNsense interface, JSON \"interface\"), got %q", "opt7", got)
	}
}
