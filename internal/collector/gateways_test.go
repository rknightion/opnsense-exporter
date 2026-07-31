package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
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
	expectedCount := 19
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
	expectedCount := 7
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

	// Enabled but monitor disabled: 1 info + 1 monitor + 5 new unconditional
	// (force_down, virtual, dynamic, monitor_killstates, monitor_killstates_priority)
	// + 1 priority + 1 status = 9. status is now emitted from the API-reported
	// value even without monitoring (#77).
	expectedCount := 9
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	foundStatus := false
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "gateways_status") {
			foundStatus = true
			if v := getMetricValue(m); v != 1 { // "Online" → 1
				t.Errorf("expected status=1 (Online) for monitor-disabled gateway, got %v", v)
			}
		}
	}
	if !foundStatus {
		t.Error("expected opnsense_gateways_status to be emitted for an enabled monitor-disabled gateway")
	}
}

// TestGatewaysCollector_DefaultGatewayMonitorDisabled reproduces the #77 blind
// spot: a default gateway with monitoring disabled (the live box's IPv6 PPPoE/
// DHCPv6-PD default gw). Before the fix no opnsense_gateways_status series
// existed for it, so OPNsenseGatewayDown could never fire.
func TestGatewaysCollector_DefaultGatewayMonitorDisabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1, "rowCount": 1, "current": 1,
			"rows": [
				{"disabled": false, "name": "WAN6_DHCP6", "descr": "IPv6 WAN",
				 "interface": "pppoe0", "ipprotocol": "inet6", "gateway": "fe80::1",
				 "defaultgw": true, "monitor_disable": "1", "monitor_noroute": "0",
				 "monitor": "", "force_down": "0", "priority": 255, "weight": "1",
				 "uuid": "v6-gw", "if": "wan6", "dynamic": true, "virtual": false,
				 "upstream": true, "interface_descr": "WAN6", "status": "Online",
				 "delay": "", "stddev": "", "loss": "", "label_class": "success"}
			]
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &gatewaysCollector{subsystem: GatewaysSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	found := false
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "gateways_status") {
			found = true
			if l := getMetricLabels(m); l["default_gateway"] != "true" {
				t.Errorf("expected default_gateway=true label, got %q", l["default_gateway"])
			}
		}
	}
	if !found {
		t.Fatal("no opnsense_gateways_status series for a monitor-disabled default gateway — OPNsenseGatewayDown blind spot (#77)")
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
	// 1 info + 3 bool metrics + 1 priority + 1 monitor + 2 monitor_killstates* = 9
	expectedCount := 9
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
	// 1 info + 3 bool metrics + 1 priority + 1 monitor + 2 monitor_killstates* = 9
	expectedCount := 9
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
	// 1 info + 5 bool metrics (force_down, virtual, dynamic, monitor_killstates,
	// monitor_killstates_priority) + 1 monitor = 7 (no priority)
	expectedCount := 8
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics (priority skipped when empty; status now always emitted), got %d", expectedCount, len(metrics))
	}

	// Verify force_down, virtual, dynamic are all 0 (false)
	for i, name := range []string{"force_down", "virtual", "dynamic"} {
		if v := getMetricValue(metrics[i+1]); v != 0.0 {
			t.Errorf("expected %s=0, got %f", name, v)
		}
	}
}

// When dpinger has no data yet ("~"), the opnsense layer returns -1 sentinels;
// the collector must skip rtt/rttd/loss instead of emitting -1.
func TestGatewaysCollector_Update_ProbeUnavailableSkipped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1,
			"rowCount": 1,
			"current": 1,
			"rows": [
				{
					"disabled": false,
					"name": "WARMUP_GW",
					"descr": "Warming up",
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
					"delay": "~",
					"stddev": "~",
					"loss": "~",
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

	// Same shape as TestGatewaysCollector_Update_EnabledWithMonitor (19 metrics)
	// minus rtt, rttd and loss_percentage (skipped): 16.
	expectedCount := 16
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics (rtt/rttd/loss skipped), got %d", expectedCount, len(metrics))
	}
	for i, m := range metrics {
		if v := getMetricValue(m); v == -1.0 {
			t.Errorf("metric %d has sentinel value -1; it should have been skipped", i)
		}
	}
}

// TestGatewaysCollector_Describe_CoversUpdateMetrics ensures Describe emits a
// descriptor for every metric Update can produce. A descriptor missing from
// Describe is invisible to docgen/-check and to strict prometheus registries.
func TestGatewaysCollector_Describe_CoversUpdateMetrics(t *testing.T) {
	c := &gatewaysCollector{subsystem: GatewaysSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	ch := make(chan *prometheus.Desc, 64)
	c.Describe(ch)
	close(ch)

	described := make([]string, 0, 32)
	for d := range ch {
		described = append(described, d.String())
	}

	wantNames := []string{
		"opnsense_gateways_info",
		"opnsense_gateways_monitor_info",
		"opnsense_gateways_rtt_milliseconds",
		"opnsense_gateways_rttd_milliseconds",
		"opnsense_gateways_rtt_low_milliseconds",
		"opnsense_gateways_rtt_high_milliseconds",
		"opnsense_gateways_loss_percentage",
		"opnsense_gateways_loss_low_percentage",
		"opnsense_gateways_loss_high_percentage",
		"opnsense_gateways_probe_interval_seconds",
		"opnsense_gateways_probe_period_seconds",
		"opnsense_gateways_probe_timeout_seconds",
		"opnsense_gateways_status",
		"opnsense_gateways_force_down",
		"opnsense_gateways_virtual",
		"opnsense_gateways_dynamic",
		"opnsense_gateways_priority",
		"opnsense_gateways_monitor_killstates",
		"opnsense_gateways_monitor_killstates_priority",
	}

	for _, name := range wantNames {
		found := false
		for _, desc := range described {
			if strings.Contains(desc, `fqName: "`+name+`"`) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Describe() does not emit descriptor for %s", name)
		}
	}
	if len(described) != len(wantNames) {
		t.Errorf("Describe() emitted %d descriptors, want %d", len(described), len(wantNames))
	}
}

// TestGatewaysCollector_Update_ThresholdInvalidSkipped verifies that empty or
// unparseable threshold/probe configuration values are skipped (with a debug
// log) rather than emitted as a misleading 0.
func TestGatewaysCollector_Update_ThresholdInvalidSkipped(t *testing.T) {
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
					"latencylow": "abc",
					"current_latencylow": "",
					"latencyhigh": "",
					"current_latencyhigh": "",
					"losslow": "",
					"current_losslow": "",
					"losshigh": "",
					"current_losshigh": "",
					"interval": "",
					"current_interval": "",
					"time_period": "",
					"current_time_period": "",
					"loss_interval": "",
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

	// All 7 threshold metrics (rttLow/rttHigh/lossLow/lossHigh/interval/period/
	// timeout) are skipped because their values are empty or unparseable:
	// 19 (full monitor case) - 7 = 12.
	expectedCount := 12
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics (invalid thresholds skipped), got %d", expectedCount, len(metrics))
	}

	// None of the emitted threshold-related descriptors should be present.
	for _, m := range metrics {
		desc := m.Desc().String()
		for _, skipped := range []string{
			"opnsense_gateways_rtt_low_milliseconds",
			"opnsense_gateways_rtt_high_milliseconds",
			"opnsense_gateways_loss_low_percentage",
			"opnsense_gateways_loss_high_percentage",
			"opnsense_gateways_probe_interval_seconds",
			"opnsense_gateways_probe_period_seconds",
			"opnsense_gateways_probe_timeout_seconds",
		} {
			if strings.Contains(desc, `fqName: "`+skipped+`"`) {
				t.Errorf("threshold metric %s should have been skipped for invalid/empty value", skipped)
			}
		}
	}
}

// TestGatewaysCollector_MonitorKillStates guards #584: monitor_killstates and
// monitor_killstates_priority must surface as their own 0/1 gauges, keyed the
// same way (name, address) as the pre-existing force_down/virtual/dynamic
// gauges, and emitted UNCONDITIONALLY per gateway -- same convention as those
// three siblings, not gated behind Enabled/MonitorEnabled.
func TestGatewaysCollector_MonitorKillStates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1, "rowCount": 1, "current": 1,
			"rows": [
				{"disabled": false, "name": "WAN_GW", "descr": "WAN Gateway",
				 "interface": "igb0", "ipprotocol": "inet", "gateway": "1.2.3.4",
				 "defaultgw": true, "monitor_disable": "0", "monitor_noroute": "0",
				 "monitor_killstates": "1", "monitor_killstates_priority": "0",
				 "monitor": "1.1.1.1", "force_down": "0", "priority": 255, "weight": "1",
				 "uuid": "abc-123", "if": "wan", "dynamic": false, "virtual": false,
				 "upstream": true, "interface_descr": "WAN", "status": "Online",
				 "delay": "1.2 ms", "stddev": "0.3 ms", "loss": "0.0 %", "label_class": "success"}
			]
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &gatewaysCollector{subsystem: GatewaysSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	var killStates, killStatesPriority *float64
	var killStatesLabels map[string]string
	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, `fqName: "opnsense_gateways_monitor_killstates"`) {
			v := getMetricValue(m)
			killStates = &v
			killStatesLabels = getMetricLabels(m)
		}
		if strings.Contains(desc, `fqName: "opnsense_gateways_monitor_killstates_priority"`) {
			v := getMetricValue(m)
			killStatesPriority = &v
		}
	}
	if killStates == nil {
		t.Fatal("expected opnsense_gateways_monitor_killstates to be emitted")
	}
	if *killStates != 1 {
		t.Errorf("expected monitor_killstates=1, got %v", *killStates)
	}
	if killStatesLabels["name"] != "WAN_GW" || killStatesLabels["address"] != "1.2.3.4" {
		t.Errorf("expected name=WAN_GW address=1.2.3.4, got %+v", killStatesLabels)
	}
	if killStatesPriority == nil {
		t.Fatal("expected opnsense_gateways_monitor_killstates_priority to be emitted")
	}
	if *killStatesPriority != 0 {
		t.Errorf("expected monitor_killstates_priority=0, got %v", *killStatesPriority)
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
