package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
	// 1 info + 1 monitor + 10 monitoring metrics (rtt, rttd, rttLow, rttHigh, loss, lossLow, lossHigh, interval, period, timeout) + 1 status = 13
	expectedCount := 13
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

	// Disabled gateway: only 1 info metric (no monitor, no monitoring metrics, no status)
	expectedCount := 1
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

	// Enabled but monitor disabled: 1 info + 1 monitor = 2
	expectedCount := 2
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestGatewaysCollector_Name(t *testing.T) {
	c := &gatewaysCollector{subsystem: GatewaysSubsystem}
	if c.Name() != GatewaysSubsystem {
		t.Errorf("expected %s, got %s", GatewaysSubsystem, c.Name())
	}
}
