package opnsense

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

func TestFetchGateways_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"total": 2,
			"rowCount": 2,
			"current": 1,
			"rows": [
				{
					"disabled": false,
					"name": "WAN_GW",
					"descr": "WAN Gateway",
					"interface": "igb0",
					"ipprotocol": "inet",
					"gateway": "10.0.0.1",
					"defaultgw": true,
					"fargw": "",
					"monitor_disable": "0",
					"monitor_noroute": "0",
					"monitor": "10.0.0.1",
					"force_down": "0",
					"priority": 255,
					"weight": "1",
					"latencylow": "200",
					"current_latencylow": "200",
					"latencyhigh": "500",
					"current_latencyhigh": "500",
					"losslow": "10",
					"current_losslow": "10",
					"losshigh": "20",
					"current_losshigh": "20",
					"interval": "",
					"current_interval": "500",
					"time_period": "",
					"current_time_period": "60",
					"loss_interval": "",
					"current_loss_interval": "2500",
					"data_length": "",
					"current_data_length": "0",
					"uuid": "uuid-wan-gw",
					"if": "wan",
					"attribute": 1,
					"dynamic": false,
					"virtual": false,
					"upstream": true,
					"interface_descr": "WAN",
					"status": "Online",
					"delay": "1.5 ms",
					"stddev": "0.3 ms",
					"loss": "0.0 %",
					"label_class": "success"
				},
				{
					"disabled": true,
					"name": "BACKUP_GW",
					"descr": "Backup Gateway",
					"interface": "igb1",
					"ipprotocol": "inet",
					"gateway": "10.0.1.1",
					"defaultgw": false,
					"fargw": "10.0.1.254",
					"monitor_disable": "1",
					"monitor_noroute": "1",
					"monitor": "",
					"force_down": "1",
					"priority": "128",
					"weight": "2",
					"latencylow": "300",
					"current_latencylow": "300",
					"latencyhigh": "600",
					"current_latencyhigh": "600",
					"losslow": "15",
					"current_losslow": "15",
					"losshigh": "25",
					"current_losshigh": "25",
					"interval": "1000",
					"current_interval": "1000",
					"time_period": "120",
					"current_time_period": "120",
					"loss_interval": "5000",
					"current_loss_interval": "5000",
					"data_length": "1",
					"current_data_length": "1",
					"uuid": "uuid-backup-gw",
					"if": "opt1",
					"attribute": 2,
					"dynamic": true,
					"virtual": true,
					"upstream": false,
					"interface_descr": "BACKUP",
					"status": "Offline",
					"delay": "~",
					"stddev": "~",
					"loss": "~",
					"label_class": "danger"
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchGateways()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Gateways) != 2 {
		t.Fatalf("expected 2 gateways, got %d", len(data.Gateways))
	}

	// First gateway: online, monitoring enabled
	gw1 := data.Gateways[0]
	if gw1.Name != "WAN_GW" {
		t.Errorf("expected name 'WAN_GW', got %q", gw1.Name)
	}
	if gw1.Status != GatewayStatusOnline {
		t.Errorf("expected status GatewayStatusOnline, got %d", gw1.Status)
	}
	if !gw1.Enabled {
		t.Error("expected Enabled=true")
	}
	if !gw1.DefaultGateway {
		t.Error("expected DefaultGateway=true")
	}
	if !gw1.MonitorEnabled {
		t.Error("expected MonitorEnabled=true (monitor_disable=0)")
	}
	if gw1.Delay != 1.5 {
		t.Errorf("expected Delay=1.5, got %f", gw1.Delay)
	}
	if gw1.StdDev != 0.3 {
		t.Errorf("expected StdDev=0.3, got %f", gw1.StdDev)
	}
	if gw1.Loss != 0.0 {
		t.Errorf("expected Loss=0.0, got %f", gw1.Loss)
	}
	if gw1.Priority != "255" {
		t.Errorf("expected Priority='255', got %q", gw1.Priority)
	}

	// Fallback fields should be used when primary is empty
	if gw1.Interval != "500" {
		t.Errorf("expected Interval='500' (from current_interval fallback), got %q", gw1.Interval)
	}
	if gw1.TimePeriod != "60" {
		t.Errorf("expected TimePeriod='60' (from current_time_period fallback), got %q", gw1.TimePeriod)
	}
	if gw1.LossInterval != "2500" {
		t.Errorf("expected LossInterval='2500' (from current_loss_interval fallback), got %q", gw1.LossInterval)
	}
	if gw1.DataLength != "0" {
		t.Errorf("expected DataLength='0' (from current_data_length fallback), got %q", gw1.DataLength)
	}

	// Second gateway: disabled, monitor disabled -> delay/stddev/loss should be -1
	gw2 := data.Gateways[1]
	if gw2.Status != GatewayStatusOffline {
		t.Errorf("expected status GatewayStatusOffline, got %d", gw2.Status)
	}
	if gw2.Enabled {
		t.Error("expected Enabled=false for disabled gateway")
	}
	if gw2.Delay != -1.0 {
		t.Errorf("expected Delay=-1.0 for disabled gateway, got %f", gw2.Delay)
	}
	if gw2.StdDev != -1.0 {
		t.Errorf("expected StdDev=-1.0 for disabled gateway, got %f", gw2.StdDev)
	}
	if gw2.Loss != -1.0 {
		t.Errorf("expected Loss=-1.0 for disabled gateway, got %f", gw2.Loss)
	}
	if gw2.ForceDown != true {
		t.Error("expected ForceDown=true")
	}
	if gw2.MonitorEnabled {
		t.Error("expected MonitorEnabled=false (monitor_disable=1)")
	}
	if gw2.Priority != "128" {
		t.Errorf("expected Priority='128' (string type), got %q", gw2.Priority)
	}
}

func TestFetchGateways_PendingAndUnknownStatus(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 2,
			"rowCount": 2,
			"current": 1,
			"rows": [
				{
					"disabled": false,
					"name": "PENDING_GW",
					"descr": "",
					"interface": "igb0",
					"ipprotocol": "inet",
					"gateway": "10.0.0.1",
					"defaultgw": false,
					"fargw": "",
					"monitor_disable": "0",
					"monitor_noroute": "0",
					"monitor": "",
					"force_down": "0",
					"priority": 255,
					"weight": "1",
					"latencylow": "200",
					"current_latencylow": "200",
					"latencyhigh": "500",
					"current_latencyhigh": "500",
					"losslow": "10",
					"current_losslow": "10",
					"losshigh": "20",
					"current_losshigh": "20",
					"interval": "500",
					"current_interval": "500",
					"time_period": "60",
					"current_time_period": "60",
					"loss_interval": "2500",
					"current_loss_interval": "2500",
					"data_length": "0",
					"current_data_length": "0",
					"uuid": "uuid-1",
					"if": "wan",
					"attribute": 1,
					"dynamic": false,
					"virtual": false,
					"upstream": true,
					"interface_descr": "WAN",
					"status": "Pending",
					"delay": "~",
					"stddev": "~",
					"loss": "~",
					"label_class": "warning"
				},
				{
					"disabled": false,
					"name": "UNKNOWN_GW",
					"descr": "",
					"interface": "igb1",
					"ipprotocol": "inet",
					"gateway": "10.0.1.1",
					"defaultgw": false,
					"fargw": "",
					"monitor_disable": "0",
					"monitor_noroute": "0",
					"monitor": "",
					"force_down": "0",
					"priority": 255,
					"weight": "1",
					"latencylow": "200",
					"current_latencylow": "200",
					"latencyhigh": "500",
					"current_latencyhigh": "500",
					"losslow": "10",
					"current_losslow": "10",
					"losshigh": "20",
					"current_losshigh": "20",
					"interval": "500",
					"current_interval": "500",
					"time_period": "60",
					"current_time_period": "60",
					"loss_interval": "2500",
					"current_loss_interval": "2500",
					"data_length": "0",
					"current_data_length": "0",
					"uuid": "uuid-2",
					"if": "opt1",
					"attribute": 2,
					"dynamic": false,
					"virtual": false,
					"upstream": false,
					"interface_descr": "LAN",
					"status": "SomeWeirdStatus",
					"delay": "~",
					"stddev": "~",
					"loss": "~",
					"label_class": "default"
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchGateways()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.Gateways[0].Status != GatewayStatusPeding {
		t.Errorf("expected GatewayStatusPeding, got %d", data.Gateways[0].Status)
	}
	if data.Gateways[1].Status != GatewayStatusUnknown {
		t.Errorf("expected GatewayStatusUnknown, got %d", data.Gateways[1].Status)
	}
}

func TestFetchGateways_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchGateways()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestParseGatewayStatus(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tests := []struct {
		name string
		in   string
		want GatewayStatusType
	}{
		{"online", "Online", GatewayStatusOnline},
		{"offline", "Offline", GatewayStatusOffline},
		{"pending", "Pending", GatewayStatusPeding},
		{"packetloss", "Packetloss", GatewayStatusLoss},
		{"latency", "Latency", GatewayStatusLatency},
		{"forced", "Offline (forced)", GatewayStatusForcedDown},
		{"combined latency packetloss", "Latency, Packetloss", GatewayStatusLoss},
		{"combined online latency", "Online, Latency", GatewayStatusLatency},
		{"unknown", "Mystery", GatewayStatusUnknown},
		{"empty", "", GatewayStatusUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseGatewayStatus(tt.in, logger, tt.in)
			if got != tt.want {
				t.Errorf("parseGatewayStatus(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// A monitored gateway can report "~" for delay/stddev/loss while dpinger has
// no data yet (upstream issue #106) — must parse to the -1 sentinel WITHOUT
// logging a warning. force_down can be JSON null (seen live on 26.1.9) — must
// parse to false.
func TestFetchGateways_ProbeUnavailableAndNullForceDown(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1,
			"rowCount": 1,
			"current": 1,
			"rows": [
				{
					"disabled": false,
					"name": "WARMUP_GW",
					"descr": "",
					"interface": "igb0",
					"ipprotocol": "inet",
					"gateway": "10.0.0.1",
					"defaultgw": true,
					"fargw": "",
					"monitor_disable": "0",
					"monitor_noroute": "0",
					"monitor": "8.8.8.8",
					"force_down": null,
					"priority": 255,
					"weight": "1",
					"latencylow": "200",
					"current_latencylow": "200",
					"latencyhigh": "500",
					"current_latencyhigh": "500",
					"losslow": "10",
					"current_losslow": "10",
					"losshigh": "20",
					"current_losshigh": "20",
					"interval": "500",
					"current_interval": "500",
					"time_period": "60",
					"current_time_period": "60",
					"loss_interval": "2500",
					"current_loss_interval": "2500",
					"data_length": "0",
					"current_data_length": "0",
					"uuid": "uuid-warmup",
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
	})
	defer server.Close()

	var logBuf bytes.Buffer
	client.log = slog.New(slog.NewTextHandler(&logBuf, nil))

	data, err := client.FetchGateways()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gw := data.Gateways[0]
	if !gw.MonitorEnabled {
		t.Fatal("expected MonitorEnabled=true")
	}
	if gw.Delay != -1.0 {
		t.Errorf("expected Delay=-1.0 for '~', got %f", gw.Delay)
	}
	if gw.StdDev != -1.0 {
		t.Errorf("expected StdDev=-1.0 for '~', got %f", gw.StdDev)
	}
	if gw.Loss != -1.0 {
		t.Errorf("expected Loss=-1.0 for '~', got %f", gw.Loss)
	}
	if gw.ForceDown {
		t.Error("expected ForceDown=false for JSON null force_down")
	}
	if logged := logBuf.String(); strings.Contains(logged, "failed") {
		t.Errorf("expected no parse warnings for '~' values, got log output: %s", logged)
	}
}

// TestFetchGateways_MonitorKillStates guards #584: monitor_killstates and
// monitor_killstates_priority are sibling monitor-behavior BooleanFields
// (Routing/Gateways.xml, verified against opnsense/core master 2026-07-31,
// same "0"/"1" string wire shape as the already-modeled monitor_disable/
// monitor_noroute) controlling whether pf states get killed when this
// gateway is marked down.
func TestFetchGateways_MonitorKillStates(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 2,
			"rowCount": 2,
			"current": 1,
			"rows": [
				{
					"disabled": false,
					"name": "WAN_GW",
					"descr": "WAN Gateway",
					"interface": "igb0",
					"ipprotocol": "inet",
					"gateway": "10.0.0.1",
					"defaultgw": true,
					"fargw": "",
					"monitor_disable": "0",
					"monitor_noroute": "0",
					"monitor_killstates": "1",
					"monitor_killstates_priority": "0",
					"monitor": "10.0.0.1",
					"force_down": "0",
					"priority": 255,
					"weight": "1",
					"uuid": "uuid-wan-gw",
					"if": "wan",
					"attribute": 1,
					"dynamic": false,
					"virtual": false,
					"upstream": true,
					"interface_descr": "WAN",
					"status": "Online",
					"delay": "1.5 ms",
					"stddev": "0.3 ms",
					"loss": "0.0 %",
					"label_class": "success"
				},
				{
					"disabled": false,
					"name": "BACKUP_GW",
					"descr": "Backup Gateway",
					"interface": "igb1",
					"ipprotocol": "inet",
					"gateway": "10.0.1.1",
					"defaultgw": false,
					"fargw": "",
					"monitor_disable": "0",
					"monitor_noroute": "0",
					"monitor": "10.0.1.1",
					"force_down": "0",
					"priority": 128,
					"weight": "1",
					"uuid": "uuid-backup-gw",
					"if": "opt1",
					"attribute": 2,
					"dynamic": false,
					"virtual": false,
					"upstream": true,
					"interface_descr": "OPT1",
					"status": "Online",
					"delay": "1.5 ms",
					"stddev": "0.3 ms",
					"loss": "0.0 %",
					"label_class": "success"
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchGateways()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Gateways) != 2 {
		t.Fatalf("expected 2 gateways, got %d", len(data.Gateways))
	}

	wan := data.Gateways[0]
	if !wan.MonitorKillStates {
		t.Error("expected WAN_GW MonitorKillStates=true")
	}
	if wan.MonitorKillStatesPriority {
		t.Error("expected WAN_GW MonitorKillStatesPriority=false")
	}

	// BACKUP_GW's fixture omits both keys entirely -- OPNsense's own
	// BooleanField carries no <Default> for either (unlike monitor_disable's
	// Default=1), so a genuinely absent key must decode to false, matching
	// how the existing MonitorNoRoute/ForceDown fields already degrade.
	backup := data.Gateways[1]
	if backup.MonitorKillStates {
		t.Error("expected BACKUP_GW MonitorKillStates=false (key absent from fixture)")
	}
	if backup.MonitorKillStatesPriority {
		t.Error("expected BACKUP_GW MonitorKillStatesPriority=false (key absent from fixture)")
	}
}

func TestConvertPriorityToString(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
	}{
		{"String", "128", "128"},
		{"Int", 255, "255"},
		{"Float64", float64(100), "100"},
		{"Nil", nil, ""},
		{"Bool", true, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := convertPriorityToString(tc.input)
			if result != tc.expected {
				t.Errorf("convertPriorityToString(%v) = %q; want %q", tc.input, result, tc.expected)
			}
		})
	}
}
