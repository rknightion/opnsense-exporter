package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

const apcupsdCollectorSuccessFixture = `{
	"error": null,
	"output": "APC : 001,036,0857",
	"status": {
		"STATUS":   {"value": "ONLINE",         "norm": "ONLINE"},
		"MODEL":    {"value": "Smart-UPS 1500",  "norm": "Smart-UPS 1500"},
		"BCHARGE":  {"value": "100.0 Percent",   "norm": 100.0},
		"TIMELEFT": {"value": "42.0 Minutes",    "norm": 42.0},
		"LOADPCT":  {"value": "12.0 Percent",    "norm": 12.0},
		"LINEV":    {"value": "230.0 Volts",     "norm": 230.0},
		"BATTV":    {"value": "27.1 Volts",      "norm": 27.1},
		"OUTPUTV":  {"value": "229.8 Volts",     "norm": 229.8},
		"TONBATT":  {"value": "0 Seconds",       "norm": 0.0},
		"NUMXFERS": {"value": "3",               "norm": 3.0},
		"NOMPOWER": {"value": "980 Watts",       "norm": 980.0}
	}
}`

func apcupsdCollectorMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/apcupsd/service/getUpsStatus", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(apcupsdCollectorSuccessFixture))
	})
	mux.HandleFunc("/api/apcupsd/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	return mux
}

func TestApcupsdCollector_Update_Normal(t *testing.T) {
	server := httptest.NewServer(apcupsdCollectorMux(t))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &apcupsdCollector{subsystem: ApcupsdSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// ups_info = 1
	// 9 numeric: battery_charge_percent, battery_runtime_seconds, load_percent,
	//            input_voltage_volts, battery_voltage_volts, output_voltage_volts,
	//            time_on_battery_seconds, transfers_total, nominal_power_watts
	// 3 flags: status_online, status_on_battery, status_low_battery
	// service_running = 1
	expected := 1 + 9 + 3 + 1
	if len(metrics) != expected {
		t.Errorf("expected %d metrics, got %d", expected, len(metrics))
	}

	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		val := getMetricValue(m)
		switch {
		case strings.Contains(desc, "apcupsd_ups_info"):
			if labels["model"] != "Smart-UPS 1500" || labels["status"] != "ONLINE" || val != 1 {
				t.Errorf("ups_info wrong: labels=%v val=%v", labels, val)
			}
		case strings.Contains(desc, "apcupsd_battery_runtime_seconds"):
			// TIMELEFT is 42.0 minutes → ×60 = 2520 seconds
			if val != 2520 {
				t.Errorf("battery_runtime_seconds wrong: want 2520, got %v", val)
			}
		case strings.Contains(desc, "apcupsd_status_online"):
			if val != 1 {
				t.Errorf("status_online wrong: want 1, got %v", val)
			}
		case strings.Contains(desc, "apcupsd_status_on_battery"):
			if val != 0 {
				t.Errorf("status_on_battery wrong: want 0, got %v", val)
			}
		case strings.Contains(desc, "apcupsd_service_running"):
			if val != 1 {
				t.Errorf("service_running wrong: want 1, got %v", val)
			}
		case strings.Contains(desc, "apcupsd_transfers_total"):
			if val != 3 {
				t.Errorf("transfers_total wrong: want 3, got %v", val)
			}
		case strings.Contains(desc, "apcupsd_nominal_power_watts"):
			if val != 980 {
				t.Errorf("nominal_power_watts wrong: want 980, got %v", val)
			}
		}
	}
}

func TestApcupsdCollector_Update_PluginAbsent(t *testing.T) {
	// All 404 → plugin absent, 0 metrics expected.
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &apcupsdCollector{subsystem: ApcupsdSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when plugin absent, got %d", len(metrics))
	}
}

func TestApcupsdCollector_Name(t *testing.T) {
	c := &apcupsdCollector{subsystem: ApcupsdSubsystem}
	if c.Name() != ApcupsdSubsystem {
		t.Errorf("expected %s, got %s", ApcupsdSubsystem, c.Name())
	}
}
