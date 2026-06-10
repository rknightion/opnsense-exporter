package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

// nutNormalFixture covers all 8 mapped numeric vars plus status with 2 flags.
const nutNormalUpsStatusFixture = `{"response": "battery.charge: 100\nbattery.runtime: 1320\nbattery.voltage: 27.1\ninput.voltage: 230.1\noutput.voltage: 229.8\nups.load: 14\nups.model: Smart-UPS 1500\nups.status: OL CHRG\nups.temperature: 24.5\ninput.frequency: 50.0\n"}`

// nutPartialVarsFixture omits output.voltage, temperature, input.frequency.
const nutPartialVarsUpsStatusFixture = `{"response": "battery.charge: 100\nbattery.runtime: 1320\nbattery.voltage: 27.1\ninput.voltage: 230.1\nups.load: 14\nups.model: Smart-UPS 1500\nups.status: OL\n"}`

func nutNormalMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/nut/diagnostics/upsstatus", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(nutNormalUpsStatusFixture))
	})
	mux.HandleFunc("/api/nut/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"running"}`))
	})
	return mux
}

// TestNUTCollector_Update_Normal checks the full metric count and spot-checks
// key values. Expected count:
//   - ups_info:                1
//   - battery_charge_percent:  1
//   - battery_runtime_seconds: 1
//   - battery_voltage_volts:   1
//   - input_voltage_volts:     1
//   - output_voltage_volts:    1
//   - load_percent:            1
//   - temperature_celsius:     1
//   - input_frequency_hertz:   1
//   - status_online:           1
//   - status_on_battery:       1
//   - status_low_battery:      1
//   - status_charging:         1
//   - status_replace_battery:  1
//   - service_running:         1
//
// Total = 15
func TestNUTCollector_Update_Normal(t *testing.T) {
	server := httptest.NewServer(nutNormalMux(t))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &nutCollector{subsystem: NUTSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	const expected = 15
	if len(metrics) != expected {
		t.Errorf("expected %d metrics, got %d", expected, len(metrics))
		for _, m := range metrics {
			t.Logf("  metric: %s", m.Desc().String())
		}
	}

	// Spot checks.
	for _, m := range metrics {
		desc := m.Desc().String()
		val := getMetricValue(m)
		switch {
		case strings.Contains(desc, "nut_service_running"):
			if val != 1 {
				t.Errorf("service_running: want 1, got %v", val)
			}
		case strings.Contains(desc, "nut_status_online"):
			if val != 1 {
				t.Errorf("status_online: want 1, got %v", val)
			}
		case strings.Contains(desc, "nut_status_on_battery"):
			if val != 0 {
				t.Errorf("status_on_battery: want 0, got %v", val)
			}
		case strings.Contains(desc, "nut_status_charging"):
			if val != 1 {
				t.Errorf("status_charging: want 1, got %v", val)
			}
		case strings.Contains(desc, "nut_battery_charge_percent"):
			if val != 100 {
				t.Errorf("battery_charge_percent: want 100, got %v", val)
			}
		case strings.Contains(desc, "nut_battery_runtime_seconds"):
			if val != 1320 {
				t.Errorf("battery_runtime_seconds: want 1320, got %v", val)
			}
		case strings.Contains(desc, "nut_ups_info"):
			labels := getMetricLabels(m)
			if labels["model"] != "Smart-UPS 1500" {
				t.Errorf("ups_info model: want %q, got %q", "Smart-UPS 1500", labels["model"])
			}
			if labels["status"] != "OL CHRG" {
				t.Errorf("ups_info status: want %q, got %q", "OL CHRG", labels["status"])
			}
		}
	}
}

// TestNUTCollector_Update_PartialVars verifies that metrics for absent upsc
// variables are not emitted (output.voltage, temperature, frequency omitted).
func TestNUTCollector_Update_PartialVars(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/nut/diagnostics/upsstatus", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(nutPartialVarsUpsStatusFixture))
	})
	mux.HandleFunc("/api/nut/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"running"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &nutCollector{subsystem: NUTSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Verify missing metrics are absent.
	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "nut_output_voltage_volts") {
			t.Error("output_voltage_volts should be absent when output.voltage not in upsc")
		}
		if strings.Contains(desc, "nut_temperature_celsius") {
			t.Error("temperature_celsius should be absent when ups.temperature not in upsc")
		}
		if strings.Contains(desc, "nut_input_frequency_hertz") {
			t.Error("input_frequency_hertz should be absent when input.frequency not in upsc")
		}
	}

	// Should still have ups_info + 5 numeric vars + 5 flags + service_running = 12
	// ups_info(1) + battery_charge_percent(1) + battery_runtime_seconds(1) +
	// battery_voltage_volts(1) + input_voltage_volts(1) + load_percent(1) +
	// status_online(1) + status_on_battery(1) + status_low_battery(1) +
	// status_charging(1) + status_replace_battery(1) + service_running(1) = 12
	const expected = 12
	if len(metrics) != expected {
		t.Errorf("expected %d metrics for partial vars, got %d", expected, len(metrics))
	}
}

// TestNUTCollector_Update_PluginAbsent verifies complete silence when the plugin
// is not installed (all requests 404).
func TestNUTCollector_Update_PluginAbsent(t *testing.T) {
	mux := http.NewServeMux() // no handlers — all 404
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &nutCollector{subsystem: NUTSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when plugin absent, got %d", len(metrics))
	}
}

func TestNUTCollector_Name(t *testing.T) {
	c := &nutCollector{subsystem: NUTSubsystem}
	if c.Name() != NUTSubsystem {
		t.Errorf("Name(): want %q, got %q", NUTSubsystem, c.Name())
	}
}
