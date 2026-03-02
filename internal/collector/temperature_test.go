package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestTemperatureCollector_Update(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[
			{
				"device": "hw.acpi.thermal",
				"device_seq": 0,
				"temperature": "42.5",
				"type_translated": "Thermal Zone",
				"type": "thermal"
			},
			{
				"device": "dev.cpu",
				"device_seq": 0,
				"temperature": "55.0",
				"type_translated": "CPU Core",
				"type": "cpu"
			},
			{
				"device": "dev.cpu",
				"device_seq": 1,
				"temperature": "54.0",
				"type_translated": "CPU Core",
				"type": "cpu"
			}
		]`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &temperatureCollector{subsystem: TemperatureSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 3 temperature readings
	expectedCount := 3
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Verify temperature values
	for _, m := range metrics {
		v := getMetricValue(m)
		if v < 0 || v > 200 {
			t.Errorf("unexpected temperature value: %f", v)
		}
	}
}

func TestTemperatureCollector_Update_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &temperatureCollector{subsystem: TemperatureSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics, got %d", len(metrics))
	}
}

func TestTemperatureCollector_Name(t *testing.T) {
	c := &temperatureCollector{subsystem: TemperatureSubsystem}
	if c.Name() != TemperatureSubsystem {
		t.Errorf("expected %s, got %s", TemperatureSubsystem, c.Name())
	}
}
