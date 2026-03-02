package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestActivityCollector_Update(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"headers": [
				"last pid: 65652;  load averages:  0.74,  0.52,  0.49  up 23+03:58:03    17:13:41",
				"849 threads:   13 running, 802 sleeping, 34 waiting",
				"CPU:  1.3% user,  0.0% nice,  2.2% system,  0.1% interrupt, 96.4% idle",
				"Mem: 5249M Active, 3393M Inact, 5446M Laundry, 13G Wired, 372K Buf, 3900M Free",
				"ARC: 8970M Total, 4571M MFU, 3776M MRU, 34M Anon, 67M Header, 517M Other",
				"     7809M Compressed, 13G Uncompressed, 1.74:1 Ratio",
				"Swap: 10G Total, 433M Used, 9807M Free, 4% Inuse"
			],
			"details": []
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &activityCollector{subsystem: ActivitySubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	expectedCount := 9
	if len(metrics) != expectedCount {
		t.Fatalf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	expectedValues := map[string]float64{
		"opnsense_activity_threads_total":         849,
		"opnsense_activity_threads_running":       13,
		"opnsense_activity_threads_sleeping":      802,
		"opnsense_activity_threads_waiting":       34,
		"opnsense_activity_cpu_user_percent":      1.3,
		"opnsense_activity_cpu_nice_percent":      0.0,
		"opnsense_activity_cpu_system_percent":    2.2,
		"opnsense_activity_cpu_interrupt_percent": 0.1,
		"opnsense_activity_cpu_idle_percent":      96.4,
	}

	for _, m := range metrics {
		desc := m.Desc().String()
		value := getMetricValue(m)

		labels := getMetricLabels(m)
		if labels["opnsense_instance"] != "test" {
			t.Errorf("expected instance label 'test', got %q", labels["opnsense_instance"])
		}

		found := false
		for name, expected := range expectedValues {
			if containsString(desc, name) {
				found = true
				if value != expected {
					t.Errorf("metric %s: expected %f, got %f", name, expected, value)
				}
				break
			}
		}
		if !found {
			t.Errorf("unexpected metric with desc: %s", desc)
		}
	}
}

func TestActivityCollector_Update_EmptyHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"headers": [],
			"details": []
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &activityCollector{subsystem: ActivitySubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	expectedCount := 9
	if len(metrics) != expectedCount {
		t.Fatalf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	for _, m := range metrics {
		value := getMetricValue(m)
		if value != 0 {
			t.Errorf("expected zero value for metric %s, got %f", m.Desc().String(), value)
		}
	}
}

// containsString checks if a string contains a substring.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
