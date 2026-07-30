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

	// 4 thread gauges + 5 ARC components + 2 ARC compression figures. The fixture
	// carries a ZFS ARC header, so the composition series (#551) are present.
	expectedCount := 11
	if len(metrics) != expectedCount {
		t.Fatalf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	expectedValues := map[string]float64{
		"opnsense_activity_threads_total":          849,
		"opnsense_activity_threads_running":        13,
		"opnsense_activity_threads_sleeping":       802,
		"opnsense_activity_threads_waiting":        34,
		"opnsense_activity_arc_compressed_bytes":   7809 * 1024 * 1024,
		"opnsense_activity_arc_uncompressed_bytes": 13 * 1024 * 1024 * 1024,
	}

	arcComponents := map[string]float64{}
	for _, m := range metrics {
		desc := m.Desc().String()
		value := getMetricValue(m)

		labels := getMetricLabels(m)
		if labels["opnsense_instance"] != "test" {
			t.Errorf("expected instance label 'test', got %q", labels["opnsense_instance"])
		}

		if containsString(desc, "opnsense_activity_arc_component_bytes") {
			// Values are checked per component below; the shared desc cannot be
			// matched against a single expected number.
			arcComponents[labels["component"]] = value
			continue
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

	const mb = 1024 * 1024
	for component, want := range map[string]float64{
		"mfu": 4571 * mb, "mru": 3776 * mb, "anon": 34 * mb,
		"header": 67 * mb, "other": 517 * mb,
	} {
		if got, ok := arcComponents[component]; !ok {
			t.Errorf("missing arc_component_bytes for %q", component)
		} else if got != want {
			t.Errorf("arc_component_bytes{component=%q} = %v, want %v", component, got, want)
		}
	}
}

// TestActivityCollector_ARCAbsentOnNonZFS pins that a UFS box publishes NO ARC series
// rather than zeros. The absence signal is not a missing header — a real UFS box
// emits a bare "ARC: " (verified live 2026-07-30) — so a zero here would show every
// non-ZFS firewall as having a real, permanently empty cache.
func TestActivityCollector_ARCAbsentOnNonZFS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"headers":[
			"849 threads:   13 running, 802 sleeping, 34 waiting",
			"ARC: ",
			"Swap: 10G Total, 433M Used, 9807M Free, 4% Inuse"
		],"details":[]}`))
	}))
	defer server.Close()

	c := &activityCollector{subsystem: ActivitySubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, newCollectorTestClient(t, server))

	if len(metrics) != 4 {
		t.Fatalf("expected only the 4 thread gauges on a non-ZFS box, got %d", len(metrics))
	}
	for _, m := range metrics {
		if containsString(m.Desc().String(), "arc") {
			t.Errorf("ARC series must be absent on a non-ZFS box, got %s", m.Desc().String())
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

	expectedCount := 4
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
