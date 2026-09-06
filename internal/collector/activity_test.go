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

	// 4 thread gauges + 5 ARC components + 2 ARC compression figures + the 2
	// process-aggregate health series (#552). The fixture carries a ZFS ARC header,
	// so the composition series (#551) are present; its details array is empty, so
	// no per-user or per-command series are produced.
	expectedCount := 13
	if len(metrics) != expectedCount {
		t.Fatalf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	expectedValues := map[string]float64{
		"opnsense_activity_threads":                849,
		"opnsense_activity_threads_running":        13,
		"opnsense_activity_threads_sleeping":       802,
		"opnsense_activity_threads_waiting":        34,
		"opnsense_activity_arc_compressed_bytes":   7809 * 1024 * 1024,
		"opnsense_activity_arc_uncompressed_bytes": 13 * 1024 * 1024 * 1024,
		"opnsense_activity_commands_tracked":       0,
		"opnsense_activity_commands_capped_total":  0,
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

		name := metricNameOf(m)
		expected, found := expectedValues[name]
		if found {
			if value != expected {
				t.Errorf("metric %s: expected %f, got %f", name, expected, value)
			}
		} else {
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

	if len(metrics) != 6 {
		t.Fatalf("expected only the 4 thread gauges plus the 2 process-aggregate health series on a non-ZFS box, got %d", len(metrics))
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

	expectedCount := 6
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

// TestActivityCollector_ProcessAggregates is the collector-level acceptance proof for
// #552's memory trap, end to end from the wire.
//
// `top -aHSTn` prints ONE ROW PER THREAD, and every thread of a process reports that
// PROCESS's RES. The fixture's PID 100 has four thread rows at 512M each; a naive
// implementation exports 2048M for it. CPU is genuinely per-thread and DOES sum, so
// the same process is 4 x 5.00% = 20%. The two [idle{...}] rows — the top rows by CPU
// on any healthy box — must not appear at all.
func TestActivityCollector_ProcessAggregates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"headers":["849 threads:   13 running, 802 sleeping, 34 waiting"],"details":[
			{"C":"10","PID":"11","THR":"100013","USERNAME":"root","RES":"192K","WCPU":"98.27%","COMMAND":"[idle{idle: cpu10}]"},
			{"C":"11","PID":"11","THR":"100014","USERNAME":"root","RES":"192K","WCPU":"97.13%","COMMAND":"[idle{idle: cpu11}]"},
			{"C":"0","PID":"100","THR":"100201","USERNAME":"www","RES":"512M","WCPU":"5.00%","COMMAND":"python3{python3}"},
			{"C":"1","PID":"100","THR":"100202","USERNAME":"www","RES":"512M","WCPU":"5.00%","COMMAND":"python3{python3}"},
			{"C":"2","PID":"100","THR":"100203","USERNAME":"www","RES":"512M","WCPU":"5.00%","COMMAND":"python3{python3}"},
			{"C":"3","PID":"100","THR":"100204","USERNAME":"www","RES":"512M","WCPU":"5.00%","COMMAND":"python3{python3}"},
			{"C":"4","PID":"200","THR":"100301","USERNAME":"root","RES":"32M","WCPU":"1.50%","COMMAND":"unbound"}
		]}`))
	}))
	defer server.Close()

	c := &activityCollector{subsystem: ActivitySubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, newCollectorTestClient(t, server))

	const mib = 1024 * 1024
	// family -> label value -> value
	got := map[string]map[string]float64{}
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		for _, family := range []string{
			"opnsense_activity_user_cpu_percent",
			"opnsense_activity_user_memory_bytes",
			"opnsense_activity_command_cpu_percent",
			"opnsense_activity_command_memory_bytes",
			"opnsense_activity_command_threads",
		} {
			if !containsString(desc, family) {
				continue
			}
			key := labels["user"] + labels["command"]
			if got[family] == nil {
				got[family] = map[string]float64{}
			}
			got[family][key] = getMetricValue(m)
		}
	}

	want := map[string]map[string]float64{
		"opnsense_activity_user_cpu_percent":     {"www": 20, "root": 1.5},
		"opnsense_activity_user_memory_bytes":    {"www": 512 * mib, "root": 32 * mib},
		"opnsense_activity_command_cpu_percent":  {"python3": 20, "unbound": 1.5},
		"opnsense_activity_command_memory_bytes": {"python3": 512 * mib, "unbound": 32 * mib},
		"opnsense_activity_command_threads":      {"python3": 4, "unbound": 1},
	}
	for family, wantValues := range want {
		if len(got[family]) != len(wantValues) {
			t.Errorf("%s: got %v, want %v", family, got[family], wantValues)
			continue
		}
		for key, wantValue := range wantValues {
			if g := got[family][key]; g != wantValue {
				t.Errorf("%s{%s} = %v, want %v", family, key, g, wantValue)
			}
		}
	}

	// The idle threads must not have produced a series anywhere.
	for _, m := range metrics {
		if getMetricLabels(m)["command"] == "idle" {
			t.Errorf("idle must never be exported: %s", m.Desc().String())
		}
	}
}
