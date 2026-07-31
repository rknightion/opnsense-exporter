package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense2otel/v4/internal/flow"
)

// TestNetflowCollector_ConcurrentFetch covers #129: the three independent netflow
// endpoints are fetched concurrently, so total wall time is bounded by the slowest
// single call rather than their sum.
func TestNetflowCollector_ConcurrentFetch(t *testing.T) {
	mux := http.NewServeMux()
	const delay = 60 * time.Millisecond
	for _, p := range []string{
		"/api/diagnostics/netflow/isEnabled",
		"/api/diagnostics/netflow/status",
		"/api/diagnostics/netflow/cacheStats",
	} {
		mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(delay)
			_, _ = w.Write([]byte(`{}`))
		})
	}
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &netflowCollector{subsystem: NetflowSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	start := time.Now()
	ch := make(chan prometheus.Metric, 128)
	if err := c.Update(context.Background(), client, ch); err != nil {
		t.Fatalf("update: %v", err)
	}
	close(ch)
	elapsed := time.Since(start)
	// Sequential = 3*60ms = 180ms; concurrent = ~60ms.
	if elapsed > 140*time.Millisecond {
		t.Errorf("netflow Update took %v; the three fetches did not run concurrently", elapsed)
	}
}

func TestNetflowCollector_Update(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/diagnostics/netflow/isEnabled", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"netflow": 1, "local": 1}`))
	})

	mux.HandleFunc("/api/diagnostics/netflow/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "active", "collectors": "12"}`))
	})

	mux.HandleFunc("/api/diagnostics/netflow/cacheStats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"netflow_igb0": {"Pkts": 2724171, "if": "igb0", "SrcIPaddresses": 539, "DstIPaddresses": 562},
			"netflow_pppoe0": {"Pkts": 0, "if": "pppoe0", "SrcIPaddresses": 0, "DstIPaddresses": 0},
			"ksocket_netflow_igb0": {"Pkts": 0, "if": "netflow_igb0", "SrcIPaddresses": 0, "DstIPaddresses": 0}
		}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &netflowCollector{subsystem: NetflowSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 2 isEnabled + 2 status + 2 interfaces * 3 cache = 10
	expectedCount := 10
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	for _, m := range metrics {
		labels := getMetricLabels(m)
		desc := m.Desc().String()

		if containsString(desc, "netflow_enabled") && !containsString(desc, "local") {
			val := getMetricValue(m)
			if val != 1 {
				t.Errorf("netflow_enabled = %v; want 1", val)
			}
		}

		if containsString(desc, "netflow_active") {
			val := getMetricValue(m)
			if val != 1 {
				t.Errorf("netflow_active = %v; want 1", val)
			}
		}

		if containsString(desc, "netflow_collectors_count") {
			val := getMetricValue(m)
			if val != 12 {
				t.Errorf("netflow_collectors_count = %v; want 12", val)
			}
		}

		if containsString(desc, "cache_packets_total") && labels["interface"] == "igb0" {
			val := getMetricValue(m)
			if val != 2724171 {
				t.Errorf("igb0 cache_packets_total = %v; want 2724171", val)
			}
		}
	}
}

func TestNetflowCollector_UpdateDisabled(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/diagnostics/netflow/isEnabled", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"netflow": 0, "local": 0}`))
	})

	mux.HandleFunc("/api/diagnostics/netflow/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "stopped", "collectors": "0"}`))
	})

	mux.HandleFunc("/api/diagnostics/netflow/cacheStats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &netflowCollector{subsystem: NetflowSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 2 isEnabled + 2 status + 0 cache = 4
	expectedCount := 4
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	for _, m := range metrics {
		desc := m.Desc().String()
		if containsString(desc, "netflow_enabled") && !containsString(desc, "local") {
			val := getMetricValue(m)
			if val != 0 {
				t.Errorf("netflow_enabled = %v; want 0", val)
			}
		}
		if containsString(desc, "netflow_active") {
			val := getMetricValue(m)
			if val != 0 {
				t.Errorf("netflow_active = %v; want 0", val)
			}
		}
	}
}

func TestNetflowCollector_Name(t *testing.T) {
	c := &netflowCollector{subsystem: NetflowSubsystem}
	if c.Name() != NetflowSubsystem {
		t.Errorf("expected %s, got %s", NetflowSubsystem, c.Name())
	}
}

// netflowCaptureMux is the three existing endpoints plus getconfig, so the capture
// metrics can be exercised without repeating the boilerplate.
func netflowCaptureMux(t *testing.T, getconfig string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/netflow/isEnabled", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"netflow": 1, "local": 0}`))
	})
	mux.HandleFunc("/api/diagnostics/netflow/status", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status": "active", "collectors": "3"}`))
	})
	mux.HandleFunc("/api/diagnostics/netflow/cacheStats", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/api/diagnostics/netflow/getconfig", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET on getconfig, got %s", r.Method)
		}
		_, _ = w.Write([]byte(getconfig))
	})
	return httptest.NewServer(mux)
}

const twoInterfaceGetconfig = `{"netflow":{"capture":{"interfaces":{` +
	`"opt7":{"value":"AAISP","selected":1},"opt1":{"value":"tailscale","selected":0}}},` +
	`"collect":{"enable":"0"},"activeTimeout":"1800","inactiveTimeout":"15"}}`

// The expected set is the half no counter can supply: without it, an interface
// producing nothing is indistinguishable from one that was never asked to (#366).
// Emitted for UNSELECTED interfaces too, as 0 — "deliberately not captured" is a
// distinct answer from "not in the config at all", and only one of them is a
// candidate fault.
func TestNetflowCollector_EmitsConfiguredCaptureSet(t *testing.T) {
	server := netflowCaptureMux(t, twoInterfaceGetconfig)
	defer server.Close()

	c := &netflowCollector{subsystem: NetflowSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	got := map[string]float64{}
	for _, m := range collectMetrics(t, c, newCollectorTestClient(t, server)) {
		if containsString(m.Desc().String(), "capture_expected") {
			got[getMetricLabels(m)["interface"]] = getMetricValue(m)
		}
	}

	if len(got) != 2 {
		t.Fatalf("capture_expected has %d series, want 2: %v", len(got), got)
	}
	if got["AAISP"] != 1 {
		t.Errorf("capture_expected{interface=AAISP} = %v, want 1", got["AAISP"])
	}
	if got["tailscale"] != 0 {
		t.Errorf("capture_expected{interface=tailscale} = %v, want 0", got["tailscale"])
	}
}

// The box's own flow timeouts, so a "gone quiet" threshold is derived from what the
// firewall actually applies rather than guessed. An interface cannot be judged
// silent until well past the active timeout, and that number is per-box.
func TestNetflowCollector_EmitsConfiguredTimeouts(t *testing.T) {
	server := netflowCaptureMux(t, twoInterfaceGetconfig)
	defer server.Close()

	c := &netflowCollector{subsystem: NetflowSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	got := map[string]float64{}
	for _, m := range collectMetrics(t, c, newCollectorTestClient(t, server)) {
		d := m.Desc().String()
		if containsString(d, "capture_active_timeout_seconds") {
			got["active"] = getMetricValue(m)
		}
		if containsString(d, "capture_inactive_timeout_seconds") {
			got["inactive"] = getMetricValue(m)
		}
	}

	if got["active"] != 1800 {
		t.Errorf("capture_active_timeout_seconds = %v, want 1800", got["active"])
	}
	if got["inactive"] != 15 {
		t.Errorf("capture_inactive_timeout_seconds = %v, want 15", got["inactive"])
	}
}

// "Never seen since start" and "seen, then stopped" must not read the same. A
// never-seen interface gets NO last-record series at all rather than a large or
// zero value, because every interface is silent at startup and a number there
// would make a fresh boot look like a box-wide outage.
func TestNetflowCollector_NeverSeenInterfaceHasNoLastRecordSeries(t *testing.T) {
	server := netflowCaptureMux(t, twoInterfaceGetconfig)
	defer server.Close()

	c := &netflowCollector{subsystem: NetflowSubsystem, store: newFlowStore(10, 100)} // nothing observed
	c.Register(namespace, "test", promslog.NewNopLogger())

	for _, m := range collectMetrics(t, c, newCollectorTestClient(t, server)) {
		if containsString(m.Desc().String(), "capture_last_record_seconds") {
			t.Fatalf("last_record_seconds emitted for %q before any record arrived; "+
				"startup silence must not read as a fault", getMetricLabels(m)["interface"])
		}
	}
}

// Once a record HAS arrived, the age is exposed as a raw number so the operator
// picks the threshold. No verdict is baked in: a guest VLAN can be legitimately
// silent for hours.
func TestNetflowCollector_EmitsSecondsSinceLastRecord(t *testing.T) {
	server := netflowCaptureMux(t, twoInterfaceGetconfig)
	defer server.Close()

	store := newFlowStore(10, 100)
	store.Observe(netflowRecOn("AAISP"))
	c := &netflowCollector{subsystem: NetflowSubsystem, store: store}
	c.Register(namespace, "test", promslog.NewNopLogger())

	seen := map[string]float64{}
	for _, m := range collectMetrics(t, c, newCollectorTestClient(t, server)) {
		if containsString(m.Desc().String(), "capture_last_record_seconds") {
			seen[getMetricLabels(m)["interface"]] = getMetricValue(m)
		}
	}

	if len(seen) != 1 {
		t.Fatalf("last_record_seconds has %d series, want 1 (only AAISP has records): %v", len(seen), seen)
	}
	if age, ok := seen["AAISP"]; !ok || age < 0 || age > 60 {
		t.Errorf("last_record_seconds{AAISP} = %v (present=%v), want a small non-negative age", age, ok)
	}
}

// getconfig failing must not take the rest of the collector down with it. The
// existing three endpoints carry the service's live state and are the more
// important signal; losing the expected set should cost only the expected set.
func TestNetflowCollector_SurvivesGetconfigFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/netflow/isEnabled", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"netflow": 1, "local": 0}`))
	})
	mux.HandleFunc("/api/diagnostics/netflow/status", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status": "active", "collectors": "3"}`))
	})
	mux.HandleFunc("/api/diagnostics/netflow/cacheStats", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/api/diagnostics/netflow/getconfig", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := &netflowCollector{subsystem: NetflowSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, newCollectorTestClient(t, server))

	// 2 isEnabled + 2 status, and nothing from getconfig.
	if len(metrics) != 4 {
		t.Fatalf("got %d metrics after a getconfig failure, want the 4 unaffected ones", len(metrics))
	}
	for _, m := range metrics {
		if containsString(m.Desc().String(), "capture_") {
			t.Errorf("capture metric %s emitted despite the fetch failing", m.Desc())
		}
	}
}

// netflowRecOn builds a NetFlow-source record attributed to iface, matching what
// the receiver hands the store.
func netflowRecOn(iface string) flow.Record {
	return flow.Record{
		Source: flow.SourceNetflow, Proto: 6,
		SrcAddr: netip.MustParseAddr("192.0.2.1"), DstAddr: netip.MustParseAddr("198.51.100.1"),
		Direction: flow.DirectionOutbound,
		Out:       flow.Iface{Name: iface},
		NF:        flow.Counters{TxBytes: 100, TxPackets: 1, Present: true},
	}
}
