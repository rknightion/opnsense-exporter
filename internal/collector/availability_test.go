package collector

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

// availabilityTestMux answers every probed feature's gating endpoint. present
// controls whether each answers success (available) or 404 (plugin absent),
// and asserts the probe never follows up with the collector's own expensive
// per-item calls.
func availabilityTestMux(t *testing.T, present map[string]bool) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, _ *http.Request) {
		if !present[SMARTSubsystem] {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"devices":[]}`))
	})
	mux.HandleFunc("/api/smart/service/info", func(w http.ResponseWriter, _ *http.Request) {
		t.Error("smart per-device info must never be called by the availability probe")
		w.WriteHeader(http.StatusInternalServerError)
	})

	mux.HandleFunc("/api/tor/service/circuits", func(w http.ResponseWriter, _ *http.Request) {
		if !present[TorSubsystem] {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"response":{}}`))
	})

	mux.HandleFunc("/api/vnstat/service/interface_list", func(w http.ResponseWriter, _ *http.Request) {
		if !present[VnstatSubsystem] {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"interfaces":[]}`))
	})
	mux.HandleFunc("/api/vnstat/service/get_json_data", func(w http.ResponseWriter, _ *http.Request) {
		t.Error("vnstat per-interface data must never be called by the availability probe")
		w.WriteHeader(http.StatusInternalServerError)
	})

	return mux
}

func newAvailabilityCollector(logger *slog.Logger, enabledFn FeatureEnabledFunc) *availabilityCollector {
	c := &availabilityCollector{subsystem: FeatureAvailabilitySubsystem, enabledFn: enabledFn}
	c.Register(namespace, "test", logger)
	return c
}

// Every family with a verdict gets a series, 0 as well as 1 (#525 decision 2), so
// a panel can show the plugins this box does NOT have and a plugin vanishing is
// alertable. Anything the test mux does not answer 404s, which is exactly what an
// uninstalled plugin does.
func TestAvailabilityCollector_EmitsZeroAndOneForEveryDeterminedFeature(t *testing.T) {
	mux := availabilityTestMux(t, map[string]bool{
		SMARTSubsystem:  true,
		TorSubsystem:    false,
		VnstatSubsystem: true,
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := newAvailabilityCollector(discardLogger(), func(feature string) bool {
		return feature == VnstatSubsystem // vnstat enabled, smart/tor not
	})

	metrics := collectMetrics(t, c, client)
	if len(metrics) != len(featureAvailabilityProbes) {
		t.Fatalf("got %d series, want one per probed family (%d)", len(metrics), len(featureAvailabilityProbes))
	}

	values := map[string]float64{}
	labels := map[string]map[string]string{}
	for _, m := range metrics {
		l := getMetricLabels(m)
		labels[l["feature"]] = l
		values[l["feature"]] = getMetricValue(m)
	}

	if got, ok := values[TorSubsystem]; !ok || got != 0 {
		t.Errorf("tor = %v (present=%v), want an explicit 0 — absence would be "+
			"indistinguishable from never having probed", got, ok)
	}
	if got := values[SMARTSubsystem]; got != 1 {
		t.Errorf("smart = %v, want 1", got)
	}
	if labels[SMARTSubsystem]["enabled"] != "false" {
		t.Errorf("smart enabled = %q, want false", labels[SMARTSubsystem]["enabled"])
	}
	if labels[VnstatSubsystem]["enabled"] != "true" {
		t.Errorf("vnstat enabled = %q, want true", labels[VnstatSubsystem]["enabled"])
	}
	// A family the mux never heard of must read 0, not vanish.
	if got, ok := values[CrowdSecSubsystem]; !ok || got != 0 {
		t.Errorf("crowdsec = %v (present=%v), want 0 — its route 404s here", got, ok)
	}
}

// An enabled collector already calls its gating endpoint every poll, so probing it
// again is duplicate load on the firewall for a question its own traffic answered
// (#525 decision 1). The mux fails the test if the probe asks anyway.
func TestAvailabilityCollector_DoesNotProbeWhatTheCollectorsAlreadyObserved(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/vnstat/service/interface_list", func(w http.ResponseWriter, _ *http.Request) {
		t.Error("vnstat is enabled and its route was already observed; probing it again is " +
			"duplicate load on the firewall")
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := newAvailabilityCollector(discardLogger(), func(f string) bool { return f == VnstatSubsystem })
	c.observedFn = func(name opnsense.EndpointName) (bool, bool) {
		if name == "vnstatInterfaceList" {
			return true, true
		}
		return false, false
	}

	values := map[string]float64{}
	for _, m := range collectMetrics(t, c, client) {
		values[getMetricLabels(m)["feature"]] = getMetricValue(m)
	}
	if got := values[VnstatSubsystem]; got != 1 {
		t.Errorf("vnstat = %v, want 1 from the observed route rather than a fresh probe", got)
	}
}

// A probe that cannot get an answer is not evidence of absence. A firewall that is
// briefly unreachable must not read as every plugin having been uninstalled at
// once — that would fire an alert and, through --exporter.enable-all-available,
// could shrink the exporter on the next restart.
func TestAvailabilityCollector_UnanswerableProbeKeepsThePreviousVerdict(t *testing.T) {
	present := map[string]bool{SMARTSubsystem: true}
	var broken bool
	mux := http.NewServeMux()
	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, _ *http.Request) {
		if broken {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !present[SMARTSubsystem] {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"devices":[]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := newAvailabilityCollector(discardLogger(), func(string) bool { return false })

	first := map[string]float64{}
	for _, m := range collectMetrics(t, c, client) {
		first[getMetricLabels(m)["feature"]] = getMetricValue(m)
	}
	if first[SMARTSubsystem] != 1 {
		t.Fatalf("smart = %v on the first probe, want 1", first[SMARTSubsystem])
	}

	broken = true
	second := map[string]float64{}
	for _, m := range collectMetrics(t, c, client) {
		second[getMetricLabels(m)["feature"]] = getMetricValue(m)
	}
	if got, ok := second[SMARTSubsystem]; !ok || got != 1 {
		t.Errorf("smart = %v (present=%v) after an unanswerable probe, want the previous 1 "+
			"carried forward — a 500 says nothing about whether the plugin is installed", got, ok)
	}
}

// TestAvailabilityCollector_LogsOnceOnChange covers #517 decision E: the
// availability report logs only on the first probe or when the set changes,
// never on every poll — a probe repeating the same result must be silent.
func TestAvailabilityCollector_LogsOnceOnChange(t *testing.T) {
	present := map[string]bool{SMARTSubsystem: false, TorSubsystem: false, VnstatSubsystem: false}
	mux := availabilityTestMux(t, present)
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	c := newAvailabilityCollector(logger, func(string) bool { return false })

	// First probe: smart becomes available. Must log (first probe ever).
	present[SMARTSubsystem] = true
	collectMetrics(t, c, client)
	firstLogCount := strings.Count(buf.String(), "feature available but its collector is not enabled")
	if firstLogCount != 1 {
		t.Fatalf("expected exactly 1 log line after the first probe, got %d:\n%s", firstLogCount, buf.String())
	}

	// Second probe: identical result. Must NOT log again.
	buf.Reset()
	collectMetrics(t, c, client)
	if got := strings.Count(buf.String(), "feature available but its collector is not enabled"); got != 0 {
		t.Errorf("expected no new log lines on an unchanged probe, got %d:\n%s", got, buf.String())
	}

	// Third probe: tor becomes available too — the set changed. Must log again.
	buf.Reset()
	present[TorSubsystem] = true
	collectMetrics(t, c, client)
	if got := strings.Count(buf.String(), "feature available but its collector is not enabled"); got == 0 {
		t.Error("expected a new log line once the availability set changed")
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
}
