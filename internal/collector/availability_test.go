package collector

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

func TestAvailabilityCollector_EmitsMetricOnlyForAvailableFeatures(t *testing.T) {
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
	if len(metrics) != 2 {
		t.Fatalf("expected 2 metrics (smart, vnstat available; tor absent), got %d", len(metrics))
	}

	byFeature := map[string]map[string]string{}
	for _, m := range metrics {
		labels := getMetricLabels(m)
		byFeature[labels["feature"]] = labels
		if getMetricValue(m) != 1 {
			t.Errorf("expected value=1 for feature %q, got %v", labels["feature"], getMetricValue(m))
		}
	}

	if _, ok := byFeature[TorSubsystem]; ok {
		t.Error("tor is unavailable and must be ABSENT, not emitted with value 0")
	}
	if labels, ok := byFeature[SMARTSubsystem]; !ok {
		t.Error("expected a smart series")
	} else if labels["enabled"] != "false" {
		t.Errorf("expected smart enabled=false, got %q", labels["enabled"])
	}
	if labels, ok := byFeature[VnstatSubsystem]; !ok {
		t.Error("expected a vnstat series")
	} else if labels["enabled"] != "true" {
		t.Errorf("expected vnstat enabled=true, got %q", labels["enabled"])
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
	firstLogCount := strings.Count(buf.String(), "feature available but not enabled")
	if firstLogCount != 1 {
		t.Fatalf("expected exactly 1 log line after the first probe, got %d:\n%s", firstLogCount, buf.String())
	}

	// Second probe: identical result. Must NOT log again.
	buf.Reset()
	collectMetrics(t, c, client)
	if got := strings.Count(buf.String(), "feature available but not enabled"); got != 0 {
		t.Errorf("expected no new log lines on an unchanged probe, got %d:\n%s", got, buf.String())
	}

	// Third probe: tor becomes available too — the set changed. Must log again.
	buf.Reset()
	present[TorSubsystem] = true
	collectMetrics(t, c, client)
	if got := strings.Count(buf.String(), "feature available but not enabled"); got == 0 {
		t.Error("expected a new log line once the availability set changed")
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
}
