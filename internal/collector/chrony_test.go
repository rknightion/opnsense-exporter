package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

const chronyTestTrackingFixture = `Reference ID    : C0A80001 (ntp1.example.net)
Stratum         : 3
Ref time (UTC)  : Tue Jun 09 08:00:00 2026
System time     : 0.000123456 seconds slow of NTP time
Last offset     : -0.000012345 seconds
RMS offset      : 0.000098765 seconds
Frequency       : 12.345 ppm fast
Residual freq   : -0.001 ppm
Skew            : 0.123 ppm
Root delay      : 0.012345678 seconds
Root dispersion : 0.001234567 seconds
Update interval : 64.5 seconds
Leap status     : Normal`

const chronyTestSourcesFixture = `MS Name/IP address         Stratum Poll Reach LastRx Last sample
===============================================================================
^* ntp1.example.net              2   6   377    34   +123us[ +145us] +/-   12ms
^+ ntp2.example.net              2   6   377    35   -250us[ -251us] +/-   15ms
^? 203.0.113.5                   0   8     0     -     +0ns[   +0ns] +/-    0ns`

const chronyTestSourceStatsFixture = `Name/IP Address            NP  NR  Span  Frequency  Freq Skew  Offset  Std Dev
==============================================================================
ntp1.example.net           25  12  19m     -0.002      0.060   -45us    113us
ntp2.example.net           20  10  17m     +0.010      0.080  +120us    220us`

func chronyCollectorMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/chrony/service/chronytracking", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response":"` + escapeCollectorJSON(chronyTestTrackingFixture) + `"}`))
	})
	mux.HandleFunc("/api/chrony/service/chronysources", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response":"` + escapeCollectorJSON(chronyTestSourcesFixture) + `"}`))
	})
	mux.HandleFunc("/api/chrony/service/chronysourcestats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response":"` + escapeCollectorJSON(chronyTestSourceStatsFixture) + `"}`))
	})
	mux.HandleFunc("/api/chrony/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	return mux
}

// escapeCollectorJSON escapes a string for use as a JSON string value.
func escapeCollectorJSON(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b = append(b, '\\', '"')
		case '\\':
			b = append(b, '\\', '\\')
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\t':
			b = append(b, '\\', 't')
		default:
			b = append(b, c)
		}
	}
	return string(b)
}

func TestChronyCollector_Update_Normal(t *testing.T) {
	server := httptest.NewServer(chronyCollectorMux(t))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &chronyCollector{subsystem: ChronySubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// service_running = 1
	// tracking gauges = 11 (stratum, system_time_offset, last_offset, rms_offset,
	//   frequency_ppm, residual_frequency_ppm, skew_ppm, root_delay,
	//   root_dispersion, update_interval, leap_status)
	// tracking_info = 1
	// sources_total = 1
	// per source: selected + stratum + reachability = 3 × 3 sources = 9
	// last_rx: 2 sources (^? has LastRx="-" → HasLastRx=false → skipped)
	// offset: 3 sources (^? "+0ns" parses ok=true → HasOffset=true)
	// sourcestats: stddev + samples = 2 × 2 rows = 4
	// total = 1 + 11 + 1 + 1 + 9 + 2 + 3 + 4 = 32
	expected := 32
	if len(metrics) != expected {
		t.Errorf("expected %d metrics, got %d", expected, len(metrics))
		for _, m := range metrics {
			t.Logf("  %s", m.Desc().String())
		}
	}

	// Spot-check specific metrics.
	var foundSelected, foundReach bool
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		val := getMetricValue(m)

		switch {
		case strings.Contains(desc, "chrony_source_selected"):
			if labels["source"] == "ntp1.example.net" {
				foundSelected = true
				if val != 1 {
					t.Errorf("source_selected for ntp1 = %v, want 1", val)
				}
			}
			if labels["source"] == "ntp2.example.net" && val != 0 {
				t.Errorf("source_selected for ntp2 = %v, want 0 (state=+)", val)
			}
		case strings.Contains(desc, "chrony_source_reachability"):
			if labels["source"] == "ntp1.example.net" {
				foundReach = true
				if val != 255 {
					t.Errorf("source_reachability for ntp1 = %v, want 255", val)
				}
			}
		case strings.Contains(desc, "chrony_service_running"):
			if val != 1 {
				t.Errorf("service_running = %v, want 1", val)
			}
		case strings.Contains(desc, "chrony_stratum"):
			if val != 3 {
				t.Errorf("stratum = %v, want 3", val)
			}
		}
	}

	if !foundSelected {
		t.Error("did not find source_selected metric for ntp1.example.net")
	}
	if !foundReach {
		t.Error("did not find source_reachability metric for ntp1.example.net")
	}
}

func TestChronyCollector_Update_PluginAbsent(t *testing.T) {
	mux := http.NewServeMux() // no handlers → all 404
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &chronyCollector{subsystem: ChronySubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when plugin absent, got %d", len(metrics))
	}
}

// TestChronyCollector_Update_SourcesFetchFailure guards #163: when the sources
// sub-fetch fails (transient 500), sources_total and per-source metrics must be
// omitted, not emitted as a false 0. Tracking metrics still appear.
func TestChronyCollector_Update_SourcesFetchFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/chrony/service/chronytracking", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response":"` + escapeCollectorJSON(chronyTestTrackingFixture) + `"}`))
	})
	mux.HandleFunc("/api/chrony/service/chronysources", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	mux.HandleFunc("/api/chrony/service/chronysourcestats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response":"` + escapeCollectorJSON(chronyTestSourceStatsFixture) + `"}`))
	})
	mux.HandleFunc("/api/chrony/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &chronyCollector{subsystem: ChronySubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	sawTracking := false
	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "sources_total") || strings.Contains(desc, "source_selected") ||
			strings.Contains(desc, "source_stratum") || strings.Contains(desc, "source_reachability") {
			t.Errorf("sources metric must be omitted on sources-fetch failure: %s", desc)
		}
		if strings.Contains(desc, "chrony_stratum") {
			sawTracking = true
		}
	}
	if !sawTracking {
		t.Error("expected tracking metrics to still be emitted despite sources-fetch failure")
	}
}

func TestChronyCollector_Name(t *testing.T) {
	c := &chronyCollector{subsystem: ChronySubsystem}
	if c.Name() != ChronySubsystem {
		t.Errorf("expected %s, got %s", ChronySubsystem, c.Name())
	}
}
