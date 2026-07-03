package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

func captivePortalCollectorMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	// Real API shape for sequential-from-0 zoneids: a JSON array, not an object (#73).
	mux.HandleFunc("/api/captiveportal/session/zones", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`["Guest WiFi", "Lab"]`))
	})
	mux.HandleFunc("/api/captiveportal/session/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total": 3, "rowCount": 3, "current": 1, "rows": [
		  {"sessionId": "abc", "zoneid": "0"},
		  {"sessionId": "def", "zoneid": "0"},
		  {"sessionId": "ghi", "zoneid": "1"}]}`))
	})
	mux.HandleFunc("/api/captiveportal/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	return mux
}

func TestCaptivePortalCollector_Update_Normal(t *testing.T) {
	server := httptest.NewServer(captivePortalCollectorMux(t))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &captivePortalCollector{subsystem: CaptivePortalSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// zones_total (1) + sessions_total (1) + zone_sessions × 2 (2) + service_running (1) = 5
	expected := 5
	if len(metrics) != expected {
		t.Errorf("expected %d metrics, got %d", expected, len(metrics))
	}

	var foundZonesTotal, foundSessionsTotal, foundServiceRunning bool
	zoneSessionCounts := map[string]float64{}
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		val := getMetricValue(m)
		switch {
		case strings.Contains(desc, "captiveportal_zones_total"):
			foundZonesTotal = true
			if val != 2 {
				t.Errorf("zones_total expected 2, got %v", val)
			}
		case strings.Contains(desc, "captiveportal_sessions_total"):
			foundSessionsTotal = true
			if val != 3 {
				t.Errorf("sessions_total expected 3, got %v", val)
			}
		case strings.Contains(desc, "captiveportal_zone_sessions"):
			zoneSessionCounts[labels["zone_id"]] = val
		case strings.Contains(desc, "captiveportal_service_running"):
			foundServiceRunning = true
			if val != 1 {
				t.Errorf("service_running expected 1, got %v", val)
			}
		}
	}

	if !foundZonesTotal {
		t.Error("missing zones_total metric")
	}
	if !foundSessionsTotal {
		t.Error("missing sessions_total metric")
	}
	if !foundServiceRunning {
		t.Error("missing service_running metric")
	}
	if zoneSessionCounts["0"] != 2 {
		t.Errorf("zone 0 sessions expected 2, got %v", zoneSessionCounts["0"])
	}
	if zoneSessionCounts["1"] != 1 {
		t.Errorf("zone 1 sessions expected 1, got %v", zoneSessionCounts["1"])
	}
}

func TestCaptivePortalCollector_Update_Unconfigured(t *testing.T) {
	// Core feature: present but unconfigured. Totals still emitted so the
	// dashboard sentinel query (zones_total > 0) can correctly hide the tab.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/captiveportal/session/zones", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/api/captiveportal/session/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total": 0, "rowCount": 0, "current": 1, "rows": []}`))
	})
	mux.HandleFunc("/api/captiveportal/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"disabled"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &captivePortalCollector{subsystem: CaptivePortalSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// zones_total (0) + sessions_total (0) + service_running = 3
	expected := 3
	if len(metrics) != expected {
		t.Errorf("expected %d metrics (unconfigured), got %d", expected, len(metrics))
	}

	for _, m := range metrics {
		desc := m.Desc().String()
		val := getMetricValue(m)
		if strings.Contains(desc, "captiveportal_zones_total") && val != 0 {
			t.Errorf("zones_total expected 0, got %v", val)
		}
		if strings.Contains(desc, "captiveportal_sessions_total") && val != 0 {
			t.Errorf("sessions_total expected 0, got %v", val)
		}
		if strings.Contains(desc, "captiveportal_service_running") && val != 0 {
			t.Errorf("service_running expected 0 (disabled), got %v", val)
		}
	}
}

func TestCaptivePortalCollector_Update_FeatureAbsent(t *testing.T) {
	// 404 on zones → Present=false → fully silent, no service probe.
	mux := http.NewServeMux() // no handlers, all 404
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &captivePortalCollector{subsystem: CaptivePortalSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when feature absent, got %d", len(metrics))
	}
}

func TestCaptivePortalCollector_Name(t *testing.T) {
	c := &captivePortalCollector{subsystem: CaptivePortalSubsystem}
	if c.Name() != CaptivePortalSubsystem {
		t.Errorf("expected %s, got %s", CaptivePortalSubsystem, c.Name())
	}
}
