package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

func acmeTestMux(t *testing.T, response string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/acmeclient/certificates/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(response))
	})
	return mux
}

func TestACMECollector_Update_Normal(t *testing.T) {
	response := `{
		"total": 2,
		"rowCount": 2,
		"current": 1,
		"rows": [
			{
				"uuid": "aaaa-1111",
				"enabled": "1",
				"name": "example.com",
				"description": "Primary cert",
				"altNames": "www.example.com",
				"lastUpdate": 1700000000,
				"statusCode": 200,
				"statusLastUpdate": 1700000100
			},
			{
				"uuid": "bbbb-2222",
				"enabled": "0",
				"name": "other.example.com",
				"description": "Other cert",
				"altNames": "",
				"lastUpdate": 1699000000,
				"statusCode": 400,
				"statusLastUpdate": 1699000050
			}
		]
	}`

	mux := acmeTestMux(t, response)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &acmeCollector{subsystem: ACMESubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Expected:
	//   1 certificates_total
	//   Per cert (2 certs): enabled + status_code + info + last_update + status_last_update = 5 each
	//   Total = 1 + 2*5 = 11
	expectedCount := 11
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Verify certificates_total
	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "certificates_total") {
			val := getMetricValue(m)
			if val != 2 {
				t.Errorf("expected certificates_total=2, got %v", val)
			}
		}
	}

	// Verify enabled metric for cert[0] (enabled=1) and cert[1] (enabled=0)
	foundEnabled := 0
	for _, m := range metrics {
		desc := m.Desc().String()
		if !strings.Contains(desc, "certificate_enabled") {
			continue
		}
		labels := getMetricLabels(m)
		val := getMetricValue(m)
		if labels["name"] == "example.com" {
			if val != 1 {
				t.Errorf("expected enabled=1 for example.com, got %v", val)
			}
			foundEnabled++
		}
		if labels["name"] == "other.example.com" {
			if val != 0 {
				t.Errorf("expected enabled=0 for other.example.com, got %v", val)
			}
			foundEnabled++
		}
	}
	if foundEnabled != 2 {
		t.Errorf("expected 2 certificate_enabled metrics, found %d", foundEnabled)
	}

	// Verify status_code metrics
	for _, m := range metrics {
		desc := m.Desc().String()
		if !strings.Contains(desc, "certificate_status_code") {
			continue
		}
		labels := getMetricLabels(m)
		val := getMetricValue(m)
		if labels["name"] == "example.com" && val != 200 {
			t.Errorf("expected status_code=200 for example.com, got %v", val)
		}
		if labels["name"] == "other.example.com" && val != 400 {
			t.Errorf("expected status_code=400 for other.example.com, got %v", val)
		}
	}

	// Verify last_update timestamp emitted (>0)
	for _, m := range metrics {
		desc := m.Desc().String()
		if !strings.Contains(desc, "certificate_last_update_timestamp_seconds") {
			continue
		}
		labels := getMetricLabels(m)
		val := getMetricValue(m)
		if labels["name"] == "example.com" && val != 1700000000 {
			t.Errorf("expected last_update=1700000000 for example.com, got %v", val)
		}
	}

	// Verify info metric carries alt_names label
	for _, m := range metrics {
		desc := m.Desc().String()
		if !strings.Contains(desc, "certificate_info") {
			continue
		}
		labels := getMetricLabels(m)
		val := getMetricValue(m)
		if val != 1 {
			t.Errorf("expected info metric value=1, got %v", val)
		}
		if labels["name"] == "example.com" && labels["alt_names"] != "www.example.com" {
			t.Errorf("expected alt_names='www.example.com', got %q", labels["alt_names"])
		}
	}
}

func TestACMECollector_Update_TimestampsSkippedWhenZero(t *testing.T) {
	// When lastUpdate and statusLastUpdate are 0, those timestamp metrics must
	// not be emitted.
	response := `{
		"total": 1,
		"rowCount": 1,
		"current": 1,
		"rows": [
			{
				"uuid": "cccc-3333",
				"enabled": "1",
				"name": "new.example.com",
				"description": "New cert",
				"altNames": [],
				"lastUpdate": 0,
				"statusCode": 100,
				"statusLastUpdate": 0
			}
		]
	}`

	mux := acmeTestMux(t, response)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &acmeCollector{subsystem: ACMESubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Expected: 1 total + enabled + status_code + info = 4 (no timestamp metrics)
	expectedCount := 4
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics (timestamps skipped), got %d", expectedCount, len(metrics))
	}

	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "last_update_timestamp") || strings.Contains(desc, "status_last_update") {
			t.Errorf("expected no timestamp metrics when value is 0, but got: %s", desc)
		}
	}
}

func TestACMECollector_Update_Empty(t *testing.T) {
	response := `{
		"total": 0,
		"rowCount": 0,
		"current": 1,
		"rows": []
	}`

	mux := acmeTestMux(t, response)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &acmeCollector{subsystem: ACMESubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Only certificates_total = 0
	expectedCount := 1
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
	if val := getMetricValue(metrics[0]); val != 0 {
		t.Errorf("expected certificates_total=0, got %v", val)
	}
}

func TestACMECollector_Update_ArrayQuirks(t *testing.T) {
	// OPNsense PHP may serialize unset fields as [] — must not panic.
	response := `{
		"total": 1,
		"rowCount": 1,
		"current": 1,
		"rows": [
			{
				"uuid": "dddd-4444",
				"enabled": "1",
				"name": "quirky.example.com",
				"description": [],
				"altNames": [],
				"lastUpdate": [],
				"statusCode": [],
				"statusLastUpdate": []
			}
		]
	}`

	mux := acmeTestMux(t, response)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &acmeCollector{subsystem: ACMESubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	// Should not panic or error; timestamps are 0 so they are skipped.
	metrics := collectMetrics(t, c, client)

	// 1 total + enabled + status_code + info = 4
	expectedCount := 4
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

// TestAcmeCollector_Update_PluginAbsent guards #87: with os-acme-client absent
// (endpoint 404s) the collector must emit nothing rather than certificates_total=0.
func TestAcmeCollector_Update_PluginAbsent(t *testing.T) {
	mux := http.NewServeMux() // no handlers: all requests 404 → plugin absent
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &acmeCollector{subsystem: ACMESubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when plugin absent (404), got %d", len(metrics))
	}
}

func TestACMECollector_Name(t *testing.T) {
	c := &acmeCollector{subsystem: ACMESubsystem}
	if c.Name() != ACMESubsystem {
		t.Errorf("expected %s, got %s", ACMESubsystem, c.Name())
	}
}
