package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

func clamavTestMux(t *testing.T, response string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/clamav/service/version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(response))
	})
	return mux
}

// TestClamAVCollector_Update_Normal covers the real post-freshclam payload
// shape captured from a live OPNsense 26.7-devel box.
func TestClamAVCollector_Update_Normal(t *testing.T) {
	response := `{"version":{"daily":" version 28059, sigs: 355490, built on Mon Jul 13 07:25:07 2026","main":" version 63, sigs: 3287027, built on Tue Dec 16 23:18:22 2025","bytecode":" version 339, sigs: 80, built on Thu Sep 11 13:29:19 2025","signatures":" 3642597","clamav":" 1.5.2"}}`

	mux := clamavTestMux(t, response)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &clamavCollector{subsystem: ClamAVSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Expected: 1 info + 1 signatures + 3 db_version + 3 db_built_timestamp = 8
	expectedCount := 8
	if len(metrics) != expectedCount {
		t.Fatalf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		val := getMetricValue(m)

		switch {
		case strings.Contains(desc, "version_info"):
			if val != 1 {
				t.Errorf("expected version_info=1, got %v", val)
			}
			if labels["version"] != "1.5.2" {
				t.Errorf("expected version='1.5.2' (leading space trimmed), got %q", labels["version"])
			}
		case strings.Contains(desc, "clamav_signatures"):
			if val != 3642597 {
				t.Errorf("expected signatures=3642597, got %v", val)
			}
		case strings.Contains(desc, "signature_db_version"):
			switch labels["db"] {
			case "daily":
				if val != 28059 {
					t.Errorf("expected daily db version 28059, got %v", val)
				}
			case "main":
				if val != 63 {
					t.Errorf("expected main db version 63, got %v", val)
				}
			case "bytecode":
				if val != 339 {
					t.Errorf("expected bytecode db version 339, got %v", val)
				}
			default:
				t.Errorf("unexpected db label %q", labels["db"])
			}
		case strings.Contains(desc, "signature_db_built_timestamp_seconds"):
			if val <= 0 {
				t.Errorf("expected a positive built timestamp for db %q, got %v", labels["db"], val)
			}
		default:
			t.Errorf("unexpected metric: %s", desc)
		}
	}
}

// TestClamAVCollector_Update_NeverRan covers the never-ran shape: no
// daily/main/bytecode keys at all, signatures=" 0". Only info + signatures
// metrics are emitted; no db_version/db_built_timestamp series.
func TestClamAVCollector_Update_NeverRan(t *testing.T) {
	response := `{"version":{"signatures":" 0","clamav":" 1.5.2"}}`

	mux := clamavTestMux(t, response)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &clamavCollector{subsystem: ClamAVSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Expected: 1 info + 1 signatures (=0) = 2. No db metrics at all.
	expectedCount := 2
	if len(metrics) != expectedCount {
		t.Fatalf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "signature_db_version") || strings.Contains(desc, "signature_db_built_timestamp") {
			t.Errorf("expected no per-database metrics in the never-ran shape, got: %s", desc)
		}
		if strings.Contains(desc, "clamav_signatures") {
			if val := getMetricValue(m); val != 0 {
				t.Errorf("expected signatures=0, got %v", val)
			}
		}
	}
}

// TestClamAVCollector_Update_PluginAbsent guards the plugin-gated contract:
// with os-clamav absent (endpoint 404s) the collector must emit nothing.
func TestClamAVCollector_Update_PluginAbsent(t *testing.T) {
	mux := http.NewServeMux() // no handlers: all requests 404 → plugin absent
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &clamavCollector{subsystem: ClamAVSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when plugin absent (404), got %d", len(metrics))
	}
}

// TestClamAVCollector_Update_MalformedBuildDate ensures a database whose
// version/sigs numbers parse but whose date fragment does not still emits its
// db_version series, just without a built_timestamp series.
func TestClamAVCollector_Update_MalformedBuildDate(t *testing.T) {
	response := `{"version":{"daily":" version 28059, sigs: 355490, built on not-a-real-date","signatures":" 100","clamav":" 1.5.2"}}`

	mux := clamavTestMux(t, response)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &clamavCollector{subsystem: ClamAVSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	foundVersion := false
	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "signature_db_built_timestamp") {
			t.Errorf("expected no built_timestamp metric for an unparseable date, got: %s", desc)
		}
		if strings.Contains(desc, "signature_db_version") {
			foundVersion = true
			if val := getMetricValue(m); val != 28059 {
				t.Errorf("expected db version 28059, got %v", val)
			}
		}
	}
	if !foundVersion {
		t.Error("expected a signature_db_version metric for 'daily' even with an unparseable date")
	}
}

func TestClamAVCollector_Name(t *testing.T) {
	c := &clamavCollector{subsystem: ClamAVSubsystem}
	if c.Name() != ClamAVSubsystem {
		t.Errorf("expected %s, got %s", ClamAVSubsystem, c.Name())
	}
}
