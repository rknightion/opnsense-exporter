package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

func siproxdTestMux(t *testing.T, response string, status int) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/siproxd/service/showregistrations", func(w http.ResponseWriter, r *http.Request) {
		if status != 0 {
			w.WriteHeader(status)
		}
		w.Write([]byte(response))
	})
	return mux
}

func TestSiproxdCollector_Update_Registrations(t *testing.T) {
	response := `{"response":"*:1:1234567890\nudp:alice@10.0.0.5:5060;tag=abc\nudp:alice@203.0.113.5:5060;tag=abc\nudp:alice@203.0.113.5:5060;tag=abc\n*:0:0\nudp:bob@10.0.0.6:5060;tag=def\nudp:bob@203.0.113.6:5060;tag=def\nudp:bob@203.0.113.6:5060;tag=def"}`

	server := httptest.NewServer(siproxdTestMux(t, response, 0))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &siproxdCollector{subsystem: SiproxdSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric (registrations gauge), got %d", len(metrics))
	}
	if !strings.Contains(metrics[0].Desc().String(), "siproxd_registrations") {
		t.Errorf("expected siproxd_registrations metric, got %s", metrics[0].Desc().String())
	}
	if val := getMetricValue(metrics[0]); val != 1 {
		t.Errorf("expected 1 active registration, got %v", val)
	}
}

func TestSiproxdCollector_Update_Empty(t *testing.T) {
	server := httptest.NewServer(siproxdTestMux(t, `{"response":""}`, 0))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &siproxdCollector{subsystem: SiproxdSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric even when there are 0 registrations (plugin present), got %d", len(metrics))
	}
	if val := getMetricValue(metrics[0]); val != 0 {
		t.Errorf("expected 0 registrations, got %v", val)
	}
}

func TestSiproxdCollector_Update_FeatureAbsent(t *testing.T) {
	// 404 -> Present=false -> fully silent (os-siproxd plugin not installed).
	mux := http.NewServeMux() // no handlers -> all 404
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &siproxdCollector{subsystem: SiproxdSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when the os-siproxd plugin is absent, got %d", len(metrics))
	}
}

func TestSiproxdCollector_Name(t *testing.T) {
	c := &siproxdCollector{subsystem: SiproxdSubsystem}
	if c.Name() != SiproxdSubsystem {
		t.Errorf("expected %s, got %s", SiproxdSubsystem, c.Name())
	}
}
