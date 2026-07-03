package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestServicesCollector_Update(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{"id":"1","name":"openssh","description":"Secure Shell Daemon","locked":0,"running":1},
				{"id":"2","name":"configd","description":"System Configuration Daemon","locked":0,"running":1},
				{"id":"3","name":"dnsmasq","description":"Dnsmasq DNS","locked":0,"running":0}
			],
			"total": 3,
			"rowCount": 3,
			"current": 1
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &servicesCollector{subsystem: ServicesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 2 totals (running + stopped) + 3 per-service status = 5
	expectedCount := 5
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

// TestServicesCollector_DuplicateNameDescription guards #85: two services sharing
// both name and description (differing only in the dropped id) must not emit
// duplicate label tuples, which would fail the whole scrape.
func TestServicesCollector_DuplicateNameDescription(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{"id":"1","name":"dpinger","description":"dpinger","locked":0,"running":1},
				{"id":"2","name":"dpinger","description":"dpinger","locked":0,"running":1}
			],
			"total": 2,
			"rowCount": 2,
			"current": 1
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &servicesCollector{subsystem: ServicesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)
}

func TestServicesCollector_Name(t *testing.T) {
	c := &servicesCollector{subsystem: ServicesSubsystem}
	if c.Name() != ServicesSubsystem {
		t.Errorf("expected %s, got %s", ServicesSubsystem, c.Name())
	}
}
