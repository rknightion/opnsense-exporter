package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

// crowdsecCollectorAlertsFixture is a minimal bootgrid response for alerts/search.
const crowdsecCollectorAlertsFixture = `{"total": 7, "rowCount": 1, "current": 1, "rows": []}`

// crowdsecCollectorDecisionsFixture demonstrates count != rows (D3).
const crowdsecCollectorDecisionsFixture = `{"total": 4321, "rowCount": 1, "current": 1, "rows": [{"id": 1}]}`

// crowdsecCollectorBouncersFixture has one valid bouncer with a last_seen timestamp.
const crowdsecCollectorBouncersFixture = `{"total": 1, "rowCount": 1, "current": 1, "rows": [
  {"name": "cs-firewall-bouncer", "type": "crowdsec-firewall-bouncer",
   "valid": true, "last_seen": "2026-06-09T08:00:00Z"}]}`

// crowdsecCollectorMachinesFixture has one validated machine with a last_seen timestamp.
const crowdsecCollectorMachinesFixture = `{"total": 1, "rowCount": 1, "current": 1, "rows": [
  {"name": "fw1-machine", "validated": true, "last_seen": "2026-06-09T08:00:00Z"}]}`

// crowdsecMessageEnvelopeCollector is the HTTP-200 error envelope.
const crowdsecMessageEnvelopeCollector = `{"message": "unable to retrieve data"}`

// crowdsecCollectorMux builds a ServeMux for the "normal" case (all endpoints OK).
func crowdsecCollectorMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/crowdsec/alerts/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecCollectorAlertsFixture))
	})
	mux.HandleFunc("/api/crowdsec/decisions/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecCollectorDecisionsFixture))
	})
	mux.HandleFunc("/api/crowdsec/bouncers/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecCollectorBouncersFixture))
	})
	mux.HandleFunc("/api/crowdsec/machines/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecCollectorMachinesFixture))
	})
	mux.HandleFunc("/api/crowdsec/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	return mux
}

// TestCrowdSecCollector_Update_Normal expects 9 metrics:
//
//	alerts_total (1) + decisions_total (1) + bouncers_total (1) + machines_total (1)
//	+ bouncer_valid (1) + bouncer_last_pull (1)
//	+ machine_validated (1) + machine_heartbeat (1)
//	+ service_running (1)
//	= 9
func TestCrowdSecCollector_Update_Normal(t *testing.T) {
	server := httptest.NewServer(crowdsecCollectorMux(t))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &crowdsecCollector{subsystem: CrowdSecSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	expected := 9
	if len(metrics) != expected {
		t.Errorf("expected %d metrics, got %d", expected, len(metrics))
		for _, m := range metrics {
			t.Logf("  %s", m.Desc().String())
		}
	}

	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		val := getMetricValue(m)
		switch {
		case strings.Contains(desc, "crowdsec_alerts_total"):
			if val != 7 {
				t.Errorf("alerts_total wrong: %v (expected 7)", val)
			}
		case strings.Contains(desc, "crowdsec_decisions_total"):
			if val != 4321 {
				t.Errorf("decisions_total wrong: %v (expected 4321)", val)
			}
		case strings.Contains(desc, "crowdsec_bouncers_total"):
			if val != 1 {
				t.Errorf("bouncers_total wrong: %v (expected 1)", val)
			}
		case strings.Contains(desc, "crowdsec_bouncer_valid"):
			if labels["name"] != "cs-firewall-bouncer" || val != 1 {
				t.Errorf("bouncer_valid wrong: labels=%v val=%v", labels, val)
			}
		case strings.Contains(desc, "crowdsec_machines_total"):
			if val != 1 {
				t.Errorf("machines_total wrong: %v (expected 1)", val)
			}
		case strings.Contains(desc, "crowdsec_machine_validated"):
			if labels["name"] != "fw1-machine" || val != 1 {
				t.Errorf("machine_validated wrong: labels=%v val=%v", labels, val)
			}
		case strings.Contains(desc, "crowdsec_service_running"):
			if val != 1 {
				t.Errorf("service_running wrong: %v (expected 1)", val)
			}
		}
	}
}

// TestCrowdSecCollector_Update_MessageEnvelope expects 8 metrics (no decisions_total).
func TestCrowdSecCollector_Update_MessageEnvelope(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/crowdsec/alerts/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecCollectorAlertsFixture))
	})
	mux.HandleFunc("/api/crowdsec/decisions/search", func(w http.ResponseWriter, r *http.Request) {
		// Returns the error envelope → no decisions_total metric.
		w.Write([]byte(crowdsecMessageEnvelopeCollector))
	})
	mux.HandleFunc("/api/crowdsec/bouncers/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecCollectorBouncersFixture))
	})
	mux.HandleFunc("/api/crowdsec/machines/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecCollectorMachinesFixture))
	})
	mux.HandleFunc("/api/crowdsec/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &crowdsecCollector{subsystem: CrowdSecSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	expected := 8 // no decisions_total
	if len(metrics) != expected {
		t.Errorf("expected %d metrics (no decisions_total), got %d", expected, len(metrics))
		for _, m := range metrics {
			t.Logf("  %s", m.Desc().String())
		}
	}

	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "crowdsec_decisions_total") {
			t.Error("decisions_total should not be emitted when decisions endpoint returned message envelope")
		}
	}
}

// TestCrowdSecCollector_Update_PluginAbsent expects 0 metrics when all
// endpoints return 404 (plugin not installed).
func TestCrowdSecCollector_Update_PluginAbsent(t *testing.T) {
	mux := http.NewServeMux() // no handlers → all 404
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &crowdsecCollector{subsystem: CrowdSecSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when plugin absent, got %d", len(metrics))
	}
}

// TestCrowdSecCollector_Name verifies the collector's Name() returns the subsystem.
func TestCrowdSecCollector_Name(t *testing.T) {
	c := &crowdsecCollector{subsystem: CrowdSecSubsystem}
	if c.Name() != CrowdSecSubsystem {
		t.Errorf("expected %q, got %q", CrowdSecSubsystem, c.Name())
	}
}
