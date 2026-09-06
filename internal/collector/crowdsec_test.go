package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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

// crowdsecCollectorHubEnabledFixture is a single-row "enabled" hub-component fixture.
const crowdsecCollectorHubEnabledFixture = `{"total": 1, "rowCount": 1, "current": 1, "rows": [
  {"name": "crowdsecurity/test", "status": "enabled", "local_version": "0.1"}]}`

// crowdsecCollectorHubEmptyFixture is the empty-but-valid bootgrid shape.
const crowdsecCollectorHubEmptyFixture = `{"total": 0, "rowCount": 0, "current": 1, "rows": []}`

// crowdsecCollectorVersionFixture is the raw multi-line cscli version text — NOT JSON.
const crowdsecCollectorVersionFixture = "version: v1.7.8_1-6322745\nCodename: alphaga\n"

// registerCrowdSecCollectorHubAndVersionHandlers registers the six hub-component
// search endpoints (collections/scenarios/parsers/postoverflows get one
// "enabled" row; the two appsec endpoints are empty-but-valid) plus
// version/get, mirroring the real dev-box capture shape.
func registerCrowdSecCollectorHubAndVersionHandlers(mux *http.ServeMux) {
	for _, path := range []string{
		"/api/crowdsec/collections/search",
		"/api/crowdsec/scenarios/search",
		"/api/crowdsec/parsers/search",
		"/api/crowdsec/postoverflows/search",
	} {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(crowdsecCollectorHubEnabledFixture))
		})
	}
	for _, path := range []string{
		"/api/crowdsec/appsecconfigs/search",
		"/api/crowdsec/appsecrules/search",
	} {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(crowdsecCollectorHubEmptyFixture))
		})
	}
	mux.HandleFunc("/api/crowdsec/version/get", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecCollectorVersionFixture))
	})
}

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
	registerCrowdSecCollectorHubAndVersionHandlers(mux)
	return mux
}

// TestCrowdSecCollector_Update_Normal expects 14 metrics:
//
//	alerts (1) + decisions (1) + bouncers (1) + machines (1)
//	+ bouncer_valid (1) + bouncer_last_pull (1)
//	+ machine_validated (1) + machine_heartbeat (1)
//	+ service_running (1)
//	+ hub_items (4: collection/scenario/parser/postoverflow, each "enabled" — the
//	  two appsec endpoints are empty and contribute none)
//	+ version_info (1)
//	= 14
func TestCrowdSecCollector_Update_Normal(t *testing.T) {
	server := httptest.NewServer(crowdsecCollectorMux(t))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &crowdsecCollector{subsystem: CrowdSecSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	expected := 14
	if len(metrics) != expected {
		t.Errorf("expected %d metrics, got %d", expected, len(metrics))
		for _, m := range metrics {
			t.Logf("  %s", m.Desc().String())
		}
	}

	var hubItemCount, versionInfoCount int
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		val := getMetricValue(m)
		switch {
		case hasFqName(m, "opnsense_crowdsec_alerts"):
			if val != 7 {
				t.Errorf("alerts wrong: %v (expected 7)", val)
			}
		case hasFqName(m, "opnsense_crowdsec_decisions"):
			if val != 4321 {
				t.Errorf("decisions wrong: %v (expected 4321)", val)
			}
		case hasFqName(m, "opnsense_crowdsec_bouncers"):
			if val != 1 {
				t.Errorf("bouncers wrong: %v (expected 1)", val)
			}
		case strings.Contains(desc, "crowdsec_bouncer_valid"):
			if labels["name"] != "cs-firewall-bouncer" || val != 1 {
				t.Errorf("bouncer_valid wrong: labels=%v val=%v", labels, val)
			}
		case hasFqName(m, "opnsense_crowdsec_machines"):
			if val != 1 {
				t.Errorf("machines wrong: %v (expected 1)", val)
			}
		case strings.Contains(desc, "crowdsec_machine_validated"):
			if labels["name"] != "fw1-machine" || val != 1 {
				t.Errorf("machine_validated wrong: labels=%v val=%v", labels, val)
			}
		case strings.Contains(desc, "crowdsec_service_running"):
			if val != 1 {
				t.Errorf("service_running wrong: %v (expected 1)", val)
			}
		case strings.Contains(desc, "crowdsec_hub_items"):
			hubItemCount++
			if labels["status"] != "enabled" || val != 1 {
				t.Errorf("hub_items wrong: labels=%v val=%v", labels, val)
			}
			switch labels["component"] {
			case "collection", "scenario", "parser", "postoverflow":
			default:
				t.Errorf("unexpected hub_items component: %v", labels["component"])
			}
		case strings.Contains(desc, "crowdsec_version_info"):
			versionInfoCount++
			if labels["version"] != "v1.7.8_1-6322745" || val != 1 {
				t.Errorf("version_info wrong: labels=%v val=%v", labels, val)
			}
		}
	}
	if hubItemCount != 4 {
		t.Errorf("expected 4 hub_items series, got %d", hubItemCount)
	}
	if versionInfoCount != 1 {
		t.Errorf("expected 1 version_info series, got %d", versionInfoCount)
	}
}

// TestCrowdSecCollector_Update_MessageEnvelope expects 8 metrics (no decisions).
func TestCrowdSecCollector_Update_MessageEnvelope(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/crowdsec/alerts/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecCollectorAlertsFixture))
	})
	mux.HandleFunc("/api/crowdsec/decisions/search", func(w http.ResponseWriter, r *http.Request) {
		// Returns the error envelope → no decisions metric.
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
	registerCrowdSecCollectorHubAndVersionHandlers(mux)

	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &crowdsecCollector{subsystem: CrowdSecSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	expected := 13 // no decisions (8 - 1 + hub_items(4) + version_info(1))
	if len(metrics) != expected {
		t.Errorf("expected %d metrics (no decisions), got %d", expected, len(metrics))
		for _, m := range metrics {
			t.Logf("  %s", m.Desc().String())
		}
	}

	for _, m := range metrics {
		if hasFqName(m, "opnsense_crowdsec_decisions") {
			t.Error("decisions should not be emitted when decisions endpoint returned message envelope")
		}
	}
}

// TestCrowdSecCollector_Update_UndecodableRows guards #104: when the bouncers
// rows fail to decode, HasBouncers is false and the collector must omit
// crowdsec_bouncers entirely (not emit a false 0).
func TestCrowdSecCollector_Update_UndecodableRows(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/crowdsec/alerts/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecCollectorAlertsFixture))
	})
	mux.HandleFunc("/api/crowdsec/decisions/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecMessageEnvelopeCollector))
	})
	// Envelope decodes but rows is an object → decode fails → HasBouncers=false.
	mux.HandleFunc("/api/crowdsec/bouncers/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total": 1, "rowCount": 1, "current": 1, "rows": {"x": 1}}`))
	})
	mux.HandleFunc("/api/crowdsec/machines/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecCollectorMachinesFixture))
	})
	mux.HandleFunc("/api/crowdsec/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	registerCrowdSecCollectorHubAndVersionHandlers(mux)

	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &crowdsecCollector{subsystem: CrowdSecSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	for _, m := range metrics {
		if hasFqName(m, "opnsense_crowdsec_bouncers") {
			t.Error("bouncers must be omitted (not emitted as 0) when bouncers rows fail to decode")
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

// countingCrowdSecMux is crowdsecCollectorMux with a per-path request counter, so a
// test can assert that the firewall was NOT asked — which is the entire point of
// #575 and is invisible to an assertion that only looks at the emitted metrics.
func countingCrowdSecMux(t *testing.T) (*http.ServeMux, func(path string) int) {
	t.Helper()
	var mu sync.Mutex
	hits := map[string]int{}
	count := func(path string) { mu.Lock(); hits[path]++; mu.Unlock() }

	mux := http.NewServeMux()
	for path, body := range map[string]string{
		"/api/crowdsec/alerts/search":    crowdsecCollectorAlertsFixture,
		"/api/crowdsec/decisions/search": crowdsecCollectorDecisionsFixture,
		"/api/crowdsec/bouncers/search":  crowdsecCollectorBouncersFixture,
		"/api/crowdsec/machines/search":  crowdsecCollectorMachinesFixture,
		"/api/crowdsec/service/status":   `{"status":"running"}`,
		"/api/crowdsec/version/get":      crowdsecCollectorVersionFixture,
	} {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			count(r.URL.Path)
			_, _ = w.Write([]byte(body))
		})
	}
	for _, path := range []string{
		"/api/crowdsec/collections/search",
		"/api/crowdsec/scenarios/search",
		"/api/crowdsec/parsers/search",
		"/api/crowdsec/postoverflows/search",
	} {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			count(r.URL.Path)
			_, _ = w.Write([]byte(crowdsecCollectorHubEnabledFixture))
		})
	}
	for _, path := range []string{
		"/api/crowdsec/appsecconfigs/search",
		"/api/crowdsec/appsecrules/search",
	} {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			count(r.URL.Path)
			_, _ = w.Write([]byte(crowdsecCollectorHubEmptyFixture))
		})
	}
	return mux, func(path string) int { mu.Lock(); defer mu.Unlock(); return hits[path] }
}

func countCrowdSecHubMetrics(t *testing.T, metrics []prometheus.Metric) int {
	t.Helper()
	n := 0
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "crowdsec_hub_items") {
			n++
		}
	}
	return n
}

// TestCrowdSecCollector_HubSubCadence_SkipsFetchButKeepsSeries is the core
// assertion of #575, and it asserts BOTH halves because either one alone would be a
// bug: the second poll must not touch the six hub endpoints, and it must still emit
// exactly the same hub gauges. A version that skipped the fetch and dropped the
// series would look like a saving while actually deleting data for 14 of every 15
// minutes.
func TestCrowdSecCollector_HubSubCadence_SkipsFetchButKeepsSeries(t *testing.T) {
	mux, hits := countingCrowdSecMux(t)
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &crowdsecCollector{subsystem: CrowdSecSubsystem, hubCadence: newSubCadence(15 * time.Minute)}
	c.Register(namespace, "test", promslog.NewNopLogger())

	first := collectMetrics(t, c, client)
	wantHub := countCrowdSecHubMetrics(t, first)
	if wantHub == 0 {
		t.Fatal("precondition: the first poll emitted no hub items")
	}
	if got := hits("/api/crowdsec/collections/search"); got != 1 {
		t.Fatalf("precondition: collections fetched %d times on the first poll, want 1", got)
	}

	second := collectMetrics(t, c, client)

	for _, path := range []string{
		"/api/crowdsec/collections/search",
		"/api/crowdsec/scenarios/search",
		"/api/crowdsec/parsers/search",
		"/api/crowdsec/postoverflows/search",
		"/api/crowdsec/appsecconfigs/search",
		"/api/crowdsec/appsecrules/search",
	} {
		if got := hits(path); got != 1 {
			t.Errorf("%s was fetched %d times across two polls, want 1: the hub half must be "+
				"gated to crowdsecHubInterval", path, got)
		}
	}
	// The live half is NOT gated and must still be fetched every poll.
	if got := hits("/api/crowdsec/alerts/search"); got != 2 {
		t.Errorf("alerts fetched %d times across two polls, want 2: the live half must keep the "+
			"collector's own tier", got)
	}
	if got := countCrowdSecHubMetrics(t, second); got != wantHub {
		t.Errorf("second poll emitted %d hub_items series, want the same %d as the first: a "+
			"skipped hub fetch must re-emit the last good counts, not drop the series", got, wantHub)
	}
}

// TestCrowdSecCollector_HubSubCadence_FailedFetchRetriesNextPoll pins the reason
// the cadence is marked only on a fetch that produced items. If it were marked on
// every attempt, one hub read failing (a message envelope, an undecodable rows
// shape) would leave the hub gauges absent — never having had a good value — for a
// full fifteen minutes, with nothing saying why.
func TestCrowdSecCollector_HubSubCadence_FailedFetchRetriesNextPoll(t *testing.T) {
	var mu sync.Mutex
	hubCalls := 0
	failFirst := true

	mux := crowdsecCollectorMux(t)
	// Re-register the four content-bearing hub endpoints to fail on the first pass.
	failing := http.NewServeMux()
	failing.HandleFunc("/api/crowdsec/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/crowdsec/collections/search", "/api/crowdsec/scenarios/search",
			"/api/crowdsec/parsers/search", "/api/crowdsec/postoverflows/search",
			"/api/crowdsec/appsecconfigs/search", "/api/crowdsec/appsecrules/search":
			mu.Lock()
			hubCalls++
			envelope := failFirst
			mu.Unlock()
			if envelope {
				_, _ = w.Write([]byte(crowdsecMessageEnvelopeCollector))
				return
			}
			_, _ = w.Write([]byte(crowdsecCollectorHubEnabledFixture))
		default:
			mux.ServeHTTP(w, r)
		}
	})

	server := httptest.NewServer(failing)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &crowdsecCollector{subsystem: CrowdSecSubsystem, hubCadence: newSubCadence(15 * time.Minute)}
	c.Register(namespace, "test", promslog.NewNopLogger())

	first := collectMetrics(t, c, client)
	if got := countCrowdSecHubMetrics(t, first); got != 0 {
		t.Fatalf("precondition: hub read returned the message envelope but %d hub series were "+
			"emitted; a never-successful fetch must emit nothing, not a fabricated zero", got)
	}

	mu.Lock()
	failFirst = false
	callsAfterFirst := hubCalls
	mu.Unlock()

	second := collectMetrics(t, c, client)

	mu.Lock()
	callsAfterSecond := hubCalls
	mu.Unlock()
	if callsAfterSecond == callsAfterFirst {
		t.Fatal("the hub half was not re-fetched on the next poll after a failed read; a failure " +
			"must retry immediately rather than parking for the whole interval")
	}
	if got := countCrowdSecHubMetrics(t, second); got == 0 {
		t.Error("the retry produced no hub series")
	}
}
