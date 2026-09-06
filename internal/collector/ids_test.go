package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/common/promslog"
)

func idsMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/ids/service/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"status":"running","widget":{}}`))
	})
	mux.HandleFunc("/api/ids/settings/get", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"ids":{"general":{"enabled":"1","promisc":"1",
		  "mode":{"pcap":{"selected":0},"netmap":{"selected":1},"divert":{"selected":0}}}}}`))
	})
	mux.HandleFunc("/api/ids/service/get_alert_logs", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`[{"size":1994,"modified":"2026/07/13 18:15","filename":"eve.json","sequence":null}]`))
	})
	mux.HandleFunc("/api/ids/settings/list_rulesets", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"total":2,"rowCount":2,"current":1,"rows":[
		  {"filename":"a.rules","modified_local":null,"enabled":"0"},
		  {"filename":"b.rules","modified_local":"2026/07/13 18:11","enabled":"1"}]}`))
	})
	mux.HandleFunc("/api/ids/settings/searchInstalledRules", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"rows":[{"sid":1}],"rowCount":1,"total":1966,"current":1}`))
	})
	return mux
}

// TestIDSCollector_DefaultOn: no alerts flag → the default-on series only.
//
//	status(1) + ips_mode(1) + promiscuous(1) + alert_log_files(1)
//	+ alert_log_size_bytes(1) + installed_rules(1)
//	+ ruleset_enabled(2) + ruleset_last_updated(1, only the downloaded one)
//	= 9
func TestIDSCollector_DefaultOn(t *testing.T) {
	server := httptest.NewServer(idsMux(t))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &idsCollector{subsystem: IDSSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	if len(metrics) != 9 {
		t.Fatalf("expected 9 metrics (default-on, no alerts), got %d", len(metrics))
	}

	// recent_alerts must NOT be present when the alerts flag is off.
	for _, m := range metrics {
		if hasFqName(m, "opnsense_ids_recent_alerts") {
			t.Error("recent_alerts emitted while alerts disabled")
		}
	}

	for _, m := range metrics {
		if hasFqName(m, "opnsense_ids_status") && getMetricValue(m) != 1 {
			t.Errorf("status = %v, want 1 (running)", getMetricValue(m))
		}
		if hasFqName(m, "opnsense_ids_ips_mode_enabled") && getMetricValue(m) != 1 {
			t.Errorf("ips_mode_enabled = %v, want 1", getMetricValue(m))
		}
		if hasFqName(m, "opnsense_ids_installed_rules") && getMetricValue(m) != 1966 {
			t.Errorf("installed_rules = %v, want 1966", getMetricValue(m))
		}
	}
}

// TestIDSCollector_WithAlerts: enabling alerts adds exactly the two action
// series (allowed + blocked), always present even with zero alerts.
func TestIDSCollector_WithAlerts(t *testing.T) {
	mux := idsMux(t)
	mux.HandleFunc("/api/ids/service/query_alerts", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"filters":[],"origin":"eve.json","rowCount":0,"total":0,"current":1,"rows":[]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &idsCollector{subsystem: IDSSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetAlertsEnabled(true, 15*time.Minute)

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	if len(metrics) != 11 {
		t.Fatalf("expected 11 metrics (9 default-on + 2 alert actions), got %d", len(metrics))
	}
	actions := map[string]bool{}
	for _, m := range metrics {
		if hasFqName(m, "opnsense_ids_recent_alerts") {
			actions[getMetricLabels(m)["action"]] = true
			if getMetricValue(m) != 0 {
				t.Errorf("recent_alerts = %v, want 0", getMetricValue(m))
			}
		}
	}
	if !actions["allowed"] || !actions["blocked"] {
		t.Errorf("recent_alerts actions = %v, want allowed+blocked", actions)
	}
}
