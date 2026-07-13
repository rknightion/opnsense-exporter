package opnsense

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
)

// crowdsecAlertsFixture is a minimal bootgrid response for the alerts endpoint.
const crowdsecAlertsFixture = `{"total": 7, "rowCount": 1, "current": 1, "rows": [{"id": 1}]}`

// crowdsecDecisionsFixture has more rows than the page (rowCount=1) to prove
// count != rows — total is the full count regardless of page size (D3).
const crowdsecDecisionsFixture = `{"total": 4321, "rowCount": 1, "current": 1, "rows": [{"id": 1}]}`

// crowdsecBouncersFixture has 1 bouncer with a nanosecond-precision timestamp.
const crowdsecBouncersFixture = `{"total": 1, "rowCount": 1, "current": 1, "rows": [
  {"name": "cs-firewall-bouncer", "type": "crowdsec-firewall-bouncer",
   "version": "v0.0.28-freebsd", "created": "2025-01-15T10:00:00Z",
   "valid": true, "ip_address": "127.0.0.1",
   "last_seen": "2026-06-09T08:00:00.123456789Z", "os": "freebsd/amd64"}]}`

// crowdsecMachinesFixture has 1 machine with a plain RFC3339 timestamp.
const crowdsecMachinesFixture = `{"total": 1, "rowCount": 1, "current": 1, "rows": [
  {"name": "fw1-machine", "ip_address": "127.0.0.1", "version": "v1.6.3",
   "validated": true, "created": "2025-01-15T10:00:00Z",
   "last_seen": "2026-06-09T08:00:00Z", "os": "freebsd/amd64"}]}`

// crowdsecMessageEnvelope is the HTTP-200 "unable to retrieve data" envelope
// returned by every cscli-backed endpoint when the daemon is not running.
const crowdsecMessageEnvelope = `{"message": "unable to retrieve data"}`

// registerCrowdSecHandlers registers all four search endpoints + service/status
// on an existing mux, using the provided body fixtures.
func registerCrowdSecHandlers(
	t *testing.T,
	mux *http.ServeMux,
	alerts, decisions, bouncers, machines string,
) {
	t.Helper()
	mux.HandleFunc("/api/crowdsec/alerts/search", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		w.Write([]byte(alerts))
	})
	mux.HandleFunc("/api/crowdsec/decisions/search", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		w.Write([]byte(decisions))
	})
	mux.HandleFunc("/api/crowdsec/bouncers/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(bouncers))
	})
	mux.HandleFunc("/api/crowdsec/machines/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(machines))
	})
	mux.HandleFunc("/api/crowdsec/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
}

// crowdsecHubEnabledFixture is a minimal single-row bootgrid fixture with a
// plain "enabled" (non-tainted, non-outdated) status, reused by every hub
// component search endpoint in tests that don't care about hub-item detail.
const crowdsecHubEnabledFixture = `{"total": 1, "rowCount": 1, "current": 1, "rows": [
  {"name": "crowdsecurity/test", "status": "enabled", "local_version": "0.1",
   "local_path": "x.yaml", "description": ""}]}`

// crowdsecHubEmptyFixture is the empty-but-valid bootgrid shape the dev-box
// capture shows for appsecconfigs/appsecrules when nothing is configured.
const crowdsecHubEmptyFixture = `{"total": 0, "rowCount": 0, "current": 1, "rows": []}`

// crowdsecVersionFixture is the raw multi-line cscli version text captured
// live 2026-07-13 — NOT JSON.
const crowdsecVersionFixture = "version: v1.7.8_1-6322745\nCodename: alphaga\nBuildDate: 2026-07-06_19:00:16\n"

// registerCrowdSecHubAndVersionHandlers registers all six hub-component search
// endpoints (one "enabled" row each, except the two appsec endpoints which are
// empty-but-valid) plus version/get, so tests exercising the original four
// endpoints keep Present=true after #205 added these as additional fetches in
// the same FetchCrowdSecStatus call.
func registerCrowdSecHubAndVersionHandlers(t *testing.T, mux *http.ServeMux) {
	t.Helper()
	for _, path := range []string{
		"/api/crowdsec/collections/search",
		"/api/crowdsec/scenarios/search",
		"/api/crowdsec/parsers/search",
		"/api/crowdsec/postoverflows/search",
	} {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(crowdsecHubEnabledFixture))
		})
	}
	for _, path := range []string{
		"/api/crowdsec/appsecconfigs/search",
		"/api/crowdsec/appsecrules/search",
	} {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(crowdsecHubEmptyFixture))
		})
	}
	mux.HandleFunc("/api/crowdsec/version/get", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecVersionFixture))
	})
}

func TestFetchCrowdSecStatus_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	var decisionsRowCount string
	mux.HandleFunc("/api/crowdsec/alerts/search", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Write([]byte(crowdsecAlertsFixture))
	})
	mux.HandleFunc("/api/crowdsec/decisions/search", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		decisionsRowCount = r.FormValue("rowCount")
		w.Write([]byte(crowdsecDecisionsFixture))
	})
	mux.HandleFunc("/api/crowdsec/bouncers/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecBouncersFixture))
	})
	mux.HandleFunc("/api/crowdsec/machines/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecMachinesFixture))
	})
	mux.HandleFunc("/api/crowdsec/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	registerCrowdSecHubAndVersionHandlers(t, mux)

	data, err := client.FetchCrowdSecStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}

	// Verify the decisions endpoint was called with rowCount=1 (D3: count-only).
	if decisionsRowCount != "1" {
		t.Errorf("expected decisions rowCount=1, got %q", decisionsRowCount)
	}

	// Alerts total.
	if !data.HasAlertsTotal || data.AlertsTotal != 7 {
		t.Errorf("expected HasAlertsTotal=true AlertsTotal=7, got HasAlertsTotal=%v AlertsTotal=%v",
			data.HasAlertsTotal, data.AlertsTotal)
	}

	// Decisions total — proves count != rows (4321 rows, only 1 returned).
	if !data.HasDecisionsTotal || data.DecisionsTotal != 4321 {
		t.Errorf("expected HasDecisionsTotal=true DecisionsTotal=4321, got HasDecisionsTotal=%v DecisionsTotal=%v",
			data.HasDecisionsTotal, data.DecisionsTotal)
	}

	// Bouncers.
	if !data.HasBouncers || len(data.Bouncers) != 1 {
		t.Fatalf("expected HasBouncers=true and 1 bouncer, got HasBouncers=%v len=%d",
			data.HasBouncers, len(data.Bouncers))
	}
	b := data.Bouncers[0]
	if b.Name != "cs-firewall-bouncer" {
		t.Errorf("bouncer name wrong: %q", b.Name)
	}
	if b.Type != "crowdsec-firewall-bouncer" {
		t.Errorf("bouncer type wrong: %q", b.Type)
	}
	if !b.Valid {
		t.Error("expected bouncer Valid=true")
	}
	if !b.HasLastPull {
		t.Error("expected HasLastPull=true for bouncer with last_seen timestamp")
	}
	// 2026-06-09T08:00:00.123456789Z → Unix 1780992000 (+ fractional nanos)
	expectedUnix := float64(1780992000)
	if b.LastPullSeconds < expectedUnix || b.LastPullSeconds > expectedUnix+1 {
		t.Errorf("bouncer LastPullSeconds wrong: %v (expected ~%v)", b.LastPullSeconds, expectedUnix)
	}

	// Machines.
	if !data.HasMachines || len(data.Machines) != 1 {
		t.Fatalf("expected HasMachines=true and 1 machine, got HasMachines=%v len=%d",
			data.HasMachines, len(data.Machines))
	}
	m := data.Machines[0]
	if m.Name != "fw1-machine" {
		t.Errorf("machine name wrong: %q", m.Name)
	}
	if !m.Validated {
		t.Error("expected machine Validated=true")
	}
	if !m.HasLastHeartbeat {
		t.Error("expected HasLastHeartbeat=true")
	}

	// Hub items (#205): four components report one "enabled" row each; the two
	// appsec endpoints are empty-but-valid and contribute no entries.
	if !data.HasHubItems {
		t.Fatal("expected HasHubItems=true")
	}
	wantHubItems := []CrowdSecHubItemCount{
		{Component: "collection", Status: "enabled", Count: 1},
		{Component: "parser", Status: "enabled", Count: 1},
		{Component: "postoverflow", Status: "enabled", Count: 1},
		{Component: "scenario", Status: "enabled", Count: 1},
	}
	if len(data.HubItems) != len(wantHubItems) {
		t.Fatalf("expected %d hub item counts, got %d: %+v", len(wantHubItems), len(data.HubItems), data.HubItems)
	}
	for i, want := range wantHubItems {
		if data.HubItems[i] != want {
			t.Errorf("hub item[%d] = %+v, want %+v", i, data.HubItems[i], want)
		}
	}

	// Engine version (#205).
	if !data.HasVersion || data.Version != "v1.7.8_1-6322745" {
		t.Errorf("expected HasVersion=true Version=%q, got HasVersion=%v Version=%q",
			"v1.7.8_1-6322745", data.HasVersion, data.Version)
	}
}

// TestFetchCrowdSecStatus_UndecodableRows guards #104: when the envelope decodes
// (total set → HasBouncers/HasMachines would be true) but the rows payload has an
// unexpected shape (object instead of array), the fetcher must mark the section
// absent and log a warning, not leave HasBouncers=true with an empty slice (which
// the collector would emit as a false total=0).
func TestFetchCrowdSecStatus_UndecodableRows(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	var buf bytes.Buffer
	client.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	mux.HandleFunc("/api/crowdsec/alerts/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecAlertsFixture))
	})
	mux.HandleFunc("/api/crowdsec/decisions/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecDecisionsFixture))
	})
	// Envelope decodes (total set) but rows is an object, not an array.
	mux.HandleFunc("/api/crowdsec/bouncers/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total": 1, "rowCount": 1, "current": 1, "rows": {"unexpected": "object"}}`))
	})
	mux.HandleFunc("/api/crowdsec/machines/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total": 1, "rowCount": 1, "current": 1, "rows": {"unexpected": "object"}}`))
	})
	mux.HandleFunc("/api/crowdsec/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	registerCrowdSecHubAndVersionHandlers(t, mux)

	data, err := client.FetchCrowdSecStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.HasBouncers {
		t.Error("expected HasBouncers=false when bouncers rows fail to decode (avoid false total=0)")
	}
	if len(data.Bouncers) != 0 {
		t.Errorf("expected no bouncers on decode failure, got %d", len(data.Bouncers))
	}
	if data.HasMachines {
		t.Error("expected HasMachines=false when machines rows fail to decode")
	}
	logs := buf.String()
	if !strings.Contains(logs, "decode bouncers rows") {
		t.Errorf("expected a warning about bouncers decode failure; got: %q", logs)
	}
	if !strings.Contains(logs, "decode machines rows") {
		t.Errorf("expected a warning about machines decode failure; got: %q", logs)
	}
}

func TestFetchCrowdSecStatus_PluginAbsent404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchCrowdSecStatus()
	if err != nil {
		t.Fatalf("expected nil error on 404 (plugin absent), got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on 404 (plugin absent)")
	}
}

func TestFetchCrowdSecStatus_MessageEnvelope(t *testing.T) {
	// decisions endpoint returns the HTTP-200 error envelope while others succeed.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	registerCrowdSecHandlers(t, mux,
		crowdsecAlertsFixture,
		crowdsecMessageEnvelope, // decisions → no-data
		crowdsecBouncersFixture,
		crowdsecMachinesFixture,
	)
	registerCrowdSecHubAndVersionHandlers(t, mux)

	data, err := client.FetchCrowdSecStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true (plugin is present, only cscli failed for decisions)")
	}
	if data.HasDecisionsTotal {
		t.Error("expected HasDecisionsTotal=false when decisions endpoint returns message envelope")
	}
	if !data.HasAlertsTotal {
		t.Error("expected HasAlertsTotal=true (alerts succeeded)")
	}
	if !data.HasBouncers {
		t.Error("expected HasBouncers=true (bouncers succeeded)")
	}
	if !data.HasMachines {
		t.Error("expected HasMachines=true (machines succeeded)")
	}
}

func TestFetchCrowdSecStatus_EmptyLastSeen(t *testing.T) {
	// bouncer with empty last_seen → HasLastPull=false.
	bouncersNoLastSeen := `{"total": 1, "rowCount": 1, "current": 1, "rows": [
	  {"name": "bouncer-no-pull", "type": "fw-bouncer",
	   "valid": true, "last_seen": ""}]}`

	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	registerCrowdSecHandlers(t, mux,
		crowdsecAlertsFixture,
		crowdsecDecisionsFixture,
		bouncersNoLastSeen,
		crowdsecMachinesFixture,
	)
	registerCrowdSecHubAndVersionHandlers(t, mux)

	data, err := client.FetchCrowdSecStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Bouncers) != 1 {
		t.Fatalf("expected 1 bouncer, got %d", len(data.Bouncers))
	}
	b := data.Bouncers[0]
	if b.HasLastPull {
		t.Error("expected HasLastPull=false for bouncer with empty last_seen")
	}
}

func TestFetchCrowdSecStatus_DecisionsRowCountParam(t *testing.T) {
	// Verify alerts endpoint is also called with rowCount=1.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	var alertsRowCount string
	mux.HandleFunc("/api/crowdsec/alerts/search", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		alertsRowCount = r.FormValue("rowCount")
		w.Write([]byte(crowdsecAlertsFixture))
	})
	mux.HandleFunc("/api/crowdsec/decisions/search", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Write([]byte(crowdsecDecisionsFixture))
	})
	mux.HandleFunc("/api/crowdsec/bouncers/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecBouncersFixture))
	})
	mux.HandleFunc("/api/crowdsec/machines/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecMachinesFixture))
	})

	_, _ = client.FetchCrowdSecStatus()

	if alertsRowCount != "1" {
		t.Errorf("expected alerts rowCount=1, got %q", alertsRowCount)
	}
}

func TestFetchCrowdSecStatus_BouncersRowCountParam(t *testing.T) {
	// Verify bouncers endpoint is called with rowCount=-1 (all rows).
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	var bouncersRowCount string
	mux.HandleFunc("/api/crowdsec/alerts/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecAlertsFixture))
	})
	mux.HandleFunc("/api/crowdsec/decisions/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecDecisionsFixture))
	})
	mux.HandleFunc("/api/crowdsec/bouncers/search", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		bouncersRowCount = r.FormValue("rowCount")
		w.Write([]byte(crowdsecBouncersFixture))
	})
	mux.HandleFunc("/api/crowdsec/machines/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecMachinesFixture))
	})

	_, _ = client.FetchCrowdSecStatus()

	if bouncersRowCount != "-1" {
		t.Errorf("expected bouncers rowCount=-1, got %q", bouncersRowCount)
	}
}

// TestNormalizeCrowdSecHubStatus covers the confirmed live vocabulary
// ("enabled", "enabled,tainted") plus defensive handling of whitespace and
// unknown future tokens.
func TestNormalizeCrowdSecHubStatus(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"enabled", "enabled", "enabled"},
		{"tainted, no space (live capture)", "enabled,tainted", "enabled,tainted"},
		{"tainted, with space", "enabled, tainted", "enabled,tainted"},
		{"disabled", "disabled", "disabled"},
		{"unknown future token passes through", "enabled,update-available", "enabled,update-available"},
		{"empty", "", "unknown"},
		{"only commas/whitespace", " , ", "unknown"},
		{"leading/trailing whitespace", "  enabled  ", "enabled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeCrowdSecHubStatus(tt.in); got != tt.want {
				t.Errorf("normalizeCrowdSecHubStatus(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestParseCrowdSecVersion covers the confirmed live cscli version text shape
// plus tolerant handling of malformed/unexpected input (must never error the
// scrape — just omit the metric).
func TestParseCrowdSecVersion(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantVer string
		wantOK  bool
	}{
		{
			name:    "live capture shape (2026-07-13)",
			in:      "version: v1.7.8_1-6322745\nCodename: alphaga\nBuildDate: 2026-07-06_19:00:16\n",
			wantVer: "v1.7.8_1-6322745",
			wantOK:  true,
		},
		{"single line, no trailing newline", "version: v1.6.3", "v1.6.3", true},
		{"case-insensitive key, extra spaces", "  Version :  v1.2.3  \nCodename: x", "v1.2.3", true},
		{"empty", "", "", false},
		{"whitespace only", "   \n  ", "", false},
		{"no colon on first line", "not a key value line\nversion: v1.2.3", "", false},
		{"wrong first-line key", "Codename: alphaga\nversion: v1.2.3", "", false},
		{"colon but empty value", "version: \nCodename: x", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVer, gotOK := parseCrowdSecVersion(tt.in)
			if gotOK != tt.wantOK || gotVer != tt.wantVer {
				t.Errorf("parseCrowdSecVersion(%q) = (%q, %v), want (%q, %v)",
					tt.in, gotVer, gotOK, tt.wantVer, tt.wantOK)
			}
		})
	}
}

// TestFetchCrowdSecStatus_HubItemsTainted mirrors the live dev-box capture
// (scenarios_search_tainted.json, 2026-07-13): 7 scenarios "enabled", 1
// "enabled,tainted" after a local edit.
func TestFetchCrowdSecStatus_HubItemsTainted(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	registerCrowdSecHandlers(t, mux, crowdsecAlertsFixture, crowdsecDecisionsFixture,
		crowdsecBouncersFixture, crowdsecMachinesFixture)

	scenariosTainted := `{"total": 8, "rowCount": 8, "current": 1, "rows": [
	  {"name": "crowdsecurity/opnsense-gui-bf", "status": "enabled", "local_version": "0.3"},
	  {"name": "crowdsecurity/ssh-bf", "status": "enabled,tainted", "local_version": "?"},
	  {"name": "crowdsecurity/ssh-cve-2024-6387", "status": "enabled", "local_version": "0.2"},
	  {"name": "crowdsecurity/ssh-generic-test", "status": "enabled", "local_version": "0.2"},
	  {"name": "crowdsecurity/ssh-refused-conn", "status": "enabled", "local_version": "0.1"},
	  {"name": "crowdsecurity/ssh-slow-bf", "status": "enabled", "local_version": "0.4"},
	  {"name": "crowdsecurity/ssh-time-based-bf", "status": "enabled", "local_version": "0.3"},
	  {"name": "firewallservices/pf-scan-multi_ports", "status": "enabled", "local_version": "0.5"}]}`

	mux.HandleFunc("/api/crowdsec/collections/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecHubEmptyFixture))
	})
	mux.HandleFunc("/api/crowdsec/scenarios/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(scenariosTainted))
	})
	mux.HandleFunc("/api/crowdsec/parsers/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecHubEmptyFixture))
	})
	mux.HandleFunc("/api/crowdsec/postoverflows/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecHubEmptyFixture))
	})
	mux.HandleFunc("/api/crowdsec/appsecconfigs/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecHubEmptyFixture))
	})
	mux.HandleFunc("/api/crowdsec/appsecrules/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecHubEmptyFixture))
	})
	mux.HandleFunc("/api/crowdsec/version/get", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecVersionFixture))
	})

	data, err := client.FetchCrowdSecStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.HasHubItems {
		t.Fatal("expected HasHubItems=true")
	}
	want := []CrowdSecHubItemCount{
		{Component: "scenario", Status: "enabled", Count: 7},
		{Component: "scenario", Status: "enabled,tainted", Count: 1},
	}
	if len(data.HubItems) != len(want) {
		t.Fatalf("expected %d hub item counts, got %d: %+v", len(want), len(data.HubItems), data.HubItems)
	}
	for i, w := range want {
		if data.HubItems[i] != w {
			t.Errorf("hub item[%d] = %+v, want %+v", i, data.HubItems[i], w)
		}
	}
}

// TestFetchCrowdSecStatus_HubItemsMessageEnvelope: one hub component (parsers)
// returns the cscli-failure message envelope; the others still contribute.
func TestFetchCrowdSecStatus_HubItemsMessageEnvelope(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	registerCrowdSecHandlers(t, mux, crowdsecAlertsFixture, crowdsecDecisionsFixture,
		crowdsecBouncersFixture, crowdsecMachinesFixture)

	mux.HandleFunc("/api/crowdsec/collections/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecHubEnabledFixture))
	})
	mux.HandleFunc("/api/crowdsec/scenarios/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecHubEnabledFixture))
	})
	mux.HandleFunc("/api/crowdsec/parsers/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecMessageEnvelope))
	})
	mux.HandleFunc("/api/crowdsec/postoverflows/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecHubEnabledFixture))
	})
	mux.HandleFunc("/api/crowdsec/appsecconfigs/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecHubEmptyFixture))
	})
	mux.HandleFunc("/api/crowdsec/appsecrules/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecHubEmptyFixture))
	})
	mux.HandleFunc("/api/crowdsec/version/get", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecVersionFixture))
	})

	data, err := client.FetchCrowdSecStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.HasHubItems {
		t.Fatal("expected HasHubItems=true (other components succeeded)")
	}
	for _, item := range data.HubItems {
		if item.Component == "parser" {
			t.Errorf("expected no parser entries (message envelope), got %+v", item)
		}
	}
	if len(data.HubItems) != 3 { // collection, scenario, postoverflow
		t.Errorf("expected 3 hub item counts (parsers omitted), got %d: %+v", len(data.HubItems), data.HubItems)
	}
}

// TestFetchCrowdSecStatus_HubItemsUndecodableRows mirrors the bouncers/machines
// #104 guard: an undecodable rows shape for one component must not silently
// contribute a false zero, and must not discard the other components.
func TestFetchCrowdSecStatus_HubItemsUndecodableRows(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	var buf bytes.Buffer
	client.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	registerCrowdSecHandlers(t, mux, crowdsecAlertsFixture, crowdsecDecisionsFixture,
		crowdsecBouncersFixture, crowdsecMachinesFixture)

	mux.HandleFunc("/api/crowdsec/collections/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecHubEnabledFixture))
	})
	// rows is an object, not an array.
	mux.HandleFunc("/api/crowdsec/scenarios/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total": 1, "rowCount": 1, "current": 1, "rows": {"unexpected": "object"}}`))
	})
	mux.HandleFunc("/api/crowdsec/parsers/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecHubEmptyFixture))
	})
	mux.HandleFunc("/api/crowdsec/postoverflows/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecHubEmptyFixture))
	})
	mux.HandleFunc("/api/crowdsec/appsecconfigs/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecHubEmptyFixture))
	})
	mux.HandleFunc("/api/crowdsec/appsecrules/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecHubEmptyFixture))
	})
	mux.HandleFunc("/api/crowdsec/version/get", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crowdsecVersionFixture))
	})

	data, err := client.FetchCrowdSecStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.HasHubItems {
		t.Fatal("expected HasHubItems=true (collections succeeded)")
	}
	for _, item := range data.HubItems {
		if item.Component == "scenario" {
			t.Errorf("expected no scenario entries on decode failure, got %+v", item)
		}
	}
	if !strings.Contains(buf.String(), "decode hub item rows") {
		t.Errorf("expected a warning about hub item decode failure; got: %q", buf.String())
	}
}

// TestFetchCrowdSecStatus_HubItems404 documents the design decision that a 404
// on any of the new hub/version endpoints is treated the same as the existing
// bouncers/machines siblings: the whole plugin is marked absent, not just that
// one series.
func TestFetchCrowdSecStatus_HubItems404(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	registerCrowdSecHandlers(t, mux, crowdsecAlertsFixture, crowdsecDecisionsFixture,
		crowdsecBouncersFixture, crowdsecMachinesFixture)
	mux.HandleFunc("/api/crowdsec/collections/search", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	// scenarios/parsers/postoverflows/appsec*/version are left unregistered
	// (404 by default) — irrelevant, collections 404s first.

	data, err := client.FetchCrowdSecStatus()
	if err != nil {
		t.Fatalf("expected nil error on 404, got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false when a hub-item endpoint 404s")
	}
}

// TestFetchCrowdSecStatus_VersionUnparseable: version/get returns text that
// doesn't match the expected "version: ..." shape — HasVersion must be false,
// and the scrape must not error.
func TestFetchCrowdSecStatus_VersionUnparseable(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	registerCrowdSecHandlers(t, mux, crowdsecAlertsFixture, crowdsecDecisionsFixture,
		crowdsecBouncersFixture, crowdsecMachinesFixture)
	for _, path := range []string{
		"/api/crowdsec/collections/search", "/api/crowdsec/scenarios/search",
		"/api/crowdsec/parsers/search", "/api/crowdsec/postoverflows/search",
		"/api/crowdsec/appsecconfigs/search", "/api/crowdsec/appsecrules/search",
	} {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(crowdsecHubEmptyFixture))
		})
	}
	mux.HandleFunc("/api/crowdsec/version/get", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not the expected format\n"))
	})

	data, err := client.FetchCrowdSecStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.HasVersion {
		t.Errorf("expected HasVersion=false for unparseable version text, got Version=%q", data.Version)
	}
	if !data.Present {
		t.Error("expected Present=true (an unparseable version body is not an HTTP error)")
	}
}

// crowdsecAlertsRowsFixture is a live dev-box capture (2026-07-13, a
// cscli-created synthetic ban) of api/crowdsec/alerts/search with rowCount=-1.
const crowdsecAlertsRowsFixture = `{"total":1,"rowCount":1,"current":1,"rows":[` +
	`{"id":1,"value":"Ip:192.0.2.66","reason":"exporter testbed synthetic ban",` +
	`"country":"","as":"","decisions":"ban:1","created":"2026-07-12T17:09:28Z"}]}`

// crowdsecDecisionsRowsFixture is a live dev-box capture (2026-07-13, same
// synthetic ban) of api/crowdsec/decisions/search with rowCount=-1.
const crowdsecDecisionsRowsFixture = `{"total":1,"rowCount":1,"current":1,"rows":[` +
	`{"id":1,"source":"cscli","scope_value":"Ip:192.0.2.66",` +
	`"reason":"exporter testbed synthetic ban","action":"ban","country":"","as":"",` +
	`"events_count":1,"expiration":"693h46m29s","alert_id":1}]}`

func TestFetchCrowdSecAlerts_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/crowdsec/alerts/search", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Write([]byte(crowdsecAlertsRowsFixture))
	})

	alerts, err := client.FetchCrowdSecAlerts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	a := alerts[0]
	if a.ID != 1 {
		t.Errorf("ID = %d, want 1", a.ID)
	}
	if a.ScopeValue != "Ip:192.0.2.66" {
		t.Errorf("ScopeValue = %q, want %q", a.ScopeValue, "Ip:192.0.2.66")
	}
	if a.Scenario != "exporter testbed synthetic ban" {
		t.Errorf("Scenario = %q", a.Scenario)
	}
	if a.DecisionsSummary != "ban:1" {
		t.Errorf("DecisionsSummary = %q, want %q", a.DecisionsSummary, "ban:1")
	}
	if !a.HasCreatedAt {
		t.Fatal("expected HasCreatedAt=true for a valid RFC3339 created timestamp")
	}
	wantCreated := time.Date(2026, 7, 12, 17, 9, 28, 0, time.UTC)
	if !a.CreatedAt.Equal(wantCreated) {
		t.Errorf("CreatedAt = %v, want %v", a.CreatedAt, wantCreated)
	}
	if a.CreatedRaw != "2026-07-12T17:09:28Z" {
		t.Errorf("CreatedRaw = %q", a.CreatedRaw)
	}
	if a.Country != "" || a.AS != "" {
		t.Errorf("expected empty country/as (no GeoIP DB on the source box), got %q/%q", a.Country, a.AS)
	}
}

func TestFetchCrowdSecAlerts_PluginAbsent404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	alerts, err := client.FetchCrowdSecAlerts()
	if err != nil {
		t.Fatalf("expected nil error on 404 (plugin absent), got: %v", err)
	}
	if alerts != nil {
		t.Errorf("expected nil alerts on 404, got %v", alerts)
	}
}

func TestFetchCrowdSecAlerts_MessageEnvelope(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/crowdsec/alerts/search", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Write([]byte(crowdsecMessageEnvelope))
	})

	alerts, err := client.FetchCrowdSecAlerts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alerts != nil {
		t.Errorf("expected nil alerts on message envelope (daemon not running), got %v", alerts)
	}
}

func TestFetchCrowdSecAlerts_UndecodableRows(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/crowdsec/alerts/search", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Write([]byte(`{"total":1,"rowCount":1,"current":1,"rows":{"not":"an array"}}`))
	})

	alerts, err := client.FetchCrowdSecAlerts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alerts != nil {
		t.Errorf("expected nil alerts on undecodable rows, got %v", alerts)
	}
}

func TestFetchCrowdSecAlerts_Empty(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/crowdsec/alerts/search", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})

	alerts, err := client.FetchCrowdSecAlerts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts, got %d", len(alerts))
	}
}

func TestFetchCrowdSecDecisions_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/crowdsec/decisions/search", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Write([]byte(crowdsecDecisionsRowsFixture))
	})

	decisions, err := client.FetchCrowdSecDecisions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(decisions))
	}
	d := decisions[0]
	if d.ID != 1 {
		t.Errorf("ID = %d, want 1", d.ID)
	}
	if d.Origin != "cscli" {
		t.Errorf("Origin = %q, want %q", d.Origin, "cscli")
	}
	if d.ScopeValue != "Ip:192.0.2.66" {
		t.Errorf("ScopeValue = %q", d.ScopeValue)
	}
	if d.Action != "ban" {
		t.Errorf("Action = %q, want %q", d.Action, "ban")
	}
	if d.Expiration != "693h46m29s" {
		t.Errorf("Expiration = %q", d.Expiration)
	}
	if d.AlertID != 1 {
		t.Errorf("AlertID = %d, want 1", d.AlertID)
	}
	if d.EventsCount != 1 {
		t.Errorf("EventsCount = %d, want 1", d.EventsCount)
	}
}

func TestFetchCrowdSecDecisions_PluginAbsent404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	decisions, err := client.FetchCrowdSecDecisions()
	if err != nil {
		t.Fatalf("expected nil error on 404 (plugin absent), got: %v", err)
	}
	if decisions != nil {
		t.Errorf("expected nil decisions on 404, got %v", decisions)
	}
}

func TestFetchCrowdSecDecisions_MessageEnvelope(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/crowdsec/decisions/search", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Write([]byte(crowdsecMessageEnvelope))
	})

	decisions, err := client.FetchCrowdSecDecisions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decisions != nil {
		t.Errorf("expected nil decisions on message envelope, got %v", decisions)
	}
}

func TestFetchCrowdSecDecisions_UndecodableRows(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/crowdsec/decisions/search", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Write([]byte(`{"total":1,"rowCount":1,"current":1,"rows":{"not":"an array"}}`))
	})

	decisions, err := client.FetchCrowdSecDecisions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decisions != nil {
		t.Errorf("expected nil decisions on undecodable rows, got %v", decisions)
	}
}
