package opnsense

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"testing"
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
