package opnsense

import (
	"net/http"
	"net/url"
	"sort"
	"testing"
)

const captivePortalZonesFixture = `{"0": "Guest WiFi", "1": "Lab"}`

const captivePortalSessionsFixture = `{"total": 3, "rowCount": 3, "current": 1, "rows": [
  {"sessionId": "abc", "userName": "alice", "ipAddress": "192.0.2.10",
   "macAddress": "aa:bb:cc:dd:ee:ff", "startTime": 1700000000, "zoneid": "0"},
  {"sessionId": "def", "userName": "bob",   "ipAddress": "192.0.2.11",
   "macAddress": "aa:bb:cc:dd:ee:00", "startTime": 1700000100, "zoneid": "0"},
  {"sessionId": "ghi", "userName": "",      "ipAddress": "192.0.2.50",
   "macAddress": "aa:bb:cc:dd:ee:01", "startTime": 1700000200, "zoneid": "1"}]}`

// captivePortalRegisterHandlers registers the captive portal handlers on an existing mux.
func captivePortalRegisterHandlers(t *testing.T, mux *http.ServeMux, zones, sessions string) {
	t.Helper()
	mux.HandleFunc("/api/captiveportal/session/zones", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(zones))
	})
	mux.HandleFunc("/api/captiveportal/session/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sessions))
	})
}

func TestFetchCaptivePortalSessions_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	captivePortalRegisterHandlers(t, mux, captivePortalZonesFixture, captivePortalSessionsFixture)

	data, err := client.FetchCaptivePortalSessions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if data.SessionsTotal != 3 {
		t.Errorf("expected SessionsTotal=3, got %v", data.SessionsTotal)
	}
	if len(data.Zones) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(data.Zones))
	}
	// Zones are sorted by ZoneID for determinism.
	sort.Slice(data.Zones, func(i, j int) bool { return data.Zones[i].ZoneID < data.Zones[j].ZoneID })
	if data.Zones[0].ZoneID != "0" || data.Zones[0].Description != "Guest WiFi" || data.Zones[0].Sessions != 2 {
		t.Errorf("zone 0 wrong: %+v", data.Zones[0])
	}
	if data.Zones[1].ZoneID != "1" || data.Zones[1].Description != "Lab" || data.Zones[1].Sessions != 1 {
		t.Errorf("zone 1 wrong: %+v", data.Zones[1])
	}
}

func TestFetchCaptivePortalSessions_Unconfigured(t *testing.T) {
	// zones returns [] (PHP empty array); sessions returns zero rows.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/captiveportal/session/zones", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/api/captiveportal/session/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total": 0, "rowCount": 0, "current": 1, "rows": []}`))
	})

	data, err := client.FetchCaptivePortalSessions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true for unconfigured (core feature)")
	}
	if len(data.Zones) != 0 {
		t.Errorf("expected 0 zones, got %d", len(data.Zones))
	}
	if data.SessionsTotal != 0 {
		t.Errorf("expected 0 sessions, got %v", data.SessionsTotal)
	}
}

func TestFetchCaptivePortalSessions_UnknownZone(t *testing.T) {
	// Session with a zoneid that has no corresponding zone entry.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/captiveportal/session/zones", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"0": "Guest WiFi"}`))
	})
	mux.HandleFunc("/api/captiveportal/session/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total": 2, "rowCount": 2, "current": 1, "rows": [
		  {"sessionId": "abc", "zoneid": "0"},
		  {"sessionId": "xyz", "zoneid": "9"}]}`))
	})

	data, err := client.FetchCaptivePortalSessions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if data.SessionsTotal != 2 {
		t.Errorf("expected SessionsTotal=2, got %v", data.SessionsTotal)
	}
	// Should have zone "0" (1 session) + synthetic "unknown" (1 session).
	if len(data.Zones) != 2 {
		t.Fatalf("expected 2 zones (configured + unknown), got %d: %+v", len(data.Zones), data.Zones)
	}
	var unknownZone *CaptivePortalZone
	for i := range data.Zones {
		if data.Zones[i].ZoneID == "unknown" {
			unknownZone = &data.Zones[i]
		}
	}
	if unknownZone == nil {
		t.Fatal("expected synthetic unknown zone")
	}
	if unknownZone.Sessions != 1 {
		t.Errorf("expected unknown zone sessions=1, got %v", unknownZone.Sessions)
	}
}

func TestFetchCaptivePortalSessions_404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchCaptivePortalSessions()
	if err != nil {
		t.Fatalf("expected nil error on 404 (feature absent), got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on 404")
	}
}

func TestFetchCaptivePortalSessions_SessionsFormRequest(t *testing.T) {
	// Verify the session search uses rowCount=-1.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	var capturedForm url.Values
	mux.HandleFunc("/api/captiveportal/session/zones", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"0": "Main"}`))
	})
	mux.HandleFunc("/api/captiveportal/session/search", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		capturedForm = r.Form
		w.Write([]byte(`{"total": 0, "rowCount": 0, "current": 1, "rows": []}`))
	})

	_, _ = client.FetchCaptivePortalSessions()
	if capturedForm.Get("rowCount") != "-1" {
		t.Errorf("expected rowCount=-1, got %q", capturedForm.Get("rowCount"))
	}
}
