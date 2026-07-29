package opnsense

import (
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Zoneids 0,1 are sequential-from-0, so the real PHP endpoint serializes the
// zones map as a JSON *array*, not an object (#73). This fixture reflects that
// real shape; captivePortalZoneMap reconstructs {"0":..,"1":..}.
const captivePortalZonesFixture = `["Guest WiFi", "Lab"]`

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

func TestCaptivePortalZoneMap_Shapes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want map[string]string
	}{
		{"sequential-from-0 array (the real default shape)", `["test"]`, map[string]string{"0": "test"}},
		{"multi-element array", `["Guest WiFi", "Lab"]`, map[string]string{"0": "Guest WiFi", "1": "Lab"}},
		{"non-sequential object still decodes", `{"3": "Lab"}`, map[string]string{"3": "Lab"}},
		{"empty array is the empty-map quirk", `[]`, map[string]string{}},
		{"null is an empty map", `null`, map[string]string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var z captivePortalZoneMap
			if err := z.UnmarshalJSON([]byte(tc.in)); err != nil {
				t.Fatalf("UnmarshalJSON(%s) error: %v", tc.in, err)
			}
			if len(z) != len(tc.want) {
				t.Fatalf("UnmarshalJSON(%s) = %v, want %v", tc.in, map[string]string(z), tc.want)
			}
			for k, v := range tc.want {
				if z[k] != v {
					t.Errorf("UnmarshalJSON(%s)[%q] = %q, want %q", tc.in, k, z[k], v)
				}
			}
		})
	}
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

// TestFetchCaptivePortalSessions_Unconfigured asserts the search POST is skipped
// entirely when no zones are configured (#524). It is not merely wasteful there:
// searchAction takes no zoneid and always runs `configd captiveportal list_clients`,
// which on a box whose portal has never started reads a schemaless SQLite database,
// exits non-zero, and makes the firewall log a traceback once per poll.
func TestFetchCaptivePortalSessions_Unconfigured(t *testing.T) {
	// zones returns [] (PHP empty array).
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/captiveportal/session/zones", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/api/captiveportal/session/search", func(w http.ResponseWriter, r *http.Request) {
		t.Error("session/search must not be requested when no zones are configured")
		http.Error(w, "configd failure", http.StatusInternalServerError)
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

func TestFetchCaptivePortalVouchers_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/captiveportal/voucher/list_providers", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`["TestVoucherServer"]`))
	})
	mux.HandleFunc("/api/captiveportal/voucher/list_voucher_groups/TestVoucherServer", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`["TestGroup1"]`))
	})
	mux.HandleFunc("/api/captiveportal/voucher/list_vouchers/TestVoucherServer/TestGroup1", func(w http.ResponseWriter, r *http.Request) {
		// Real dev-box shape (#207): username IS the voucher code and must
		// never be decoded — included here only to prove it is ignored.
		w.Write([]byte(`[
			{"username":"J#qfpf","validity":0,"expirytime":0,"starttime":1783963735,"endtime":1783963735,"state":"expired"},
			{"username":"ut22)*","validity":3600,"expirytime":0,"starttime":1783963735,"endtime":1783967335,"state":"expired"},
			{"username":"!kIbam","validity":3600,"expirytime":0,"starttime":1783968205,"endtime":1783971805,"state":"unused"},
			{"username":"TM,*hh","validity":3600,"expirytime":0,"starttime":1783968205,"endtime":1783971805,"state":"unused"},
			{"username":"RgfX0t","validity":3600,"expirytime":0,"starttime":1783968205,"endtime":1783971805,"state":"unused"}
		]`))
	})

	data, err := client.FetchCaptivePortalVouchers()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if len(data.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(data.Groups))
	}
	g := data.Groups[0]
	if g.Provider != "TestVoucherServer" || g.Group != "TestGroup1" {
		t.Errorf("group identity wrong: %+v", g)
	}
	if g.Counts["expired"] != 2 || g.Counts["unused"] != 3 || g.Counts["valid"] != 0 {
		t.Errorf("counts wrong: %+v", g.Counts)
	}
	if g.HasNextExpiryTimestamp {
		t.Errorf("expirytime is 0 on every row; expected no next-expiry, got %v", g.NextExpiryTimestamp)
	}
}

func TestFetchCaptivePortalVouchers_NoProvider(t *testing.T) {
	// Boxes without any voucher-type auth server: list_providers returns [].
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	defer server.Close()

	data, err := client.FetchCaptivePortalVouchers()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Error("expected Present=true (core endpoint, just no provider configured)")
	}
	if len(data.Groups) != 0 {
		t.Errorf("expected 0 groups, got %d", len(data.Groups))
	}
}

func TestFetchCaptivePortalVouchers_NoGroups(t *testing.T) {
	// A configured provider with no generated voucher groups yet.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/captiveportal/voucher/list_providers", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`["Guest"]`))
	})
	mux.HandleFunc("/api/captiveportal/voucher/list_voucher_groups/Guest", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})

	data, err := client.FetchCaptivePortalVouchers()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Error("expected Present=true")
	}
	if len(data.Groups) != 0 {
		t.Errorf("expected 0 groups, got %d", len(data.Groups))
	}
}

func TestFetchCaptivePortalVouchers_404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchCaptivePortalVouchers()
	if err != nil {
		t.Fatalf("expected nil error on 404 (feature absent), got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on 404")
	}
}

func TestFetchCaptivePortalVouchers_NextExpiryTimestamp(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/captiveportal/voucher/list_providers", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`["Guest"]`))
	})
	mux.HandleFunc("/api/captiveportal/voucher/list_voucher_groups/Guest", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`["Group1"]`))
	})
	mux.HandleFunc("/api/captiveportal/voucher/list_vouchers/Guest/Group1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[
			{"username":"a","validity":3600,"expirytime":2000000000,"starttime":0,"endtime":0,"state":"unused"},
			{"username":"b","validity":3600,"expirytime":1900000000,"starttime":0,"endtime":0,"state":"valid"},
			{"username":"c","validity":3600,"expirytime":0,"starttime":0,"endtime":0,"state":"expired"}
		]`))
	})

	data, err := client.FetchCaptivePortalVouchers()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(data.Groups))
	}
	g := data.Groups[0]
	if !g.HasNextExpiryTimestamp {
		t.Fatal("expected HasNextExpiryTimestamp=true")
	}
	// Min positive expirytime across unused/valid rows: 1900000000 (the
	// expired row's 0 must not participate).
	if g.NextExpiryTimestamp != 1900000000 {
		t.Errorf("expected NextExpiryTimestamp=1900000000, got %v", g.NextExpiryTimestamp)
	}
}

func TestFetchCaptivePortalVouchers_UsernameNeverDecoded(t *testing.T) {
	// Sensitivity guard (tracker #227): captivePortalVoucherRow must have no
	// field that could ever carry the voucher code. Enforced structurally via
	// reflection so a future field addition trips this test, not just review.
	typ := reflect.TypeOf(captivePortalVoucherRow{})
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		if strings.Contains(strings.ToLower(tag), "username") {
			t.Fatalf("captivePortalVoucherRow must never decode the username field; found tag %q", tag)
		}
	}
}

func TestFetchCaptivePortalVouchers_ProviderGroupFailureSkipped(t *testing.T) {
	// A provider whose groups call fails outright is skipped, not fatal; a
	// group whose vouchers call fails is likewise skipped.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/captiveportal/voucher/list_providers", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`["Bad", "Good"]`))
	})
	mux.HandleFunc("/api/captiveportal/voucher/list_voucher_groups/Bad", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	mux.HandleFunc("/api/captiveportal/voucher/list_voucher_groups/Good", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`["G1", "BadGroup"]`))
	})
	mux.HandleFunc("/api/captiveportal/voucher/list_vouchers/Good/G1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"username":"x","validity":10,"expirytime":0,"starttime":0,"endtime":0,"state":"valid"}]`))
	})
	mux.HandleFunc("/api/captiveportal/voucher/list_vouchers/Good/BadGroup", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	data, err := client.FetchCaptivePortalVouchers()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Groups) != 1 {
		t.Fatalf("expected exactly 1 surviving group, got %d: %+v", len(data.Groups), data.Groups)
	}
	if data.Groups[0].Provider != "Good" || data.Groups[0].Group != "G1" {
		t.Errorf("wrong surviving group: %+v", data.Groups[0])
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
