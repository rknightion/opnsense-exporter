package opnsense

import (
	"net/http"
	"testing"
	"time"
)

// TestFetchClamAVVersion_Success covers the real post-freshclam payload shape,
// captured from a live OPNsense 26.7-devel box (captures/clamav/service_version.json):
// numeric fields arrive as strings with a leading space, and daily/main/bytecode
// are free-text version strings with an embedded build date.
func TestFetchClamAVVersion_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/clamav/service/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{"version":{"daily":" version 28059, sigs: 355490, built on Mon Jul 13 07:25:07 2026","main":" version 63, sigs: 3287027, built on Tue Dec 16 23:18:22 2025","bytecode":" version 339, sigs: 80, built on Thu Sep 11 13:29:19 2025","signatures":" 3642597","clamav":" 1.5.2"}}`))
	})

	data, err := client.FetchClamAVVersion()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if data.EngineVersion != "1.5.2" {
		t.Errorf("expected EngineVersion '1.5.2' (leading space trimmed), got %q", data.EngineVersion)
	}
	if !data.HasTotalSignatures {
		t.Fatal("expected HasTotalSignatures=true")
	}
	if data.TotalSignatures != 3642597 {
		t.Errorf("expected TotalSignatures=3642597 (leading space trimmed), got %d", data.TotalSignatures)
	}
	if len(data.Databases) != 3 {
		t.Fatalf("expected 3 parsed databases, got %d: %+v", len(data.Databases), data.Databases)
	}

	byName := make(map[string]ClamAVSignatureDB, 3)
	for _, db := range data.Databases {
		byName[db.Name] = db
	}

	daily, ok := byName["daily"]
	if !ok {
		t.Fatal("expected a 'daily' database entry")
	}
	if daily.Version != 28059 {
		t.Errorf("expected daily version 28059, got %d", daily.Version)
	}
	wantDaily := time.Date(2026, time.July, 13, 7, 25, 7, 0, time.UTC).Unix()
	if int64(daily.BuiltTimestamp) != wantDaily {
		t.Errorf("expected daily built timestamp %d, got %v", wantDaily, daily.BuiltTimestamp)
	}

	main, ok := byName["main"]
	if !ok {
		t.Fatal("expected a 'main' database entry")
	}
	if main.Version != 63 {
		t.Errorf("expected main version 63, got %d", main.Version)
	}
	wantMain := time.Date(2025, time.December, 16, 23, 18, 22, 0, time.UTC).Unix()
	if int64(main.BuiltTimestamp) != wantMain {
		t.Errorf("expected main built timestamp %d, got %v", wantMain, main.BuiltTimestamp)
	}

	bytecode, ok := byName["bytecode"]
	if !ok {
		t.Fatal("expected a 'bytecode' database entry")
	}
	if bytecode.Version != 339 {
		t.Errorf("expected bytecode version 339, got %d", bytecode.Version)
	}
	wantBytecode := time.Date(2025, time.September, 11, 13, 29, 19, 0, time.UTC).Unix()
	if int64(bytecode.BuiltTimestamp) != wantBytecode {
		t.Errorf("expected bytecode built timestamp %d, got %v", wantBytecode, bytecode.BuiltTimestamp)
	}
}

// TestFetchClamAVVersion_NeverRan covers the shape captured before freshclam
// has ever run (captures/clamav/service_version_never_ran.json): daily/main/
// bytecode keys are absent entirely, and signatures reads " 0" — not an error,
// just "no signature data yet".
func TestFetchClamAVVersion_NeverRan(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/clamav/service/version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"version":{"signatures":" 0","clamav":" 1.5.2"}}`))
	})

	data, err := client.FetchClamAVVersion()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if data.EngineVersion != "1.5.2" {
		t.Errorf("expected EngineVersion '1.5.2', got %q", data.EngineVersion)
	}
	if !data.HasTotalSignatures {
		t.Fatal("expected HasTotalSignatures=true even when the count is zero")
	}
	if data.TotalSignatures != 0 {
		t.Errorf("expected TotalSignatures=0, got %d", data.TotalSignatures)
	}
	if len(data.Databases) != 0 {
		t.Errorf("expected 0 parsed databases (keys absent entirely), got %d: %+v", len(data.Databases), data.Databases)
	}
}

// TestFetchClamAVVersion_NotFound covers the os-clamav-plugin-absent case: the
// endpoint 404s and must be treated as "feature absent", not an error.
func TestFetchClamAVVersion_NotFound(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/clamav/service/version", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	})

	data, err := client.FetchClamAVVersion()
	if err != nil {
		t.Fatalf("expected nil error for 404 (plugin absent), got %v", err)
	}
	if data.Present {
		t.Error("expected Present=false for 404")
	}
	if data.EngineVersion != "" || len(data.Databases) != 0 {
		t.Errorf("expected empty data for 404, got %+v", data)
	}
}

// TestFetchClamAVVersion_ServerError covers a genuine upstream failure, which
// must still propagate as an error (unlike a 404).
func TestFetchClamAVVersion_ServerError(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/clamav/service/version", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})

	_, err := client.FetchClamAVVersion()
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

// TestFetchClamAVVersion_EmptyArrayPayload covers the theoretical shape where
// the backing configd call produces no parseable output at all: PHP's
// json_encode(array()) emits "[]", which cannot unmarshal into the object-
// shaped struct. This must degrade to "present, no data" rather than failing
// the whole scrape.
func TestFetchClamAVVersion_EmptyArrayPayload(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/clamav/service/version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})

	data, err := client.FetchClamAVVersion()
	if err != nil {
		t.Fatalf("expected nil error for an unparseable '[]' payload, got %v", err)
	}
	if !data.Present {
		t.Error("expected Present=true (the endpoint answered 200, just with no usable data)")
	}
	if data.EngineVersion != "" || data.HasTotalSignatures || len(data.Databases) != 0 {
		t.Errorf("expected empty data for an unparseable payload, got %+v", data)
	}
}

// TestFetchClamAVVersion_MalformedDatabaseString covers a daily/main/bytecode
// value that doesn't match the expected "version N, sigs: N, built on <date>"
// shape at all: it must be skipped silently, never fail the scrape.
func TestFetchClamAVVersion_MalformedDatabaseString(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/clamav/service/version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"version":{"daily":" not a recognisable version string","main":" version 63, sigs: 3287027, built on Tue Dec 16 23:18:22 2025","signatures":" 100","clamav":" 1.5.2"}}`))
	})

	data, err := client.FetchClamAVVersion()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Databases) != 1 {
		t.Fatalf("expected only the 'main' database to parse, got %d: %+v", len(data.Databases), data.Databases)
	}
	if data.Databases[0].Name != "main" {
		t.Errorf("expected the surviving entry to be 'main', got %q", data.Databases[0].Name)
	}
}

// TestFetchClamAVVersion_MalformedBuildDate covers a version string whose
// version/sigs numbers parse but whose build-date fragment does not: the
// version number is still valid data and must still be emitted, just with
// BuiltTimestamp left at 0.
func TestFetchClamAVVersion_MalformedBuildDate(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/clamav/service/version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"version":{"daily":" version 28059, sigs: 355490, built on not-a-real-date","signatures":" 100","clamav":" 1.5.2"}}`))
	})

	data, err := client.FetchClamAVVersion()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Databases) != 1 {
		t.Fatalf("expected the 'daily' database to still parse (version is valid), got %d: %+v", len(data.Databases), data.Databases)
	}
	if data.Databases[0].Version != 28059 {
		t.Errorf("expected version 28059, got %d", data.Databases[0].Version)
	}
	if data.Databases[0].BuiltTimestamp != 0 {
		t.Errorf("expected BuiltTimestamp=0 for an unparseable date, got %v", data.Databases[0].BuiltTimestamp)
	}
}
