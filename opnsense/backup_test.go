package opnsense

import (
	"math"
	"net/http"
	"testing"
)

func TestFetchConfigBackupHistory_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		// Sanitised prod shapes (2026-07-13 capture): time is a quoted decimal
		// epoch string, filesize a JSON int. Items are newest-first.
		w.Write([]byte(`{
			"items": [
				{
					"time": "1783886416.55",
					"time_iso": "2026-07-12T21:00:16+01:00",
					"description": "/api/example/config change made changes",
					"username": "root@10.0.0.1",
					"filesize": 417639,
					"id": "config-1783886416.5486.xml"
				},
				{
					"time": "1783886406.03",
					"time_iso": "2026-07-12T21:00:06+01:00",
					"description": "/api/example/other change made changes",
					"username": "root@10.0.0.1",
					"filesize": 417637,
					"id": "config-1783886406.0265.xml"
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchConfigBackupHistory()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.Count != 2 {
		t.Errorf("expected Count=2, got %d", data.Count)
	}
	if data.LastTimestamp != 1783886416.55 {
		t.Errorf("expected LastTimestamp=1783886416.55, got %v", data.LastTimestamp)
	}
	if data.LastSizeBytes != 417639 {
		t.Errorf("expected LastSizeBytes=417639, got %v", data.LastSizeBytes)
	}
}

// TestFetchConfigBackupHistory_OutOfOrder covers the defensive max(time) scan:
// even if a response were not newest-first, the newest backup must still win.
func TestFetchConfigBackupHistory_OutOfOrder(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"items": [
				{"time": "1000", "filesize": 100},
				{"time": "3000", "filesize": 300},
				{"time": "2000", "filesize": 200}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchConfigBackupHistory()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Count != 3 {
		t.Errorf("expected Count=3, got %d", data.Count)
	}
	if data.LastTimestamp != 3000 {
		t.Errorf("expected LastTimestamp=3000, got %v", data.LastTimestamp)
	}
	if data.LastSizeBytes != 300 {
		t.Errorf("expected LastSizeBytes=300, got %v", data.LastSizeBytes)
	}
}

func TestFetchConfigBackupHistory_Empty(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"items": []}`))
	})
	defer server.Close()

	data, err := client.FetchConfigBackupHistory()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Count != 0 {
		t.Errorf("expected Count=0, got %d", data.Count)
	}
	if data.LastTimestamp != 0 {
		t.Errorf("expected LastTimestamp=0, got %v", data.LastTimestamp)
	}
	if data.LastSizeBytes != 0 {
		t.Errorf("expected LastSizeBytes=0, got %v", data.LastSizeBytes)
	}
}

func TestFetchConfigBackupHistory_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchConfigBackupHistory()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

// TestFetchConfigBackupHistory_NaNTimestamp is the #323 regression test.
// backup.go seeds its newest-timestamp scan from Items[0]; strconv.ParseFloat
// accepts "NaN" WITHOUT an error, and every comparison against NaN is false,
// so a NaN seed could never be displaced by a later, larger timestamp. The
// resulting NaN opnsense_backup_last_timestamp_seconds makes a
// `time() - metric > X` staleness alert silently never fire.
func TestFetchConfigBackupHistory_NaNTimestamp(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"items": [
				{"time": "NaN", "filesize": 100},
				{"time": "1783886416.55", "filesize": 417639}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchConfigBackupHistory()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if math.IsNaN(data.LastTimestamp) || math.IsInf(data.LastTimestamp, 0) {
		t.Fatalf("LastTimestamp is non-finite (%v); a NaN gauge defeats staleness alerting", data.LastTimestamp)
	}
	if data.LastTimestamp != 1783886416.55 {
		t.Errorf("expected LastTimestamp=1783886416.55 (the real entry must win over the NaN seed), got %v", data.LastTimestamp)
	}
}

// TestFetchConfigBackupHistory_InfTimestamp covers the ±Inf half of #323:
// +Inf DOES compare greater than every real timestamp, so it wins the scan
// outright and pins the gauge at infinity.
func TestFetchConfigBackupHistory_InfTimestamp(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"items": [
				{"time": "+Inf", "filesize": 100},
				{"time": "1783886416.55", "filesize": 417639}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchConfigBackupHistory()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if math.IsInf(data.LastTimestamp, 0) || math.IsNaN(data.LastTimestamp) {
		t.Fatalf("LastTimestamp is non-finite (%v)", data.LastTimestamp)
	}
	if data.LastTimestamp != 1783886416.55 {
		t.Errorf("expected LastTimestamp=1783886416.55, got %v", data.LastTimestamp)
	}
}
