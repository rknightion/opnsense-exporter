package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchSnapshotsSupported_ZFS(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{"supported": true}`))
	})
	defer server.Close()

	supported, err := client.FetchSnapshotsSupported()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !supported {
		t.Error("expected supported=true")
	}
}

// TestFetchSnapshotsSupported_UFS covers the shape captured live from the UFS
// dev box (2026-07-13): a plain 200 with supported:false, not a 404.
func TestFetchSnapshotsSupported_UFS(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"supported": false}`))
	})
	defer server.Close()

	supported, err := client.FetchSnapshotsSupported()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if supported {
		t.Error("expected supported=false")
	}
}

func TestFetchSnapshotsSupported_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchSnapshotsSupported()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

// TestFetchBootEnvironments_ZFS uses the sanitised prod capture shape
// (2026-07-13): rows carry mountpoint/created_str alongside created (a plain
// int), and observed active values are "NR" and "-".
func TestFetchBootEnvironments_ZFS(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"total": 2,
			"rowCount": 2,
			"current": 1,
			"rows": [
				{
					"uuid": "3b78af2f-c0b8-3156-b084-fe8f5a94e2e4",
					"name": "default",
					"active": "NR",
					"mountpoint": "/",
					"size": "28.8G",
					"created_str": "2024-08-29 08:16",
					"created": 1724915760
				},
				{
					"uuid": "8021f880-126b-3ab0-bbe6-5acf478c62fb",
					"name": "pre-fw-rule-migration",
					"active": "-",
					"mountpoint": "-",
					"size": "13.3G",
					"created_str": "2026-02-06 13:28",
					"created": 1770384480
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchBootEnvironments()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Total != 2 {
		t.Errorf("expected Total=2, got %d", data.Total)
	}
	if !data.HasActive {
		t.Fatal("expected HasActive=true")
	}
	if data.ActiveCreatedTimestamp != 1724915760 {
		t.Errorf("expected ActiveCreatedTimestamp=1724915760, got %v", data.ActiveCreatedTimestamp)
	}
}

// TestFetchBootEnvironments_UFS covers the empty rowset captured live from the
// UFS dev box (2026-07-13): total/rowCount 0, rows [].
func TestFetchBootEnvironments_UFS(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total": 0, "rowCount": 0, "current": 1, "rows": []}`))
	})
	defer server.Close()

	data, err := client.FetchBootEnvironments()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Total != 0 {
		t.Errorf("expected Total=0, got %d", data.Total)
	}
	if data.HasActive {
		t.Error("expected HasActive=false")
	}
	if data.ActiveCreatedTimestamp != 0 {
		t.Errorf("expected ActiveCreatedTimestamp=0, got %v", data.ActiveCreatedTimestamp)
	}
}

// TestFetchBootEnvironments_NoActiveRow covers an all "-" rowset: no row's
// active flag contains "N", so HasActive must stay false rather than
// defaulting to some arbitrary row.
func TestFetchBootEnvironments_NoActiveRow(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1,
			"rowCount": 1,
			"current": 1,
			"rows": [
				{"uuid": "x", "name": "orphan", "active": "-", "mountpoint": "-", "size": "1G", "created_str": "x", "created": 123}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchBootEnvironments()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Total != 1 {
		t.Errorf("expected Total=1, got %d", data.Total)
	}
	if data.HasActive {
		t.Error("expected HasActive=false when no row's active flag contains N")
	}
}

func TestFetchBootEnvironments_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchBootEnvironments()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
