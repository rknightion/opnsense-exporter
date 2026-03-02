package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchMbufStatistics_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"mbuf-statistics": {
				"mbuf-current": 1024,
				"mbuf-cache": 512,
				"mbuf-total": 2048,
				"mbuf-max": 4096,
				"cluster-current": 256,
				"cluster-cache": 128,
				"cluster-total": 512,
				"cluster-max": 1024,
				"mbuf-failures": 3,
				"cluster-failures": 1,
				"packet-failures": 0,
				"mbuf-sleeps": 5,
				"cluster-sleeps": 2,
				"packet-sleeps": 0,
				"jumbop-current": 10,
				"jumbop-cache": 5,
				"jumbop-total": 20,
				"jumbop-max": 50,
				"jumbop-failures": 7,
				"jumbop-sleeps": 4,
				"bytes-in-use": 65536,
				"bytes-total": 131072,
				"percentage": 50,
				"mbuf-and-cluster": 100
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchMbufStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check scalar fields
	if data.MbufCurrent != 1024 {
		t.Errorf("expected MbufCurrent=1024, got %d", data.MbufCurrent)
	}
	if data.MbufCache != 512 {
		t.Errorf("expected MbufCache=512, got %d", data.MbufCache)
	}
	if data.MbufTotal != 2048 {
		t.Errorf("expected MbufTotal=2048, got %d", data.MbufTotal)
	}
	if data.ClusterCurrent != 256 {
		t.Errorf("expected ClusterCurrent=256, got %d", data.ClusterCurrent)
	}
	if data.ClusterCache != 128 {
		t.Errorf("expected ClusterCache=128, got %d", data.ClusterCache)
	}
	if data.ClusterTotal != 512 {
		t.Errorf("expected ClusterTotal=512, got %d", data.ClusterTotal)
	}
	if data.ClusterMax != 1024 {
		t.Errorf("expected ClusterMax=1024, got %d", data.ClusterMax)
	}
	if data.BytesInUse != 65536 {
		t.Errorf("expected BytesInUse=65536, got %d", data.BytesInUse)
	}
	if data.BytesTotal != 131072 {
		t.Errorf("expected BytesTotal=131072, got %d", data.BytesTotal)
	}

	// Check FailuresByType map
	expectedFailures := map[string]int{
		"mbuf":    3,
		"cluster": 1,
		"packet":  0,
		"jumbop":  7,
	}
	for k, want := range expectedFailures {
		if got := data.FailuresByType[k]; got != want {
			t.Errorf("FailuresByType[%q] = %d; want %d", k, got, want)
		}
	}

	// Check SleepsByType map
	expectedSleeps := map[string]int{
		"mbuf":    5,
		"cluster": 2,
		"packet":  0,
		"jumbop":  4,
	}
	for k, want := range expectedSleeps {
		if got := data.SleepsByType[k]; got != want {
			t.Errorf("SleepsByType[%q] = %d; want %d", k, got, want)
		}
	}
}

func TestFetchMbufStatistics_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchMbufStatistics()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
