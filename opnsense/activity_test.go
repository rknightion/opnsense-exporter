package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchActivity_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/diagnostics/activity/get_activity" {
			t.Errorf("expected path /api/diagnostics/activity/get_activity, got %s", r.URL.Path)
		}
		w.Write([]byte(`{
			"headers": [
				"last pid: 65652;  load averages:  0.74,  0.52,  0.49  up 23+03:58:03    17:13:41",
				"849 threads:   13 running, 802 sleeping, 34 waiting",
				"CPU:  1.3% user,  0.0% nice,  2.2% system,  0.1% interrupt, 96.4% idle",
				"Mem: 5249M Active, 3393M Inact, 5446M Laundry, 13G Wired, 372K Buf, 3900M Free",
				"ARC: 8970M Total, 4571M MFU, 3776M MRU, 34M Anon, 67M Header, 517M Other",
				"     7809M Compressed, 13G Uncompressed, 1.74:1 Ratio",
				"Swap: 10G Total, 433M Used, 9807M Free, 4% Inuse"
			],
			"details": []
		}`))
	})
	defer server.Close()

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.ThreadsTotal != 849 {
		t.Errorf("expected ThreadsTotal=849, got %d", data.ThreadsTotal)
	}
	if data.ThreadsRunning != 13 {
		t.Errorf("expected ThreadsRunning=13, got %d", data.ThreadsRunning)
	}
	if data.ThreadsSleeping != 802 {
		t.Errorf("expected ThreadsSleeping=802, got %d", data.ThreadsSleeping)
	}
	if data.ThreadsWaiting != 34 {
		t.Errorf("expected ThreadsWaiting=34, got %d", data.ThreadsWaiting)
	}
	if data.CPUUser != 1.3 {
		t.Errorf("expected CPUUser=1.3, got %f", data.CPUUser)
	}
	if data.CPUNice != 0.0 {
		t.Errorf("expected CPUNice=0.0, got %f", data.CPUNice)
	}
	if data.CPUSystem != 2.2 {
		t.Errorf("expected CPUSystem=2.2, got %f", data.CPUSystem)
	}
	if data.CPUInterrupt != 0.1 {
		t.Errorf("expected CPUInterrupt=0.1, got %f", data.CPUInterrupt)
	}
	if data.CPUIdle != 96.4 {
		t.Errorf("expected CPUIdle=96.4, got %f", data.CPUIdle)
	}
}

func TestFetchActivity_EmptyHeaders(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/diagnostics/activity/get_activity" {
			t.Errorf("expected path /api/diagnostics/activity/get_activity, got %s", r.URL.Path)
		}
		w.Write([]byte(`{
			"headers": [],
			"details": []
		}`))
	})
	defer server.Close()

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.ThreadsTotal != 0 {
		t.Errorf("expected ThreadsTotal=0, got %d", data.ThreadsTotal)
	}
	if data.ThreadsRunning != 0 {
		t.Errorf("expected ThreadsRunning=0, got %d", data.ThreadsRunning)
	}
	if data.ThreadsSleeping != 0 {
		t.Errorf("expected ThreadsSleeping=0, got %d", data.ThreadsSleeping)
	}
	if data.ThreadsWaiting != 0 {
		t.Errorf("expected ThreadsWaiting=0, got %d", data.ThreadsWaiting)
	}
	if data.CPUUser != 0.0 {
		t.Errorf("expected CPUUser=0.0, got %f", data.CPUUser)
	}
	if data.CPUNice != 0.0 {
		t.Errorf("expected CPUNice=0.0, got %f", data.CPUNice)
	}
	if data.CPUSystem != 0.0 {
		t.Errorf("expected CPUSystem=0.0, got %f", data.CPUSystem)
	}
	if data.CPUInterrupt != 0.0 {
		t.Errorf("expected CPUInterrupt=0.0, got %f", data.CPUInterrupt)
	}
	if data.CPUIdle != 0.0 {
		t.Errorf("expected CPUIdle=0.0, got %f", data.CPUIdle)
	}
}

func TestFetchActivity_MalformedHeaders(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/diagnostics/activity/get_activity" {
			t.Errorf("expected path /api/diagnostics/activity/get_activity, got %s", r.URL.Path)
		}
		w.Write([]byte(`{
			"headers": [
				"some random header text",
				"no threads info here",
				"CPU usage is unknown"
			],
			"details": []
		}`))
	})
	defer server.Close()

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.ThreadsTotal != 0 {
		t.Errorf("expected ThreadsTotal=0, got %d", data.ThreadsTotal)
	}
	if data.ThreadsRunning != 0 {
		t.Errorf("expected ThreadsRunning=0, got %d", data.ThreadsRunning)
	}
	if data.CPUUser != 0.0 {
		t.Errorf("expected CPUUser=0.0, got %f", data.CPUUser)
	}
	if data.CPUIdle != 0.0 {
		t.Errorf("expected CPUIdle=0.0, got %f", data.CPUIdle)
	}
}

func TestFetchActivity_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchActivity()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
