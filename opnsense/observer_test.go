package opnsense

import (
	"net/http"
	"sync"
	"testing"
	"time"
)

type obsCall struct {
	endpoint string
	code     int
	dur      time.Duration
}

type fakeObserver struct {
	mu    sync.Mutex
	calls []obsCall
}

func (f *fakeObserver) ObserveAPIRequest(endpoint string, code int, dur time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, obsCall{endpoint, code, dur})
}

func (f *fakeObserver) snapshot() []obsCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]obsCall(nil), f.calls...)
}

// TestClientObservesSuccessfulRequest covers #126 acceptance #3: a successful do()
// call notifies the observer once with the endpoint, a 2xx code, and a duration —
// this is the single seam that drives both the api_requests_total counter and the
// api_request_duration_seconds histogram.
func TestClientObservesSuccessfulRequest(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	defer server.Close()

	obs := &fakeObserver{}
	client.SetRequestObserver(obs)

	var out map[string]any
	if err := client.do("GET", "api/test/ok", nil, &out); err != nil {
		t.Fatalf("do: %v", err)
	}

	calls := obs.snapshot()
	if len(calls) != 1 {
		t.Fatalf("expected exactly 1 observation, got %d: %+v", len(calls), calls)
	}
	if calls[0].endpoint != "api/test/ok" {
		t.Errorf("endpoint = %q, want api/test/ok", calls[0].endpoint)
	}
	if calls[0].code != http.StatusOK {
		t.Errorf("code = %d, want 200", calls[0].code)
	}
	if calls[0].dur < 0 {
		t.Errorf("duration = %v, want >= 0", calls[0].dur)
	}
}

// TestClientObservesFailedRequest covers #126 acceptance #3: a failed call still
// notifies the observer, carrying the non-2xx status code (so api_requests_total gets a
// meaningful `code` label and provides the error-rate denominator).
func TestClientObservesFailedRequest(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	})
	defer server.Close()

	obs := &fakeObserver{}
	client.SetRequestObserver(obs)

	var out map[string]any
	if err := client.do("GET", "api/test/fail", nil, &out); err == nil {
		t.Fatal("expected an error for a 500 response")
	}

	calls := obs.snapshot()
	if len(calls) != 1 {
		t.Fatalf("expected exactly 1 observation, got %d: %+v", len(calls), calls)
	}
	if calls[0].code != http.StatusInternalServerError {
		t.Errorf("code = %d, want 500", calls[0].code)
	}
}

// TestClientObservesFormPost covers the doForm()/POST path through the same choke point.
func TestClientObservesFormPost(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	defer server.Close()

	obs := &fakeObserver{}
	client.SetRequestObserver(obs)

	var out map[string]any
	if err := client.doForm("api/test/form", nil, &out); err != nil {
		t.Fatalf("doForm: %v", err)
	}
	calls := obs.snapshot()
	if len(calls) != 1 || calls[0].endpoint != "api/test/form" || calls[0].code != http.StatusOK {
		t.Fatalf("expected one 200 observation for api/test/form, got %+v", calls)
	}
}
