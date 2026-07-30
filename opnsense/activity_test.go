package opnsense

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
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
}

// TestFetchActivity_ZombieBetweenSleepingAndWaiting guards #82: FreeBSD's top
// inserts non-zero states (zombie/stopped/starting) in a fixed order, breaking a
// regex that requires running,sleeping,waiting to be contiguous. Each state must
// be parsed independently.
func TestFetchActivity_ZombieBetweenSleepingAndWaiting(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"headers": [
				"879 threads:   13 running, 831 sleeping, 1 zombie, 34 waiting",
				"CPU:  1.3% user,  0.0% nice,  2.2% system,  0.1% interrupt, 96.4% idle"
			],
			"details": []
		}`))
	})
	defer server.Close()

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.ThreadsTotal != 879 {
		t.Errorf("expected ThreadsTotal=879, got %d", data.ThreadsTotal)
	}
	if data.ThreadsRunning != 13 {
		t.Errorf("expected ThreadsRunning=13, got %d", data.ThreadsRunning)
	}
	if data.ThreadsSleeping != 831 {
		t.Errorf("expected ThreadsSleeping=831, got %d", data.ThreadsSleeping)
	}
	if data.ThreadsWaiting != 34 {
		t.Errorf("expected ThreadsWaiting=34, got %d", data.ThreadsWaiting)
	}
	// CPU must still parse from the following header despite the thread-state change.
}

// TestFetchActivity_WaitingAbsent guards #82: top only prints non-zero states, so
// a header can omit waiting entirely. The present states must still parse and the
// absent one defaults to 0 without failing the whole parse.
func TestFetchActivity_WaitingAbsent(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"headers": [
				"8 threads:   2 running, 6 sleeping"
			],
			"details": []
		}`))
	})
	defer server.Close()

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.ThreadsTotal != 8 {
		t.Errorf("expected ThreadsTotal=8, got %d", data.ThreadsTotal)
	}
	if data.ThreadsRunning != 2 {
		t.Errorf("expected ThreadsRunning=2, got %d", data.ThreadsRunning)
	}
	if data.ThreadsSleeping != 6 {
		t.Errorf("expected ThreadsSleeping=6, got %d", data.ThreadsSleeping)
	}
	if data.ThreadsWaiting != 0 {
		t.Errorf("expected ThreadsWaiting=0 (absent), got %d", data.ThreadsWaiting)
	}
}

// TestFetchActivity_StartingBeforeRunning guards #82: a starting/stopped segment
// can precede running; the remaining states must still parse correctly.
func TestFetchActivity_StartingBeforeRunning(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"headers": [
				"900 threads:   1 starting, 13 running, 850 sleeping, 1 stopped, 35 waiting"
			],
			"details": []
		}`))
	})
	defer server.Close()

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.ThreadsTotal != 900 {
		t.Errorf("expected ThreadsTotal=900, got %d", data.ThreadsTotal)
	}
	if data.ThreadsRunning != 13 {
		t.Errorf("expected ThreadsRunning=13, got %d", data.ThreadsRunning)
	}
	if data.ThreadsSleeping != 850 {
		t.Errorf("expected ThreadsSleeping=850, got %d", data.ThreadsSleeping)
	}
	if data.ThreadsWaiting != 35 {
		t.Errorf("expected ThreadsWaiting=35, got %d", data.ThreadsWaiting)
	}
}

// TestFetchActivity_WarnsOnUnparsableThreadStates guards #82's acceptance
// criterion: when a "threads:" header is present but no state segment parses, the
// failure must be logged, not silent.
func TestFetchActivity_WarnsOnUnparsableThreadStates(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"headers": [
				"42 threads: something totally unexpected here"
			],
			"details": []
		}`))
	})
	defer server.Close()

	var buf bytes.Buffer
	client.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The total is still recoverable from the header prefix.
	if data.ThreadsTotal != 42 {
		t.Errorf("expected ThreadsTotal=42, got %d", data.ThreadsTotal)
	}
	if !strings.Contains(buf.String(), "thread-state") {
		t.Errorf("expected a warning about unparsable thread states; got log: %q", buf.String())
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

// TestFetchActivity_ThreadStateMatchesAreBounded covers #321: the thread-state
// scan used FindAllStringSubmatch(header, -1), so an appliance-controlled
// header — bounded only by the 64 MiB response cap — could make the client
// materialize millions of submatch slices (allocation amplification; this is
// NOT ReDoS, Go's RE2 cannot backtrack). Only 7 thread states exist and
// FreeBSD's top prints each at most once, so a small cap cannot lose real
// data. The parse of a pathological header must stay finite and the last
// occurrence of each state must still be what wins for a normal header.
func TestFetchActivity_ThreadStateMatchesAreBounded(t *testing.T) {
	// Far more state segments than any real `top` header carries.
	var sb strings.Builder
	sb.WriteString("849 threads:")
	for i := 0; i < 100000; i++ {
		sb.WriteString(" 1 running,")
	}
	header := sb.String()

	if got := len(parseThreadStates(header)); got > threadStateMatchLimit {
		t.Fatalf("thread-state scan returned %d matches; expected at most %d", got, threadStateMatchLimit)
	}
	if threadStateMatchLimit <= 0 || threadStateMatchLimit > 64 {
		t.Fatalf("threadStateMatchLimit=%d is outside the sane range (must bound allocation, must exceed the 7 real states)", threadStateMatchLimit)
	}

	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"headers":[%q],"details":[]}`, header)
	})
	defer server.Close()

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.ThreadsTotal != 849 {
		t.Errorf("expected ThreadsTotal=849, got %d", data.ThreadsTotal)
	}
	if data.ThreadsRunning != 1 {
		t.Errorf("expected ThreadsRunning=1, got %d", data.ThreadsRunning)
	}
}

// TestFetchActivity_AllSevenThreadStatesParse pins the lower bound of the
// #321 cap: every state FreeBSD's top can print must still be seen, so the
// bound can never be tightened below the real maximum.
func TestFetchActivity_AllSevenThreadStatesParse(t *testing.T) {
	const header = "849 threads:   1 starting, 13 running, 802 sleeping, 2 stopped, 3 zombie, 34 waiting, 5 lock"

	states := parseThreadStates(header)
	if len(states) != 7 {
		t.Fatalf("expected all 7 thread states to be captured under the cap, got %d", len(states))
	}

	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"headers":[%q],"details":[]}`, header)
	})
	defer server.Close()

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.ThreadsRunning != 13 || data.ThreadsSleeping != 802 || data.ThreadsWaiting != 34 {
		t.Errorf("expected running/sleeping/waiting = 13/802/34, got %d/%d/%d",
			data.ThreadsRunning, data.ThreadsSleeping, data.ThreadsWaiting)
	}
}
