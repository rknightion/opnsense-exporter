package cpustream

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testConfig is a Config scaled down so the reconnect and stall paths run in
// milliseconds rather than seconds. The production defaults are asserted separately
// by TestConfigDefaults.
func testConfig() Config {
	return Config{
		StallAfter:  150 * time.Millisecond,
		GracePeriod: 300 * time.Millisecond,
		MaxFrameGap: time.Second,
		MinBackoff:  time.Millisecond,
		MaxBackoff:  10 * time.Millisecond,
	}
}

// sseServer serves one SSE response per request from handler, flushing each write.
func sseServer(t *testing.T, handler func(w io.Writer, flush func(), r *http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		f, ok := w.(http.Flusher)
		if !ok {
			t.Error("test server response writer is not a Flusher")
			return
		}
		w.WriteHeader(http.StatusOK)
		f.Flush()
		handler(w, f.Flush, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func frameLine(idle int) string {
	return fmt.Sprintf("event: message\ndata: {\"total\":%d,\"user\":%d,\"nice\":0,\"sys\":0,\"intr\":0,\"idle\":%d}\n\n",
		100-idle, 100-idle, idle)
}

// httpOpener dials srv and returns the response body, mirroring what
// opnsense.Client.OpenCPUStream does in production.
func httpOpener(srv *httptest.Server) Opener {
	return func(ctx context.Context) (io.ReadCloser, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		if err != nil {
			return nil, err
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			return nil, err
		}
		return resp.Body, nil
	}
}

// eventually polls cond until it holds or the deadline passes.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func TestStreamAccumulatesFrames(t *testing.T) {
	srv := sseServer(t, func(w io.Writer, flush func(), _ *http.Request) {
		for range 200 {
			if _, err := io.WriteString(w, frameLine(100)); err != nil {
				return
			}
			flush()
			time.Sleep(5 * time.Millisecond)
		}
	})

	s := New(httpOpener(srv), testConfig())
	s.Start(context.Background())
	defer s.Close()

	eventually(t, "the counter to advance past the discarded first frame", func() bool {
		return s.Snapshot().Seconds[ModeIdle] > 0
	})

	snap := s.Snapshot()
	if !snap.Connected {
		t.Error("stream should report connected while frames are flowing")
	}
	if !snap.Fresh {
		t.Error("counters should be publishable while frames are flowing")
	}
	if snap.Frames < 2 {
		t.Errorf("frames = %d, want at least 2", snap.Frames)
	}
	// A 100%-idle box: idle accrues, nothing else does.
	for _, mode := range []string{ModeUser, ModeNice, ModeSystem, ModeInterrupt} {
		if snap.Seconds[mode] != 0 {
			t.Errorf("seconds[%s] = %v, want 0 on a fully idle box", mode, snap.Seconds[mode])
		}
	}
}

// TestStreamReconnectsAndKeepsItsCounter covers the mandatory recovery path: the
// connection drops (server-side close, which is exactly what
// `server.max-write-idle = 999` produces on a quiet connection), the stream
// re-dials, and the accumulated counter survives — the exporter process never
// restarted, so a counter reset would be a lie.
func TestStreamReconnectsAndKeepsItsCounter(t *testing.T) {
	var conns atomic.Int64
	srv := sseServer(t, func(w io.Writer, flush func(), _ *http.Request) {
		n := conns.Add(1)
		limit := 200
		if n == 1 {
			limit = 3 // first connection dies after three frames
		}
		for range limit {
			if _, err := io.WriteString(w, frameLine(100)); err != nil {
				return
			}
			flush()
			time.Sleep(5 * time.Millisecond)
		}
	})

	s := New(httpOpener(srv), testConfig())
	s.Start(context.Background())
	defer s.Close()

	eventually(t, "the first connection to accumulate", func() bool {
		return s.Snapshot().Seconds[ModeIdle] > 0
	})
	before := s.Snapshot().Seconds[ModeIdle]

	eventually(t, "a reconnect", func() bool { return s.Snapshot().Reconnects > 0 })
	eventually(t, "the counter to keep advancing after the reconnect", func() bool {
		return s.Snapshot().Seconds[ModeIdle] > before
	})

	if got := s.Snapshot().Seconds[ModeIdle]; got < before {
		t.Errorf("counter went backwards across a reconnect: %v then %v", before, got)
	}
}

// TestStreamWatchdogFiresOnASilentStall is the defence against this box's known SSE
// failure mode: the connection stays open and healthy-looking while the data has
// stopped. A liveness check on the socket would see nothing wrong, so the watchdog
// tracks time since the last DATA frame — keepalive comments must not reset it.
func TestStreamWatchdogFiresOnASilentStall(t *testing.T) {
	var conns atomic.Int64
	srv := sseServer(t, func(w io.Writer, flush func(), _ *http.Request) {
		conns.Add(1)
		// One real frame, then keepalive comments forever: alive, but stalled.
		if _, err := io.WriteString(w, frameLine(100)); err != nil {
			return
		}
		flush()
		for range 500 {
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			flush()
			time.Sleep(5 * time.Millisecond)
		}
	})

	s := New(httpOpener(srv), testConfig())
	s.Start(context.Background())
	defer s.Close()

	eventually(t, "the watchdog to tear down the stalled connection and re-dial", func() bool {
		return conns.Load() >= 2 && s.Snapshot().Reconnects > 0
	})
}

// TestStreamCountersGoAbsentAfterTheGraceWindow pins decision 2 of #559: a short
// blip must not gap the graph, but a real outage must stop the metrics lying. A
// frozen counter reads as an idle CPU, which is silently wrong; absent is not.
func TestStreamCountersGoAbsentAfterTheGraceWindow(t *testing.T) {
	srv := sseServer(t, func(w io.Writer, flush func(), r *http.Request) {
		if _, err := io.WriteString(w, frameLine(100)); err != nil {
			return
		}
		flush()
		if _, err := io.WriteString(w, frameLine(100)); err != nil {
			return
		}
		flush()
		// Then hang: no more frames, connection held open. Unblocks on client
		// disconnect so httptest.Server.Close does not wait it out.
		<-r.Context().Done()
	})

	cfg := testConfig()
	cfg.StallAfter = 5 * time.Second // keep the watchdog out of the way
	s := New(httpOpener(srv), cfg)
	s.Start(context.Background())
	defer s.Close()

	eventually(t, "a first frame", func() bool { return s.Snapshot().HaveFrame })
	if !s.Snapshot().Fresh {
		t.Error("counters must publish immediately after a frame")
	}
	eventually(t, "the grace window to expire", func() bool { return !s.Snapshot().Fresh })

	snap := s.Snapshot()
	if !snap.HaveFrame {
		t.Error("HaveFrame must stay true so last-frame-age is still exportable")
	}
	if snap.LastFrameAge < cfg.GracePeriod {
		t.Errorf("LastFrameAge = %v, want at least the %v grace period", snap.LastFrameAge, cfg.GracePeriod)
	}
}

// TestStreamHealthIsExportableBeforeAnyFrame pins that a stream which has never
// connected still reports its state, rather than the collector having nothing to say.
func TestStreamHealthIsExportableBeforeAnyFrame(t *testing.T) {
	s := New(func(context.Context) (io.ReadCloser, error) {
		return nil, fmt.Errorf("firewall unreachable")
	}, testConfig())
	s.Start(context.Background())
	defer s.Close()

	snap := s.Snapshot()
	if snap.Connected || snap.HaveFrame || snap.Fresh {
		t.Errorf("a stream that never connected must report down and stale, got %+v", snap)
	}
	if len(snap.Seconds) != len(Modes) {
		t.Errorf("Seconds must always carry every mode, got %v", snap.Seconds)
	}
}

func TestStreamCloseIsIdempotentAndUnblocks(t *testing.T) {
	srv := sseServer(t, func(w io.Writer, flush func(), _ *http.Request) {
		for range 5000 {
			if _, err := io.WriteString(w, frameLine(100)); err != nil {
				return
			}
			flush()
			time.Sleep(time.Millisecond)
		}
	})
	s := New(httpOpener(srv), testConfig())
	s.Start(context.Background())
	eventually(t, "a frame", func() bool { return s.Snapshot().HaveFrame })

	done := make(chan struct{})
	go func() { s.Close(); s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return")
	}
}

func TestConfigDefaults(t *testing.T) {
	got := New(nil, Config{}).cfg
	for _, tc := range []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"StallAfter", got.StallAfter, defaultStallAfter},
		{"GracePeriod", got.GracePeriod, DefaultGracePeriod},
		{"MaxFrameGap", got.MaxFrameGap, defaultMaxFrameGap},
		{"MinBackoff", got.MinBackoff, defaultMinBackoff},
		{"MaxBackoff", got.MaxBackoff, defaultMaxBackoff},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

// TestReadFramesHandlesSSEFraming covers the wire-format details: the `data:` prefix
// with and without a space, comment lines, multi-line data payloads (per the SSE
// spec, even though cpu.py only ever emits one line), and a frame dispatched only on
// the blank line that terminates it.
func TestReadFramesHandlesSSEFraming(t *testing.T) {
	body := strings.Join([]string{
		": a comment\n",
		"event: message\n",
		"data: {\"user\":10,\"nice\":0,\"sys\":0,\"intr\":0,\"idle\":90}\n",
		"\n",
		"data:{\"user\":20,\"nice\":0,\"sys\":0,\"intr\":0,\"idle\":80}\n",
		"\n",
		"data: {\"user\":30,\n",
		"data: \"nice\":0,\"sys\":0,\"intr\":0,\"idle\":70}\n",
		"\n",
	}, "")

	var got []map[string]float64
	err := readFrames(bufio.NewReader(strings.NewReader(body)), func(pct map[string]float64) {
		got = append(got, pct)
	})
	if err != nil && err != io.EOF {
		t.Fatalf("readFrames: %v", err)
	}
	want := []float64{10, 20, 30}
	if len(got) != len(want) {
		t.Fatalf("got %d frames, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i][ModeUser] != w {
			t.Errorf("frame %d user = %v, want %v", i, got[i][ModeUser], w)
		}
	}
}
