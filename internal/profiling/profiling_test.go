package profiling

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/grafana/pyroscope-go"
)

// oneMiB matches maxUploadResponseBytes; spelled out locally so the test asserts
// against a literal, not a tautological reference to the constant it's checking.
const oneMiB = 1 << 20

// heapSink keeps a live allocation so the heap delta profile has data to flush.
var heapSink [][]byte

// TestStop_FlushesFinalWindow reproduces #121: with UploadRate high enough that no
// periodic upload fires during the test, the SDK's Profiler.Stop() alone uploads only
// the CPU profile and silently drops the heap/alloc window. profiling.Stop must call
// Flush(true) first, so the in-progress window is uploaded before the process exits.
func TestStop_FlushesFinalWindow(t *testing.T) {
	var uploads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		uploads.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	profiler, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: "opnsense-exporter.test",
		ServerAddress:   srv.URL,
		UploadRate:      time.Hour, // no periodic upload within the test window
		ProfileTypes:    profileTypes(false),
		Logger:          nil,
	})
	if err != nil {
		t.Fatalf("pyroscope.Start: %v", err)
	}

	// Allocate so the heap delta window is non-empty at flush time.
	for range 16 {
		heapSink = append(heapSink, make([]byte, 1<<20))
	}

	before := uploads.Load()
	Stop(profiler, discardLogger())
	if got := uploads.Load(); got <= before {
		t.Fatalf("expected the final flush to upload the in-progress window, got %d uploads (before=%d)", got, before)
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// leakType returns the goroutine-leak profile types present in a default build —
// one when the binary was built with GOEXPERIMENT=goroutineleakprofile, none
// otherwise. The type tests key their expected counts off this so they pass in
// both CI (plain build) and release builds (with the experiment).
func leakType() []pyroscope.ProfileType {
	if GoroutineLeakAvailable() {
		return []pyroscope.ProfileType{pyroscope.ProfileGoroutineLeak}
	}
	return nil
}

func TestProfileTypes_DefaultSet(t *testing.T) {
	got := profileTypes(false)
	// All standard types are on by default: cpu + alloc/inuse + goroutines +
	// mutex/block (10), plus goroutine-leak when the experiment is built in (#268).
	want := []pyroscope.ProfileType{
		pyroscope.ProfileCPU,
		pyroscope.ProfileAllocObjects,
		pyroscope.ProfileAllocSpace,
		pyroscope.ProfileInuseObjects,
		pyroscope.ProfileInuseSpace,
		pyroscope.ProfileGoroutines,
		pyroscope.ProfileMutexCount,
		pyroscope.ProfileMutexDuration,
		pyroscope.ProfileBlockCount,
		pyroscope.ProfileBlockDuration,
	}
	want = append(want, leakType()...)
	if len(got) != len(want) {
		t.Fatalf("expected %d default profile types, got %d: %v", len(want), len(got), got)
	}
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("default set missing %q", w)
		}
	}
}

func TestProfileTypes_DisableMutexBlockDropsContentionOnly(t *testing.T) {
	got := profileTypes(true)
	// Disabling drops the four contention profiles; everything else stays on.
	want := []pyroscope.ProfileType{
		pyroscope.ProfileCPU,
		pyroscope.ProfileAllocObjects,
		pyroscope.ProfileAllocSpace,
		pyroscope.ProfileInuseObjects,
		pyroscope.ProfileInuseSpace,
		pyroscope.ProfileGoroutines,
	}
	want = append(want, leakType()...)
	if len(got) != len(want) {
		t.Fatalf("expected %d profile types with mutex/block disabled, got %d: %v", len(want), len(got), got)
	}
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("set missing %q", w)
		}
	}
	for _, notWant := range []pyroscope.ProfileType{
		pyroscope.ProfileMutexCount,
		pyroscope.ProfileMutexDuration,
		pyroscope.ProfileBlockCount,
		pyroscope.ProfileBlockDuration,
	} {
		if slices.Contains(got, notWant) {
			t.Errorf("disabled set unexpectedly contains contention profile %q", notWant)
		}
	}
}

func TestLoggerAdapter_RoutesLevels(t *testing.T) {
	var buf bytes.Buffer
	base := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	a := loggerAdapter{logger: base}

	a.Infof("info %d", 1)
	a.Debugf("debug %s", "x")
	a.Errorf("error %v", true)

	out := buf.String()
	for _, want := range []string{
		`level=INFO msg="info 1"`,
		`level=DEBUG msg="debug x"`,
		`level=ERROR msg="error true"`,
	} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("expected log output to contain %q, got:\n%s", want, out)
		}
	}
}

// TestLimitedBodyHTTPClient_CapsResponseBody reproduces #309: a backend that returns
// a far-oversized response body must not have all of it read into memory by callers
// of limitedBodyHTTPClient.Do — the returned body must stop yielding bytes at
// maxUploadResponseBytes, well short of what the server actually wrote.
func TestLimitedBodyHTTPClient_CapsResponseBody(t *testing.T) {
	const oversized = 10 * oneMiB // far more than the cap
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("a"), oversized))
	}))
	defer srv.Close()

	client := newLimitedBodyHTTPClient(5 * time.Second)
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil) //nolint:noctx
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if closeErr := resp.Body.Close(); closeErr != nil {
		t.Errorf("Close: %v", closeErr)
	}

	if len(got) != maxUploadResponseBytes {
		t.Fatalf("expected exactly the %d-byte cap, got %d bytes", maxUploadResponseBytes, len(got))
	}
	if maxUploadResponseBytes != oneMiB {
		t.Fatalf("sanity check: maxUploadResponseBytes = %d, expected %d (1 MiB)", maxUploadResponseBytes, oneMiB)
	}
}

// TestStop_BoundedByTimeoutOnSlowServer reproduces #310: previously Stop() raced
// Flush(true) against stopFlushTimeout but then called profiler.Stop() unconditionally
// afterward — including on the timeout branch — and the vendored Profiler.Stop() does
// an uncancellable wg.Wait() on any goroutine already blocked inside an HTTP
// round-trip. So the real bound on Stop() was the HTTP client's timeout (tens of
// seconds), not the advertised stopFlushTimeout. With Flush+Stop moved into the same
// abandonable goroutine, Stop() must return close to stopFlushTimeout even against a
// server that never responds.
func TestStop_BoundedByTimeoutOnSlowServer(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // never respond until the test releases it during cleanup
	}))
	defer srv.Close()
	defer close(block)

	orig := stopFlushTimeout
	stopFlushTimeout = 200 * time.Millisecond
	t.Cleanup(func() { stopFlushTimeout = orig })

	profiler, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: "opnsense-exporter.test",
		ServerAddress:   srv.URL,
		UploadRate:      time.Hour, // no periodic upload within the test window
		ProfileTypes:    profileTypes(false),
		Logger:          nil,
	})
	if err != nil {
		t.Fatalf("pyroscope.Start: %v", err)
	}

	start := time.Now()
	Stop(profiler, discardLogger())
	elapsed := time.Since(start)

	// Generous epsilon: this only needs to prove Stop() did NOT wait for the ~30s
	// HTTP client timeout or block indefinitely, not that it hit stopFlushTimeout
	// to the millisecond.
	const epsilon = 2 * time.Second
	if elapsed > stopFlushTimeout+epsilon {
		t.Fatalf("Stop took %s, expected roughly bounded by stopFlushTimeout=%s (+%s epsilon)",
			elapsed, stopFlushTimeout, epsilon)
	}
}
