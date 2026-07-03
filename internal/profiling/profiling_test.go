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

func TestProfileTypes_DefaultSet(t *testing.T) {
	got := profileTypes(false)
	if len(got) != 5 {
		t.Fatalf("expected 5 default profile types, got %d: %v", len(got), got)
	}
	for _, want := range []pyroscope.ProfileType{
		pyroscope.ProfileCPU,
		pyroscope.ProfileAllocObjects,
		pyroscope.ProfileAllocSpace,
		pyroscope.ProfileInuseObjects,
		pyroscope.ProfileInuseSpace,
	} {
		if !slices.Contains(got, want) {
			t.Errorf("default set missing %q", want)
		}
	}
}

func TestProfileTypes_MutexBlockSet(t *testing.T) {
	got := profileTypes(true)
	if len(got) != 10 {
		t.Fatalf("expected 10 profile types with mutex/block, got %d: %v", len(got), got)
	}
	// The mutex/block set must extend, not replace, the default set.
	for _, want := range []pyroscope.ProfileType{
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
	} {
		if !slices.Contains(got, want) {
			t.Errorf("mutex/block set missing %q", want)
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
