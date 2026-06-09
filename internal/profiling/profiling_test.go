package profiling

import (
	"bytes"
	"log/slog"
	"slices"
	"testing"

	"github.com/grafana/pyroscope-go"
)

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
