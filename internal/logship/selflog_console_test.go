package logship

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// quietSelfLogHandler builds a quiet-console handler whose stderr copy is
// captured, together with an enqueue callback whose acceptance the test
// controls. Acceptance is the only thing quiet mode reads: the console copy
// exists precisely for the records the pipeline could not take.
func quietSelfLogHandler(t *testing.T, accept bool) (*SelfLogHandler, *bytes.Buffer, *[]Entry) {
	t.Helper()
	var stderr bytes.Buffer
	var got []Entry
	h := NewSelfLogHandler(slog.NewTextHandler(&stderr, nil), WithQuietConsole(true))
	h.Bind(func(e Entry) bool {
		got = append(got, e)
		return accept
	})
	return h, &stderr, &got
}

func TestSelfLogHandlerQuietConsoleSuppressesAcceptedRecords(t *testing.T) {
	h, stderr, got := quietSelfLogHandler(t, true)

	slog.New(h).Info("polling gateways", "collector", "gateways")

	if len(*got) != 1 {
		t.Fatalf("pipeline received %d self-log entries, want 1", len(*got))
	}
	if stderr.Len() != 0 {
		t.Fatalf("quiet console wrote %q to stderr for an accepted record, want nothing", stderr.String())
	}
}

func TestSelfLogHandlerQuietConsoleKeepsRejectedRecords(t *testing.T) {
	h, stderr, got := quietSelfLogHandler(t, false)

	slog.New(h).Error("collector failed", "collector", "gateways")

	if len(*got) != 1 {
		t.Fatalf("pipeline received %d self-log entries, want 1", len(*got))
	}
	if !strings.Contains(stderr.String(), "collector failed") {
		t.Fatalf("stderr = %q, want the record the pipeline refused", stderr.String())
	}
}

func TestSelfLogHandlerQuietConsoleKeepsRecordsEmittedBeforeBind(t *testing.T) {
	var stderr bytes.Buffer
	h := NewSelfLogHandler(slog.NewTextHandler(&stderr, nil), WithQuietConsole(true))

	slog.New(h).Info("starting opnsense2otel", "version", "v9.9.9")

	if !strings.Contains(stderr.String(), "starting opnsense2otel") {
		t.Fatalf("stderr = %q, want the pre-bind startup record", stderr.String())
	}

	var got []Entry
	h.Bind(func(e Entry) bool {
		got = append(got, e)
		return true
	})
	if len(got) != 1 {
		t.Fatalf("pipeline received %d buffered startup entries after Bind, want 1", len(got))
	}
}

func TestSelfLogHandlerQuietConsoleKeepsRecordsEmittedAfterUnbind(t *testing.T) {
	h, stderr, _ := quietSelfLogHandler(t, true)
	h.Unbind()
	stderr.Reset()

	slog.New(h).Info("stopping opnsense2otel")

	if !strings.Contains(stderr.String(), "stopping opnsense2otel") {
		t.Fatalf("stderr = %q, want the post-Unbind shutdown record", stderr.String())
	}
}

// The startup-loss diagnostic from OPN-0073 is written directly to the wrapped
// handler, so quiet mode must not silence it: it reports records the pipeline
// never saw, which is exactly what quiet mode is not allowed to hide.
func TestSelfLogHandlerQuietConsoleStillReportsPreBindOverflow(t *testing.T) {
	var stderr bytes.Buffer
	h := NewSelfLogHandler(slog.NewTextHandler(&stderr, nil), WithQuietConsole(true))
	logger := slog.New(h)

	for sequence := 0; sequence <= selfLogPendingLimit; sequence++ {
		logger.Info("startup self log", "sequence", sequence)
	}

	if !strings.Contains(stderr.String(), "self-log startup buffer overflow") {
		t.Fatalf("stderr = %q, want the bounded startup overflow diagnostic", stderr.String())
	}
}

// Unbind's drain contract (OPN-0073 AC2) is independent of the console mode,
// and quiet mode must not let a shutdown record slip past it: Handle blocks on
// the same submit path before deciding whether stderr needs the copy.
func TestSelfLogHandlerQuietConsoleUnbindWaitsForAdmittedEnqueue(t *testing.T) {
	enqueueAcquired := make(chan struct{})
	releaseEnqueue := make(chan struct{})

	h := NewSelfLogHandler(slog.NewTextHandler(io.Discard, nil), WithQuietConsole(true))
	h.Bind(func(Entry) bool {
		close(enqueueAcquired)
		<-releaseEnqueue
		return true
	})

	logged := make(chan struct{})
	go func() {
		slog.New(h).Info("self log during shutdown")
		close(logged)
	}()
	<-enqueueAcquired

	unbound := make(chan struct{})
	go func() {
		h.Unbind()
		close(unbound)
	}()
	select {
	case <-unbound:
		t.Fatal("Unbind returned before the admitted enqueue callback completed")
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseEnqueue)
	<-logged
	<-unbound
}

// WithAttrs and WithGroup clone the handler, and a clone that forgot the
// console mode would put every logger.With(...) line back on stderr - which is
// most of the exporter's logging.
func TestSelfLogHandlerQuietConsoleSurvivesWithAttrsAndWithGroup(t *testing.T) {
	h, stderr, got := quietSelfLogHandler(t, true)

	slog.New(h).With("component", "collector").WithGroup("poll").Info("tick", "collector", "gateways")

	if len(*got) != 1 {
		t.Fatalf("pipeline received %d self-log entries, want 1", len(*got))
	}
	if stderr.Len() != 0 {
		t.Fatalf("quiet console wrote %q to stderr from a derived handler, want nothing", stderr.String())
	}
}

func TestSelfLogHandlerFullConsoleKeepsAcceptedRecords(t *testing.T) {
	var stderr bytes.Buffer
	h := NewSelfLogHandler(slog.NewTextHandler(&stderr, nil))
	var got []Entry
	h.Bind(func(e Entry) bool {
		got = append(got, e)
		return true
	})

	slog.New(h).Info("polling gateways", "collector", "gateways")

	if len(got) != 1 {
		t.Fatalf("pipeline received %d self-log entries, want 1", len(got))
	}
	if !strings.Contains(stderr.String(), "polling gateways") {
		t.Fatalf("stderr = %q, want the record: the default console mode tees", stderr.String())
	}
}

// The quiet decision is per record, taken from the pipeline's own answer, so a
// mid-run change of acceptance (a full queue, then a drained one) moves the
// console copy with it rather than latching either way.
func TestSelfLogHandlerQuietConsoleFollowsPerRecordAcceptance(t *testing.T) {
	var stderr bytes.Buffer
	var mu sync.Mutex
	accept := true

	h := NewSelfLogHandler(slog.NewTextHandler(&stderr, nil), WithQuietConsole(true))
	h.Bind(func(Entry) bool {
		mu.Lock()
		defer mu.Unlock()
		return accept
	})
	logger := slog.New(h)

	logger.Info("accepted record")
	mu.Lock()
	accept = false
	mu.Unlock()
	logger.Info("overflowed record")

	out := stderr.String()
	if strings.Contains(out, "accepted record") {
		t.Errorf("stderr = %q, want no copy of the accepted record", out)
	}
	if !strings.Contains(out, "overflowed record") {
		t.Errorf("stderr = %q, want a copy of the record the queue refused", out)
	}
}
