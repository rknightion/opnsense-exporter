package logship

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/internal/options"
)

type selfLogHandlerSink struct {
	mu      sync.Mutex
	entries []Entry
	err     error
	tries   int
}

func (s *selfLogHandlerSink) Emit(_ context.Context, batch []Entry) SinkResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tries++
	if s.err != nil {
		return retryResult(batch, s.err)
	}
	s.entries = append(s.entries, batch...)
	return ackedResult(batch)
}

func (s *selfLogHandlerSink) Shutdown(context.Context) error { return nil }

func (s *selfLogHandlerSink) got() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Entry(nil), s.entries...)
}

func (s *selfLogHandlerSink) attempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tries
}

func TestSelfLogHandlerConvertsRecordForTheOTLPPipeline(t *testing.T) {
	var stderr slog.Handler = slog.NewTextHandler(io.Discard, nil)
	h := NewSelfLogHandler(stderr)
	var got []Entry
	h.Bind(func(e Entry) bool {
		got = append(got, e)
		return true
	})

	log := slog.New(h).With("component", "test")
	log.Warn("sink is unhealthy", "attempt", 2, "when", time.Unix(42, 123).UTC())

	if len(got) != 1 {
		t.Fatalf("got %d self-log entries, want 1", len(got))
	}
	e := got[0]
	if e.Source != SelfLogSource {
		t.Fatalf("source = %q, want %q", e.Source, SelfLogSource)
	}
	if e.Record.Timestamp.IsZero() {
		t.Fatal("self-log timestamp is zero")
	}
	if e.Record.Body != "sink is unhealthy" {
		t.Fatalf("body = %q, want sink is unhealthy", e.Record.Body)
	}
	if e.Record.Severity != SeverityWarn {
		t.Fatalf("severity = %v, want warn", e.Record.Severity)
	}
	if got := e.Record.Attributes[AttrSubsystem]; got != SelfLogSubsystem {
		t.Fatalf("subsystem = %q, want %q", got, SelfLogSubsystem)
	}
	if got := e.Record.Attributes["component"]; got != "test" {
		t.Fatalf("component = %q, want test", got)
	}
	if got := e.Record.Attributes["attempt"]; got != "2" {
		t.Fatalf("attempt = %q, want 2", got)
	}
	if got := e.Record.Attributes["when"]; got == "" {
		t.Fatal("time attribute was lost")
	}
}

func TestSelfLogHandlerRedactsCredentialBearingURLsBeforeBuffering(t *testing.T) {
	const (
		userinfoSecret = "synthetic-userinfo-credential-not-real"
		tokenSecret    = "synthetic-query-token-not-real"
		apiKeySecret   = "synthetic-query-api-key-not-real"
		passwordSecret = "synthetic-query-password-not-real"
	)
	endpoint := "https://operator:" + userinfoSecret +
		"@telemetry.example.test/v1/logs?format=proto&access_token=" + tokenSecret +
		"&api-key=" + apiKeySecret + "&password=" + passwordSecret + "&timeout=5s"

	h := NewSelfLogHandler(slog.NewTextHandler(io.Discard, nil))
	slog.New(h).Info("configuring OTLP logs", "endpoint", endpoint, "retry_after", "3s")

	h.state.mu.Lock()
	if len(h.state.pending) != 1 {
		h.state.mu.Unlock()
		t.Fatalf("pending self-log records = %d, want 1", len(h.state.pending))
	}
	pendingAttrs := h.state.pending[0].Attributes
	h.state.mu.Unlock()
	assertSanitizedSelfLogEndpoint(t, pendingAttrs, userinfoSecret, tokenSecret, apiKeySecret, passwordSecret)

	exp := &fakeExporter{}
	sink := newTestSink(exp)
	h.Bind(func(e Entry) bool {
		res := sink.Emit(context.Background(), []Entry{e})
		return len(res.Acked) == 1
	})
	records := exp.exported()
	if len(records) != 1 {
		t.Fatalf("exported %d records, want 1", len(records))
	}
	assertSanitizedSelfLogEndpoint(t, recordAttrs(records[0]), userinfoSecret, tokenSecret, apiKeySecret, passwordSecret)
}

func TestSelfLogHandlerReportsPreBindOverflowOnce(t *testing.T) {
	var stderr bytes.Buffer
	h := NewSelfLogHandler(slog.NewTextHandler(&stderr, nil))
	logger := slog.New(h)

	for sequence := 0; sequence <= selfLogPendingLimit; sequence++ {
		logger.Info("startup self log", "sequence", sequence)
	}

	h.state.mu.Lock()
	pending := append([]Record(nil), h.state.pending...)
	h.state.mu.Unlock()
	if len(pending) != selfLogPendingLimit {
		t.Fatalf("pending self-log records = %d, want %d", len(pending), selfLogPendingLimit)
	}
	if got := pending[0].Attributes["sequence"]; got != "1" {
		t.Fatalf("first retained self-log sequence = %q, want 1", got)
	}
	if got := pending[len(pending)-1].Attributes["sequence"]; got != "256" {
		t.Fatalf("last retained self-log sequence = %q, want 256", got)
	}
	if got := strings.Count(stderr.String(), "self-log startup buffer overflow"); got != 1 {
		t.Fatalf("startup overflow diagnostics = %d, want 1", got)
	}
}

func assertSanitizedSelfLogEndpoint(t *testing.T, attrs map[string]string, secrets ...string) {
	t.Helper()
	endpoint := attrs["endpoint"]
	for _, secret := range secrets {
		for _, value := range attrs {
			if strings.Contains(value, secret) {
				t.Error("self-log attributes retained a credential")
			}
		}
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		t.Fatalf("sanitized self-log endpoint is not a URL: %v", err)
	}
	if parsed.Scheme != "https" || parsed.Host != "telemetry.example.test" || parsed.Path != "/v1/logs" {
		t.Error("sanitized self-log endpoint lost scheme, host, or path context")
	}
	if parsed.User == nil {
		t.Error("sanitized self-log endpoint lost the redacted userinfo marker")
	} else if parsed.User.Username() != "[REDACTED]" {
		t.Error("self-log endpoint userinfo was not redacted")
	} else if _, hasPassword := parsed.User.Password(); hasPassword {
		t.Error("sanitized self-log endpoint retained a userinfo password component")
	}
	query := parsed.Query()
	if query.Get("access_token") != "[REDACTED]" || query.Get("api-key") != "[REDACTED]" ||
		query.Get("password") != "[REDACTED]" {
		t.Error("self-log endpoint retained a sensitive query value")
	}
	if query.Get("format") != "proto" || query.Get("timeout") != "5s" {
		t.Error("sanitized self-log endpoint lost safe query context")
	}
	if attrs["retry_after"] != "3s" {
		t.Error("self-log sanitization changed a non-URL diagnostic attribute")
	}
}

func TestSelfLogHandlerPreservesGroupsAndRecordAttributePrecedence(t *testing.T) {
	h := NewSelfLogHandler(slog.NewTextHandler(io.Discard, nil))
	var got []Entry
	h.Bind(func(e Entry) bool {
		got = append(got, e)
		return true
	})

	slog.New(h).
		With("component", "bound", "top", "bound").
		WithGroup("request").
		With("bound", "group-bound").
		Info("handled", "component", "record", "top", "record", "id", 42)

	if len(got) != 1 {
		t.Fatalf("got %d self-log entries, want 1", len(got))
	}
	attrs := got[0].Record.Attributes
	for key, want := range map[string]string{
		"component":         "bound",
		"top":               "bound",
		"request.bound":     "group-bound",
		"request.component": "record",
		"request.top":       "record",
		"request.id":        "42",
	} {
		if got := attrs[key]; got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestSelfLogHandlerUsesTheExistingOTLPSinkResource(t *testing.T) {
	exp := &fakeExporter{}
	sink := newTestSink(exp)
	h := NewSelfLogHandler(slog.NewTextHandler(io.Discard, nil))
	h.Bind(func(e Entry) bool {
		res := sink.Emit(context.Background(), []Entry{e})
		return len(res.Acked) == 1
	})

	slog.New(h).Error("collector failed", "endpoint", "healthCheck")
	records := exp.exported()
	if len(records) != 1 {
		t.Fatalf("exported %d records, want 1", len(records))
	}
	attrs := resourceAttrs(records[0])
	for key, want := range map[string]string{
		"service.name":        "opnsense2otel",
		"service.version":     "v1.2.3",
		"service.instance.id": "opnsense",
		attrSource:            SelfLogSource,
		AttrSubsystem:         SelfLogSubsystem,
	} {
		if got := attrs[key]; got != want {
			t.Errorf("resource %s = %q, want %q", key, got, want)
		}
	}
}

// TestSelfLogHandlerDeliversConcurrentRecords pins the property a shared
// re-entrancy flag used to break: the exporter logs from many goroutines at
// once (65 collector pollers plus the push receivers), and a record emitted
// while another goroutine is inside the enqueue callback must still be
// delivered. A process-wide "forwarding" boolean cannot tell re-entry from
// concurrency, so it dropped those records silently and without accounting.
//
// The callback parks every submission at a barrier until all of them have
// arrived, which makes the overlap deterministic rather than a race the test
// might lose: under the old shared guard only the first submission reached the
// callback at all, so the barrier times out and the count assertion fails.
func TestSelfLogHandlerDeliversConcurrentRecords(t *testing.T) {
	const goroutines = 8

	var mu sync.Mutex
	var arrived int
	var delivered int
	barrier := make(chan struct{})

	h := NewSelfLogHandler(slog.NewTextHandler(io.Discard, nil))
	h.Bind(func(Entry) bool {
		mu.Lock()
		arrived++
		if arrived == goroutines {
			close(barrier)
		}
		mu.Unlock()

		select {
		case <-barrier:
		case <-time.After(2 * time.Second):
		}

		mu.Lock()
		delivered++
		mu.Unlock()
		return true
	})
	logger := slog.New(h)

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			logger.Error("concurrent self log", "goroutine", id)
		}(i)
	}
	wg.Wait()

	mu.Lock()
	got := delivered
	mu.Unlock()
	if got != goroutines {
		t.Fatalf("self-log callback received %d records, want %d", got, goroutines)
	}
}

func TestSelfLogHandlerUnbindWaitsForAdmittedEnqueue(t *testing.T) {
	enqueueAcquired := make(chan struct{})
	releaseEnqueue := make(chan struct{})
	queueClosed := make(chan struct{})

	h := NewSelfLogHandler(slog.NewTextHandler(io.Discard, nil))
	h.Bind(func(Entry) bool {
		close(enqueueAcquired)
		<-releaseEnqueue
		select {
		case <-queueClosed:
			t.Error("queue closed before admitted self-log enqueue returned")
		default:
		}
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
	close(queueClosed)
}

func TestSelfLogDiagnosticLoggerCannotReenterSink(t *testing.T) {
	var calls int
	h := NewSelfLogHandler(slog.NewTextHandler(io.Discard, nil))
	h.Bind(func(Entry) bool {
		calls++
		return true
	})

	h.DiagnosticLogger().Error("sink export failed", "err", errors.New("endpoint down"))

	if calls != 0 {
		t.Fatalf("diagnostic logger entered self-log callback %d times, want 0", calls)
	}
}

func TestStartRejectsSelfLogsWithStdout(t *testing.T) {
	withRegistry(t)
	cfg := &options.LogsConfig{
		Sink:         "stdout",
		PollInterval: 5 * time.Second,
		BufferSize:   1,
		BatchMax:     1,
	}
	_, err := Start(
		context.Background(), cfg, nil, Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))},
		"v", "instance", prometheus.NewRegistry(), NewSelfLogHandler(slog.NewTextHandler(io.Discard, nil)),
	)
	if err == nil {
		t.Fatal("Start accepted self-log forwarding with stdout sink")
	}
	if !strings.Contains(err.Error(), "--logs.sink=otlp") {
		t.Fatalf("Start error = %v, want sink dependency", err)
	}
}
