package main

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestGracefulShutdownDrainsInFlightRequest covers #161: a slow request in flight when
// the signal arrives must complete (not be severed), telemetry stop hooks must run, and
// the log must reflect the actual signal received (SIGINT -> "interrupt", not a
// hardcoded "SIGTERM").
func TestGracefulShutdownDrainsInFlightRequest(t *testing.T) {
	started := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte("OK"))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	type result struct {
		body   string
		status int
		err    error
	}
	resCh := make(chan result, 1)
	go func() {
		resp, err := http.Get(ts.URL + "/metrics")
		if err != nil {
			resCh <- result{err: err}
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		resCh <- result{body: string(b), status: resp.StatusCode}
	}()

	<-started // request is now in flight inside the handler

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var otlpStopped, profStopped bool
	gracefulShutdown(ts.Config, syscall.SIGINT,
		func() { otlpStopped = true },
		func() { profStopped = true },
		logger)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("in-flight request was severed: %v", res.err)
	}
	if res.status != http.StatusOK || res.body != "OK" {
		t.Errorf("in-flight request did not complete cleanly: status=%d body=%q", res.status, res.body)
	}
	if !otlpStopped || !profStopped {
		t.Errorf("stop hooks not run: otlp=%v prof=%v", otlpStopped, profStopped)
	}
	// SIGINT stringifies to "interrupt"; assert the actual signal, not a hardcoded one.
	if !strings.Contains(buf.String(), "interrupt") {
		t.Errorf("log did not reflect the actual signal (SIGINT); log=%q", buf.String())
	}
}

// TestResolveInstanceLabel pins the deterministic instance-label resolution
// (#75): the value must never depend on startup timing or the box's momentary
// reachability.
func TestResolveInstanceLabel(t *testing.T) {
	log := quietLogger()

	t.Run("explicit label always wins", func(t *testing.T) {
		got, err := resolveInstanceLabel("fw-01", "10.0.0.1", true, func() (string, error) {
			t.Fatal("lookup must not be called when an explicit label is set")
			return "", nil
		}, log)
		if err != nil || got != "fw-01" {
			t.Fatalf("got (%q, %v), want (\"fw-01\", nil)", got, err)
		}
	})

	t.Run("default uses address without calling the API (deterministic)", func(t *testing.T) {
		calls := 0
		got, err := resolveInstanceLabel("", "10.0.0.1", false, func() (string, error) {
			calls++
			return "should-not-be-used", nil
		}, log)
		if err != nil || got != "10.0.0.1" {
			t.Fatalf("got (%q, %v), want (\"10.0.0.1\", nil)", got, err)
		}
		if calls != 0 {
			t.Errorf("lookup was called %d times; the address default must not depend on the API", calls)
		}
	})

	t.Run("use-hostname success", func(t *testing.T) {
		got, err := resolveInstanceLabel("", "10.0.0.1", true, func() (string, error) {
			return "opnsense.example.com", nil
		}, log)
		if err != nil || got != "opnsense.example.com" {
			t.Fatalf("got (%q, %v), want (\"opnsense.example.com\", nil)", got, err)
		}
	})

	t.Run("use-hostname lookup failure fails startup, never falls back to address", func(t *testing.T) {
		got, err := resolveInstanceLabel("", "10.0.0.1", true, func() (string, error) {
			return "", errors.New("unreachable")
		}, log)
		if err == nil {
			t.Fatalf("expected an error, got label %q (must not silently fall back to the address)", got)
		}
	})

	t.Run("use-hostname empty hostname fails startup", func(t *testing.T) {
		_, err := resolveInstanceLabel("", "10.0.0.1", true, func() (string, error) {
			return "", nil
		}, log)
		if err == nil {
			t.Fatal("expected an error for an empty hostname")
		}
	})

	t.Run("deterministic across repeated calls regardless of a flaky/slow API", func(t *testing.T) {
		// With the default (address) path, a lookup that would return different
		// values on each call must not affect the result.
		seq := []string{"a", "b", "c"}
		i := 0
		lookup := func() (string, error) { v := seq[i%len(seq)]; i++; return v, nil }
		first, _ := resolveInstanceLabel("", "10.0.0.1", false, lookup, log)
		for range 5 {
			got, _ := resolveInstanceLabel("", "10.0.0.1", false, lookup, log)
			if got != first {
				t.Fatalf("non-deterministic label: %q vs %q", got, first)
			}
		}
	})
}
