package main

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/options"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestEveryDisableSwitchWiredInMain guards the fourth "Adding a New Collector" step that
// no other test covered (#153): each CollectorsDisableSwitch struct field must be
// referenced as `collectorsSwitches.<Field>` in main.go, otherwise the documented
// --exporter.disable-*/--exporter.enable-* flag is generated but silently does nothing at
// runtime (the collector self-registers via init() and would never be gated). It parses
// main.go's AST for the references and diffs them against the reflected struct fields in
// both directions — a field with no reference (unwired flag), and a reference to a field
// that no longer exists (stale block left after a rename/removal).
func TestEveryDisableSwitchWiredInMain(t *testing.T) {
	structFields := map[string]bool{}
	st := reflect.TypeOf(options.CollectorsDisableSwitch{})
	for i := 0; i < st.NumField(); i++ {
		structFields[st.Field(i).Name] = true
	}
	if len(structFields) == 0 {
		t.Fatal("CollectorsDisableSwitch has no fields — reflection failed")
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	referenced := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); ok && x.Name == "collectorsSwitches" {
			referenced[sel.Sel.Name] = true
		}
		return true
	})
	if len(referenced) == 0 {
		t.Fatal("no collectorsSwitches.<Field> references found in main.go — variable renamed?")
	}

	// Forward drift: a struct field (documented flag) with no wiring in main.go is a no-op.
	for field := range structFields {
		if !referenced[field] {
			t.Errorf("CollectorsDisableSwitch.%s is not wired in main.go: its --exporter.* flag would be documented but do nothing", field)
		}
	}
	// Reverse drift: main.go references a field no longer on the struct (stale wiring).
	for field := range referenced {
		if !structFields[field] {
			t.Errorf("main.go references collectorsSwitches.%s, which is not a CollectorsDisableSwitch field (stale wiring)", field)
		}
	}
}

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
	var pollStopped, logsStopped, otlpStopped, profStopped bool
	gracefulShutdown(ts.Config, syscall.SIGINT,
		func() { pollStopped = true },
		func() { logsStopped = true },
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
	if !pollStopped || !logsStopped || !otlpStopped || !profStopped {
		t.Errorf("stop hooks not run: poll=%v logs=%v otlp=%v prof=%v", pollStopped, logsStopped, otlpStopped, profStopped)
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
