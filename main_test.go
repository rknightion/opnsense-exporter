package main

import (
	"errors"
	"io"
	"log/slog"
	"testing"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

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
