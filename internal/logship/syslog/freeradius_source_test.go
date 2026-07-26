package syslog

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/capture"
	"github.com/rknightion/opnsense-exporter/internal/options"
)

// TestSourceFreeRADIUSMalformedEnvelopesShipOneSafeGenericShape guards the
// source-boundary rule for #407. Recognisable radiusd headers must never enter
// the generic malformed-envelope path with their original bytes: a Radius
// password is authentication material, not diagnostic data.
func TestSourceFreeRADIUSMalformedEnvelopesShipOneSafeGenericShape(t *testing.T) {
	reg := prometheus.NewRegistry()
	dir := t.TempDir()
	logOutput := &bytes.Buffer{}
	cap, err := capture.New(capture.Config{Dir: dir, MaxBytes: 8 << 20}, reg, nil)
	if err != nil {
		t.Fatal(err)
	}

	s := newSource(&options.SyslogConfig{DebugCapture: true}, logship.Deps{
		Registerer:   reg,
		DebugCapture: cap,
		Logger:       slog.New(slog.NewTextHandler(logOutput, nil)),
	})
	var emitted []logship.Record
	s.emit = func(record logship.Record) { emitted = append(emitted, record) }

	canaries := []string{"radius-secret-alpha", "radius-secret-bravo"}
	for _, line := range [][]byte{
		[]byte(`<134>1 2026-07-26T12:34:56Z opnsense radiusd 123 ID47 [bad password="radius-secret-alpha"`),
		[]byte(`<134>Jax 26 12:34:56 opnsense radiusd[123]: password=radius-secret-bravo`),
	} {
		s.handle(line, netip.MustParseAddr("192.0.2.1"))
	}

	if len(emitted) != 2 {
		t.Fatalf("emitted records = %d, want 2", len(emitted))
	}
	if emitted[0].Body != emitted[1].Body || !reflect.DeepEqual(emitted[0].Attributes, emitted[1].Attributes) {
		t.Fatalf("malformed radiusd lines produced different generic frames: first=%+v second=%+v", emitted[0], emitted[1])
	}
	for _, record := range emitted {
		assertSafeFreeRADIUSRecord(t, record, canaries...)
	}

	samples := sourceParseErrorSamples(t, reg)
	if len(samples) != 1 || samples[0].value != 2 || !sameLabels(samples[0].labels, map[string]string{"source": sourceName, "stage": "envelope"}) {
		t.Fatalf("envelope parse-error samples = %+v, want one syslog/envelope sample with value 2", samples)
	}

	if err := cap.Close(); err != nil {
		t.Fatal(err)
	}
	captured := readSyslogCaptures(t, dir)
	if len(captured) != 1 {
		t.Fatalf("captured entries = %d, want 1 safe shape: %+v", len(captured), captured)
	}
	assertFreeRADIUSCaptureSafe(t, captured, canaries...)
	assertFreeRADIUSStringsSafe(t, []string{logOutput.String()}, canaries...)
}

// TestSourceFreeRADIUSUnknownVariantsAreSanitisedBeforeDispatchAndCapture
// protects every later source stage from an unsupported-but-parseable radiusd
// message. A processor must receive the same safe frame that generic fallback
// and debug capture receive; passwords that differ only alphabetically must not
// mint distinct capture shapes.
func TestSourceFreeRADIUSUnknownVariantsAreSanitisedBeforeDispatchAndCapture(t *testing.T) {
	dir := t.TempDir()
	cap, err := capture.New(capture.Config{Dir: dir, MaxBytes: 8 << 20}, prometheus.NewRegistry(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := newCaptureSource(t, cap)
	var processorEnvelopes []Envelope
	s.proc = fakeProc{
		handles: func(program string) bool { return program == "radiusd" },
		process: func(env Envelope, _ netip.Addr, _ []int, _ func(logship.Record)) bool {
			processorEnvelopes = append(processorEnvelopes, env)
			return false // generic fallback is the observable safe output in this test.
		},
	}
	var emitted []logship.Record
	s.emit = func(record logship.Record) { emitted = append(emitted, record) }

	canaries := []string{"radius-password-alpha", "radius-password-bravo"}
	for _, line := range [][]byte{
		[]byte(`<134>1 2026-07-26T12:34:56Z opnsense radiusd 123 ID47 - Access-Accept password=radius-password-alpha`),
		[]byte(`<134>1 2026-07-26T12:34:56Z opnsense radiusd 123 ID47 - Access-Accept password=radius-password-bravo`),
	} {
		s.handle(line, netip.MustParseAddr("192.0.2.1"))
	}

	if len(processorEnvelopes) != 2 {
		t.Fatalf("processor received %d envelopes, want 2", len(processorEnvelopes))
	}
	if processorEnvelopes[0].Message != processorEnvelopes[1].Message {
		t.Fatalf("processor received different radiusd messages: first=%q second=%q", processorEnvelopes[0].Message, processorEnvelopes[1].Message)
	}
	for _, env := range processorEnvelopes {
		assertFreeRADIUSStringsSafe(t, []string{env.Program, env.Message}, canaries...)
	}
	if len(emitted) != 2 {
		t.Fatalf("emitted records = %d, want 2", len(emitted))
	}
	if emitted[0].Body != emitted[1].Body || !reflect.DeepEqual(emitted[0].Attributes, emitted[1].Attributes) {
		t.Fatalf("unknown radiusd variants produced different generic frames: first=%+v second=%+v", emitted[0], emitted[1])
	}
	for _, record := range emitted {
		assertSafeFreeRADIUSRecord(t, record, canaries...)
	}

	if err := cap.Close(); err != nil {
		t.Fatal(err)
	}
	captured := readSyslogCaptures(t, dir)
	if len(captured) != 1 {
		t.Fatalf("captured entries = %d, want 1 safe shape: %+v", len(captured), captured)
	}
	assertFreeRADIUSCaptureSafe(t, captured, canaries...)
}

func assertSafeFreeRADIUSRecord(t *testing.T, record logship.Record, canaries ...string) {
	t.Helper()
	if record.Attributes["program"] != "radiusd" {
		t.Fatalf("safe generic record program = %q, want radiusd", record.Attributes["program"])
	}
	assertFreeRADIUSStringsSafe(t, []string{record.Body, fmt.Sprint(record.Attributes)}, canaries...)
}

func assertFreeRADIUSCaptureSafe(t *testing.T, captured []map[string]any, canaries ...string) {
	t.Helper()
	for _, entry := range captured {
		assertFreeRADIUSStringsSafe(t, []string{fmt.Sprint(entry)}, canaries...)
	}
}

func assertFreeRADIUSStringsSafe(t *testing.T, values []string, canaries ...string) {
	t.Helper()
	for _, value := range values {
		for _, canary := range canaries {
			if strings.Contains(value, canary) {
				t.Fatalf("unsafe FreeRADIUS data contains canary %q: %q", canary, value)
			}
		}
	}
}
