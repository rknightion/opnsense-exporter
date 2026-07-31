package syslog

import (
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/logship"
)

func envelopeFor(program, msg string, severity int) Envelope {
	return Envelope{
		Timestamp: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC),
		Hostname:  "opnsense",
		Program:   program,
		PID:       "4242",
		Facility:  16,
		Severity:  severity,
		Message:   msg,
	}
}

func TestBuildRecord_UnknownProgramShipsGeneric(t *testing.T) {
	msg := "UPS ups@localhost on battery"
	rec := BuildRecord(envelopeFor("upsmon", msg, 4), nil, nil)

	if rec.Body != msg {
		t.Errorf("Body = %q, want the raw message %q", rec.Body, msg)
	}
	assertAttr(t, rec, "program", "upsmon")
	assertAttr(t, rec, "host", "opnsense")
	assertAttr(t, rec, "pid", "4242")
	assertAttr(t, rec, "facility", "16")
	assertAttr(t, rec, "severity", "4")
	if rec.Severity != logship.SeverityWarn {
		t.Errorf("Severity = %v, want SeverityWarn (syslog 4)", rec.Severity)
	}
	if !rec.Timestamp.Equal(envelopeFor("", "", 0).Timestamp) {
		t.Errorf("Timestamp = %v, want the envelope timestamp", rec.Timestamp)
	}
}

func TestBuildRecord_SuricataEngineLineShipsGeneric(t *testing.T) {
	msg := "[100:1:1] Suricata IDS engine started"
	rec := BuildRecord(envelopeFor("suricata", msg, 6), nil, nil)
	if rec.Body != msg {
		t.Errorf("Body = %q, want raw %q", rec.Body, msg)
	}
	assertAttr(t, rec, "program", "suricata")
	if rec.Severity != logship.SeverityInfo {
		t.Errorf("Severity = %v, want SeverityInfo", rec.Severity)
	}
}

// The v1 decision (ship EVE as generic to avoid double-shipping against the ids poll
// lane) was REVERSED by #253: the receiver now parses EVE, and running both paths at
// once is refused at startup instead — see options.LogsSyslog. Parsing is covered in
// suricata_test.go; what this guards is the OTHER half of the discrimination, which
// is easy to break: the engine's plain-text log arrives under the SAME program name
// and must never be mistaken for an alert.
func TestBuildRecord_SuricataEngineTextIsNotAnAlert(t *testing.T) {
	const engine = `[207442] <Warning> -- flowbit 'ET.JS.Obfus.Func' is checked but not set.`

	rec := BuildRecord(envelopeFor("suricata", engine, 4), nil, nil)

	if rec.Body != engine {
		t.Errorf("Body = %q, want the engine line verbatim", rec.Body)
	}
	assertAttr(t, rec, "program", "suricata")
	for _, k := range []string{"signature", "alert_sid", "alert_action", "event_type"} {
		if v, ok := rec.Attributes[k]; ok {
			t.Errorf("engine text was parsed as an alert: attribute %q = %q", k, v)
		}
	}
}

func TestBuildRecord_FilterlogIsParsed(t *testing.T) {
	rec := BuildRecord(envelopeFor("filterlog", realIPv4TCPLine, 5), testSnapshot(t), nil)
	assertAttr(t, rec, "src.ip", "10.0.0.6")
	assertAttr(t, rec, "tcp.window", "64240")
	assertAttr(t, rec, "rule.description", "anti-lockout rule")
	if strings.Contains(rec.Body, ",") {
		t.Errorf("Body = %q, want the rendered human line, not the raw CSV", rec.Body)
	}
	assertNoAttr(t, rec, "program") // parsed records are not generic records
}

func TestBuildRecord_MalformedFilterlogDegradesToGeneric(t *testing.T) {
	msg := "not,enough,fields"
	rec := BuildRecord(envelopeFor("filterlog", msg, 5), testSnapshot(t), nil)
	if rec.Body != msg {
		t.Errorf("Body = %q, want the raw body %q preserved on fallback", rec.Body, msg)
	}
	assertAttr(t, rec, "program", "filterlog")
	assertNoAttr(t, rec, "src.ip")
	if rec.Severity != logship.SeverityInfo {
		t.Errorf("Severity = %v, want SeverityInfo (syslog 5)", rec.Severity)
	}
}

func TestBuildRecord_EmptyProgramNeverDropped(t *testing.T) {
	rec := BuildRecord(envelopeFor("", "something with no tag", 6), nil, nil)
	if rec.Body != "something with no tag" {
		t.Errorf("Body = %q, want the raw body", rec.Body)
	}
	assertNoAttr(t, rec, "program") // never an empty-string attribute
	assertAttr(t, rec, "host", "opnsense")
}

func TestSource_DelegatesToProgramProcessor(t *testing.T) {
	// Reset the package processor after the test.
	t.Cleanup(ResetProgramProcessor)

	var got string
	RegisterProgramProcessor(fakeProc{
		handles: func(p string) bool { return p == "zenarmor" },
		process: func(env Envelope, _ netip.Addr, _ []int, emit func(logship.Record)) bool {
			got = env.Program
			emit(logship.Record{Body: "delegated"})
			return true
		},
	})
	if p := registeredProgramProcessor(); p == nil || !p.Handles("zenarmor") {
		t.Fatal("processor not registered")
	}
	if got != "" {
		t.Fatal("processor ran before dispatch")
	}
}

type fakeProc struct {
	handles func(string) bool
	process func(Envelope, netip.Addr, []int, func(logship.Record)) bool
}

func (f fakeProc) Handles(p string) bool { return f.handles(p) }
func (f fakeProc) Process(e Envelope, a netip.Addr, ports []int, emit func(logship.Record)) bool {
	return f.process(e, a, ports, emit)
}
func (f fakeProc) EmittedSource() string { return "zenarmor" }

func TestSourceExtraSourceNames(t *testing.T) {
	t.Cleanup(ResetProgramProcessor)

	s := &source{}
	if got := s.ExtraSourceNames(); got != nil {
		t.Fatalf("with no processor registered, ExtraSourceNames() = %v, want nil", got)
	}

	RegisterProgramProcessor(fakeProc{
		handles: func(string) bool { return true },
		process: func(Envelope, netip.Addr, []int, func(logship.Record)) bool { return true },
	})
	want := []string{"zenarmor"}
	if got := s.ExtraSourceNames(); len(got) != 1 || got[0] != want[0] {
		t.Fatalf("with a processor registered, ExtraSourceNames() = %v, want %v", got, want)
	}
}

// TestRegisterProgramProcessor_RebuildDoesNotPanic covers #401: the registry used
// to panic on a second RegisterProgramProcessor call, which made a second pipeline
// construction in one process (a test rebuilding it, or a future in-process
// reload) unsafe. A rebuild is now a supported event: the second registration
// replaces the first cleanly, and nothing from the first processor leaks into
// what registeredProgramProcessor returns afterwards.
func TestRegisterProgramProcessor_RebuildDoesNotPanic(t *testing.T) {
	t.Cleanup(ResetProgramProcessor)

	first := fakeProc{
		handles: func(p string) bool { return p == "first" },
		process: func(Envelope, netip.Addr, []int, func(logship.Record)) bool { return true },
	}
	RegisterProgramProcessor(first)
	if p := registeredProgramProcessor(); p == nil || !p.Handles("first") {
		t.Fatal("first registration not visible")
	}

	second := fakeProc{
		handles: func(p string) bool { return p == "second" },
		process: func(Envelope, netip.Addr, []int, func(logship.Record)) bool { return true },
	}
	// Must NOT panic: a rebuild is normal, not a wiring bug.
	RegisterProgramProcessor(second)

	p := registeredProgramProcessor()
	if p == nil {
		t.Fatal("registeredProgramProcessor() = nil after rebuild")
	}
	if p.Handles("first") {
		t.Error("registry still reports the FIRST processor's Handles() after a rebuild registered a second one")
	}
	if !p.Handles("second") {
		t.Error("registry does not report the SECOND (latest) processor after a rebuild")
	}
}

// TestResetProgramProcessor covers the explicit clear half of the lifecycle: a
// caller with a defined rebuild boundary (this test, or a future graceful
// shutdown/reload path) can leave the registry exactly as it found it rather than
// depending on the next RegisterProgramProcessor call to overwrite a leftover one.
func TestResetProgramProcessor(t *testing.T) {
	t.Cleanup(ResetProgramProcessor)

	RegisterProgramProcessor(fakeProc{
		handles: func(string) bool { return true },
		process: func(Envelope, netip.Addr, []int, func(logship.Record)) bool { return true },
	})
	if registeredProgramProcessor() == nil {
		t.Fatal("registration did not take")
	}

	ResetProgramProcessor()
	if p := registeredProgramProcessor(); p != nil {
		t.Fatalf("registeredProgramProcessor() = %v after Reset, want nil", p)
	}

	// Reset must also be idempotent / safe to call with nothing registered.
	ResetProgramProcessor()
}

// TestProgramProcessorRegistry_ConcurrentAccess drives Register/Reset/read from
// many goroutines at once. This is the concurrency half of #401's acceptance
// criteria ("concurrent reads and lifecycle transitions pass the race
// detector") — run this package's tests with -race to make it meaningful.
func TestProgramProcessorRegistry_ConcurrentAccess(t *testing.T) {
	t.Cleanup(ResetProgramProcessor)

	const goroutines = 16
	const iterations = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				switch i % 3 {
				case 0:
					RegisterProgramProcessor(fakeProc{
						handles: func(string) bool { return true },
						process: func(Envelope, netip.Addr, []int, func(logship.Record)) bool { return true },
					})
				case 1:
					_ = registeredProgramProcessor()
				case 2:
					ResetProgramProcessor()
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestSyslogSeverity(t *testing.T) {
	cases := map[int]logship.Severity{
		0:  logship.SeverityFatal, // emerg
		1:  logship.SeverityFatal, // alert
		2:  logship.SeverityFatal, // crit
		3:  logship.SeverityError,
		4:  logship.SeverityWarn,
		5:  logship.SeverityInfo,
		6:  logship.SeverityInfo,
		7:  logship.SeverityDebug,
		9:  logship.SeverityInfo, // out of range -> info, never dropped
		-1: logship.SeverityInfo,
	}
	for sev, want := range cases {
		if got := syslogSeverity(sev); got != want {
			t.Errorf("syslogSeverity(%d) = %v, want %v", sev, got, want)
		}
	}
}
