package syslog

import (
	"strings"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/logship"
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
