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

// Regression guard on the v1 duplication decision: internal/logship/ids.go
// already ships full EVE alert records from the richer file-based eve.json.
// Parsing EVE here too would ship every alert TWICE into Loki with no dedupe.
// So an EVE JSON line over syslog must ship as a generic record with its body
// verbatim and NO extracted alert fields.
func TestBuildRecord_SuricataEVEJSONShipsGenericWithoutAlertFields(t *testing.T) {
	eve := `{"timestamp":"2026-07-14T12:00:00.000000+0000","flow_id":1234,"event_type":"alert",` +
		`"src_ip":"10.0.0.6","src_port":51000,"dest_ip":"1.1.1.1","dest_port":443,"proto":"TCP",` +
		`"alert":{"action":"allowed","gid":1,"signature_id":2013028,"rev":7,` +
		`"signature":"ET POLICY curl User-Agent Outbound","category":"Attempted Information Leak","severity":2}}`

	rec := BuildRecord(envelopeFor("suricata", eve, 5), nil, nil)

	if rec.Body != eve {
		t.Errorf("Body = %q, want the EVE JSON verbatim", rec.Body)
	}
	assertAttr(t, rec, "program", "suricata")
	for _, k := range []string{"alert.signature", "alert.signature_id", "alert.category", "alert.severity", "src.ip", "dst.ip"} {
		if v, ok := rec.Attributes[k]; ok {
			t.Errorf("v1 must NOT parse Suricata EVE over syslog (ids.go already ships it from eve.json): "+
				"attribute %q was extracted (%q) — that would duplicate every alert in Loki", k, v)
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
