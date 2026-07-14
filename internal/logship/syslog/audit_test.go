package syslog

import (
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/logship"
)

// auditEnv builds an envelope for one of the audit-trail programs. The fixture
// lines below are VERBATIM from a live OPNsense 26.7 box (2026-07-14) — the
// formats in this lane have been guessed wrong before, so they are never
// paraphrased here.
func auditEnv(program string, facility, severity int, msg string) Envelope {
	return Envelope{
		Timestamp: time.Date(2026, 7, 14, 22, 1, 25, 0, time.UTC),
		Hostname:  "opnsense-devel.internal",
		Program:   program,
		PID:       "75086",
		Facility:  facility,
		Severity:  severity,
		Message:   msg,
	}
}

func TestParseAudit_ConfigChange(t *testing.T) {
	// Live line, program=audit, PRI 37 => facility 4 (auth), severity 5 (notice).
	// Note the URI is REPEATED ("... made changes"); the repeat is ignored, as the
	// deleted diaglog lane did.
	const msg = "user root@127.0.0.1 changed configuration to /conf/backup/config-1784062885.085.xml in /api/syslog/settings/set /api/syslog/settings/set made changes"

	rec, ok := parseAudit(auditEnv("audit", 4, 5, msg), nil, nil)
	if !ok {
		t.Fatal("parseAudit returned ok=false for the live config-change line")
	}
	if rec.Body != msg {
		t.Errorf("Body = %q, want the raw message verbatim", rec.Body)
	}
	if rec.Severity != logship.SeverityInfo {
		t.Errorf("Severity = %v, want Info (syslog notice)", rec.Severity)
	}
	want := map[string]string{
		"config_user":     "root@127.0.0.1",
		"config_revision": "/conf/backup/config-1784062885.085.xml",
		"config_uri":      "/api/syslog/settings/set",
		"event":           "config_change",
		// envelope attrs from newRecord
		"program":  "audit",
		"host":     "opnsense-devel.internal",
		"pid":      "75086",
		"facility": "4",
		"severity": "5",
	}
	for k, v := range want {
		if got := rec.Attributes[k]; got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}
}

func TestParseAudit_ConfigChangeParenthesisedUser(t *testing.T) {
	// The deleted lane also saw a "(root)" form from CLI/php-driven changes.
	const msg = "user (root) changed configuration to /conf/backup/config-1784062885.085.xml in /tmp/fix_dup_opt4.php made changes"

	rec, ok := parseAudit(auditEnv("audit", 4, 5, msg), nil, nil)
	if !ok {
		t.Fatal("parseAudit returned ok=false")
	}
	if got := rec.Attributes["config_user"]; got != "(root)" {
		t.Errorf("config_user = %q, want %q", got, "(root)")
	}
	if got := rec.Attributes["config_uri"]; got != "/tmp/fix_dup_opt4.php" {
		t.Errorf("config_uri = %q, want %q", got, "/tmp/fix_dup_opt4.php")
	}
}

func TestParseConfigd_Authorisation(t *testing.T) {
	// Live line, program=configd.py, facility auth, severity 6.
	const msg = "action allowed interface.newipv6 for user root"

	rec, ok := parseAudit(auditEnv("configd.py", 4, 6, msg), nil, nil)
	if !ok {
		t.Fatal("parseAudit returned ok=false for the live configd authorisation line")
	}
	if rec.Body != msg {
		t.Errorf("Body = %q, want the raw message verbatim", rec.Body)
	}
	want := map[string]string{
		"audit.action": "interface.newipv6",
		"audit.user":   "root",
		"audit.result": "allowed",
		"event":        "authorization",
		"program":      "configd.py",
	}
	for k, v := range want {
		if got := rec.Attributes[k]; got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}
	if rec.Severity != logship.SeverityInfo {
		t.Errorf("Severity = %v, want Info", rec.Severity)
	}
}

func TestParseConfigd_AuthorisationDenied(t *testing.T) {
	const msg = "action denied interface.newipv6 for user nobody"

	rec, ok := parseAudit(auditEnv("configd.py", 4, 6, msg), nil, nil)
	if !ok {
		t.Fatal("parseAudit returned ok=false for the denied variant")
	}
	if got := rec.Attributes["audit.result"]; got != "denied" {
		t.Errorf("audit.result = %q, want %q", got, "denied")
	}
	if got := rec.Attributes["audit.user"]; got != "nobody" {
		t.Errorf("audit.user = %q, want %q", got, "nobody")
	}
	// A denial is worth more than Info even though syslog ships it at sev 6.
	if rec.Severity != logship.SeverityWarn {
		t.Errorf("Severity = %v, want Warn for a denied action", rec.Severity)
	}
}

func TestParseConfigd_RPC(t *testing.T) {
	// Live lines, program=configd.py, facility daemon, severity 5.
	tests := []struct {
		msg     string
		taskID  string
		command string
	}{
		{
			msg:     "[1d319fef-0428-4250-9cb8-fdd9c4148887] request suricata rule metadata",
			taskID:  "1d319fef-0428-4250-9cb8-fdd9c4148887",
			command: "request suricata rule metadata",
		},
		{
			msg:     "[ac7aa2ee-407f-4476-af6e-01cabaf8ee10] New IPv6 on vtnet0",
			taskID:  "ac7aa2ee-407f-4476-af6e-01cabaf8ee10",
			command: "New IPv6 on vtnet0",
		},
	}
	for _, tc := range tests {
		t.Run(tc.taskID, func(t *testing.T) {
			rec, ok := parseAudit(auditEnv("configd.py", 3, 5, tc.msg), nil, nil)
			if !ok {
				t.Fatal("parseAudit returned ok=false for the live configd RPC line")
			}
			if rec.Body != tc.msg {
				t.Errorf("Body = %q, want the raw message verbatim", rec.Body)
			}
			if got := rec.Attributes["configd.task_id"]; got != tc.taskID {
				t.Errorf("configd.task_id = %q, want %q", got, tc.taskID)
			}
			if got := rec.Attributes["configd.command"]; got != tc.command {
				t.Errorf("configd.command = %q, want %q", got, tc.command)
			}
			if got := rec.Attributes["event"]; got != "configd_rpc" {
				t.Errorf("event = %q, want %q", got, "configd_rpc")
			}
		})
	}
}

// A line matching none of the three shapes degrades to ok=false so BuildRecord
// ships it as a generic record. It is never dropped and never invented into.
func TestParseAudit_UnrecognisedDegrades(t *testing.T) {
	lines := []string{
		"",
		"   ",
		"config-1784062885.085.xml written",
		"user root changed something else entirely",
		"action escalated interface.newipv6 for user root", // not allowed/denied
		"[not-a-uuid] request suricata rule metadata",
		"[1d319fef-0428-4250-9cb8-fdd9c4148887]",                  // uuid, no command
		"[1d319fef-0428-4250-9cb8-fdd9c4148887]    ",              // uuid, blank command
		"\x00\x01\x02 garbage \xff",                               // binary junk
		"user  changed configuration to  in  ",                    // empty captures
		"action allowed for user root",                            // missing action
		"[1d319fef-0428-4250-9cb8-fdd9c4148887 request suricata]", // unbalanced
	}
	for _, line := range lines {
		if _, ok := parseAudit(auditEnv("audit", 4, 5, line), nil, nil); ok {
			t.Errorf("parseAudit(%q) = ok, want ok=false (degrade to generic)", line)
		}
	}
}

// A nil snapshot and a nil miss func must both be fine: this lane does no cache
// lookups at all, so it must never call miss() and never dereference the snapshot.
func TestParseAudit_NilSnapshotAndNoMissCalls(t *testing.T) {
	var mr missRecorder
	lines := []string{
		"user root@127.0.0.1 changed configuration to /conf/backup/config-1.xml in /api/x/y made changes",
		"action allowed interface.newipv6 for user root",
		"[1d319fef-0428-4250-9cb8-fdd9c4148887] request suricata rule metadata",
		"total garbage",
	}
	for _, line := range lines {
		parseAudit(auditEnv("configd.py", 4, 6, line), nil, mr.miss)
	}
	if len(mr.calls) != 0 {
		t.Errorf("parseAudit called miss(%v); this lane performs no cache lookups and must never signal a miss", mr.calls)
	}
}

// The registry must route both programs here, and BuildRecord must produce the
// structured record end-to-end (with the coarse audit subsystem attached).
func TestBuildRecord_AuditPrograms(t *testing.T) {
	for _, prog := range []string{"audit", "configd.py"} {
		if _, ok := parserFor(prog); !ok {
			t.Fatalf("no parser registered for program %q", prog)
		}
	}

	const msg = "user root@127.0.0.1 changed configuration to /conf/backup/config-1784062885.085.xml in /api/syslog/settings/set /api/syslog/settings/set made changes"
	rec := BuildRecord(auditEnv("audit", 4, 5, msg), nil, nil)
	if got := rec.Attributes["config_user"]; got != "root@127.0.0.1" {
		t.Errorf("config_user = %q, want %q", got, "root@127.0.0.1")
	}
	if got := rec.Attributes["subsystem"]; got != "audit" {
		t.Errorf("subsystem = %q, want %q", got, "audit")
	}
}
