package syslog

import (
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/logship"
)

func sudoEnv(msg string) Envelope {
	return Envelope{
		Timestamp: time.Date(2026, 8, 4, 8, 46, 0, 0, time.UTC),
		Hostname:  "opnsense",
		Program:   "sudo",
		PID:       "54321",
		Facility:  4, // auth
		Severity:  5, // notice
		Message:   msg,
	}
}

// TestSudoRegistered guards the registry wiring: `sudo` must dispatch to this
// parser, and only this parser — RegisterParser panics on a duplicate, so this
// also proves sudo.go did not collide with an existing registration.
func TestSudoRegistered(t *testing.T) {
	if _, ok := parsers["sudo"]; !ok {
		t.Fatal(`"sudo" is not registered`)
	}
	if parserEnrichesBody("sudo") {
		t.Error(`parserEnrichesBody("sudo") = true, want false — sudo resolves no positional address of its own`)
	}
}

// The one real captured line (#669) plus TTY-present and multi-argument-command
// variants derived from upstream's new_logline() field order (plugins/sudoers/
// logging.c / lib/eventlog/eventlog.c): TTY= is present only when sudo runs from a
// terminal, and COMMAND carries the full invocation verbatim, arguments included.
func TestSudoAllowedLines(t *testing.T) {
	tests := []struct {
		name    string
		message string
		user    string
		tty     string
		pwd     string
		target  string
		command string
	}{
		{
			// Captured verbatim on production, 2026-08-04 (#669). Leading whitespace
			// is upstream's own actor-field padding.
			name:    "captured, no TTY (cron/scripted sudo)",
			message: "     rob : PWD=/home/rob ; USER=root ; COMMAND=/usr/bin/true",
			user:    "rob", tty: "", pwd: "/home/rob", target: "root", command: "/usr/bin/true",
		},
		{
			// TTY= present: source-derived from new_logline()'s field order, not
			// captured — this repo's one capture happened to have no controlling
			// terminal. sudo emits the raw tty name (no /dev/ prefix) here.
			name:    "TTY present, interactive sudo",
			message: "rob : TTY=pts/0 ; PWD=/home/rob ; USER=root ; COMMAND=/usr/bin/true",
			user:    "rob", tty: "pts/0", pwd: "/home/rob", target: "root", command: "/usr/bin/true",
		},
		{
			// Multi-argument COMMAND: source-derived — new_logline() logs the
			// command and its argv verbatim, space-separated, with no escaping of
			// its own. This is exactly the shape the credential-safety note in
			// sudo.go is about: an argument here could be a typed secret, and it
			// ships unmodified either way.
			name:    "command with arguments",
			message: "rob : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/local/sbin/pluginctl -d",
			user:    "rob", tty: "pts/1", pwd: "/root", target: "root", command: "/usr/local/sbin/pluginctl -d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, ok := parseSudo(sudoEnv(tt.message), nil, nil)
			if !ok {
				t.Fatalf("parseSudo(%q) ok = false, want true", tt.message)
			}
			if rec.Body != tt.message {
				t.Errorf("Body = %q, want the message verbatim", rec.Body)
			}
			want := map[string]string{
				attrSudoResult:     sudoResultAllowed,
				attrSudoUser:       tt.user,
				attrSudoTargetUser: tt.target,
				attrSudoCommand:    tt.command,
				attrSudoPWD:        tt.pwd,
			}
			for k, v := range want {
				if got := rec.Attributes[k]; got != v {
					t.Errorf("attribute %s = %q, want %q", k, got, v)
				}
			}
			if tt.tty == "" {
				if v, present := rec.Attributes[attrSudoTTY]; present {
					t.Errorf("attrSudoTTY unexpectedly present = %q, want absent when TTY= is not in the line", v)
				}
			} else if got := rec.Attributes[attrSudoTTY]; got != tt.tty {
				t.Errorf("attrSudoTTY = %q, want %q", got, tt.tty)
			}
			if rec.Severity == logship.SeverityWarn {
				t.Errorf("Severity = %v, an allowed sudo must not be elevated", rec.Severity)
			}
		})
	}
}

// The two failure shapes. NEITHER is in this repo's capture archive (#669) — both
// are derived from sudo's own source, not invented or captured:
//
//   - "user NOT in sudoers": the literal reason log_denied() emits
//     (plugins/sudoers/logging.c, N_("user NOT in sudoers")).
//   - "N incorrect password attempts": fmt_authfail_message()'s ngettext format
//     (plugins/sudoers/sudo_auth.c: "%u incorrect password attempt"/"%u incorrect
//     password attempts").
//
// These are the shapes the issue calls out as the ones that actually matter for
// alerting, so both raise severity the same way sshd.go raises a failed/
// invalid-user auth attempt.
func TestSudoFailureLinesAreSourceDerived(t *testing.T) {
	tests := []struct {
		name    string
		message string
	}{
		{
			name:    "not in sudoers, source-derived from log_denied()",
			message: "eve : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/eve ; USER=root ; COMMAND=/usr/bin/true",
		},
		{
			name:    "incorrect password attempts, source-derived from fmt_authfail_message()",
			message: "eve : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/home/eve ; USER=root ; COMMAND=/usr/bin/true",
		},
		{
			// ngettext's singular form (tries == 1) — same source function, the
			// other plural branch.
			name:    "singular incorrect password attempt, source-derived",
			message: "eve : 1 incorrect password attempt ; PWD=/home/eve ; USER=root ; COMMAND=/usr/bin/true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, ok := parseSudo(sudoEnv(tt.message), nil, nil)
			if !ok {
				t.Fatalf("parseSudo(%q) ok = false, want true", tt.message)
			}
			if got := rec.Attributes[attrSudoResult]; got != sudoResultFailed {
				t.Errorf("attrSudoResult = %q, want %q", got, sudoResultFailed)
			}
			if got := rec.Attributes[attrSudoUser]; got != "eve" {
				t.Errorf("attrSudoUser = %q, want %q", got, "eve")
			}
			if got := rec.Attributes[attrSudoTargetUser]; got != "root" {
				t.Errorf("attrSudoTargetUser = %q, want %q", got, "root")
			}
			if rec.Severity != logship.SeverityWarn {
				t.Errorf("Severity = %v, want SeverityWarn — a rejected sudo is a security event", rec.Severity)
			}
		})
	}
}

// auth.command must never become a metric label: it is unbounded, wire-derived,
// and can carry a typed secret (see the credential-safety note in sudo.go). This
// package registers no observeDerived family for sudo at all — proving that would
// require a case in derive.go's family switch, which does not exist for sudo — so
// the only assertion available here, and the one that matters, is that the
// attribute lands as structured metadata (Attributes, never a label) exactly like
// sshd.go's username handling.
func TestSudoCommandNeverBecomesALabel(t *testing.T) {
	rec, ok := parseSudo(sudoEnv("rob : PWD=/home/rob ; USER=root ; COMMAND=/usr/bin/true --password hunter2"), nil, nil)
	if !ok {
		t.Fatal("parseSudo() ok = false, want true")
	}
	got, ok := rec.Attributes[attrSudoCommand]
	if !ok {
		t.Fatal("auth.command missing from Attributes")
	}
	if got != "/usr/bin/true --password hunter2" {
		t.Errorf("auth.command = %q, want the command verbatim", got)
	}
	// logship.Record.Attributes is documented as "shipped as Loki structured
	// metadata. NEVER labels" (record.go) — there is no separate label field on
	// Record for this test to check against, which is the guarantee: the type
	// itself makes a label impossible from this parser.
}

// Lines this parser must decline, so they keep shipping as generic records rather
// than being mis-claimed.
func TestSudoUnmatchedLinesAreLeftGeneric(t *testing.T) {
	lines := []string{
		// Session open/close chatter (PAM), a different sudo log line shape
		// entirely — not one of the three modelled grammars.
		"pam_unix(sudo:session): session opened for user root(uid=0) by rob(uid=1000)",
		"pam_unix(sudo:session): session closed for user root",
		// Missing the "USER=" field.
		"rob : PWD=/home/rob ; COMMAND=/usr/bin/true",
		// Empty message.
		"",
	}
	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			if _, ok := parseSudo(sudoEnv(line), nil, nil); ok {
				t.Errorf("parseSudo(%q) claimed a line it must leave generic", line)
			}
		})
	}
}
