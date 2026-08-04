package syslog

import (
	"testing"
	"time"
)

func cronEnv(msg string) Envelope {
	return Envelope{
		Timestamp: time.Date(2026, 7, 20, 14, 0, 0, 0, time.UTC),
		Hostname:  "opnsense",
		Program:   "cron",
		Facility:  9, // cron
		Severity:  6, // info
		Message:   msg,
	}
}

func TestCronRegistered(t *testing.T) {
	for _, prog := range []string{"cron", "/usr/sbin/cron"} {
		if _, ok := parserFor(prog); !ok {
			t.Errorf("no parser registered for program %q", prog)
		}
	}
}

// TestCronVerbatimLines covers every line captured verbatim from the live box:
// plain CMD, CMD with nested parens in the command, and the unbalanced MAIL
// detail.
func TestCronVerbatimLines(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
		none []string
	}{
		{
			name: "atrun CMD",
			msg:  "(root) CMD (/usr/libexec/atrun)",
			want: map[string]string{
				"cron.user":    "root",
				"cron.action":  "cmd",
				"cron.command": "/usr/libexec/atrun",
			},
		},
		{
			name: "sfpmetrics CMD",
			msg:  "(nobody) CMD (/usr/local/sbin/configctl -d -- sfpmetrics run)",
			want: map[string]string{
				"cron.user":    "nobody",
				"cron.action":  "cmd",
				"cron.command": "/usr/local/sbin/configctl -d -- sfpmetrics run",
			},
		},
		{
			name: "zenarmor CMD",
			msg:  "(nobody) CMD (/usr/local/sbin/configctl -d -- zenarmor periodicals)",
			want: map[string]string{
				"cron.user":    "nobody",
				"cron.action":  "cmd",
				"cron.command": "/usr/local/sbin/configctl -d -- zenarmor periodicals",
			},
		},
		{
			name: "flock CMD with nested parens",
			msg:  "(root) CMD ((/usr/local/bin/flock -n -E 0 -o /tmp/filter_update_tables.lock /usr/local/opnsense/scripts/filter/update_tables.py --quick) > /dev/null)",
			want: map[string]string{
				"cron.user":    "root",
				"cron.action":  "cmd",
				"cron.command": "(/usr/local/bin/flock -n -E 0 -o /tmp/filter_update_tables.lock /usr/local/opnsense/scripts/filter/update_tables.py --quick) > /dev/null",
			},
		},
		{
			name: "MAIL with unbalanced trailing paren",
			msg:  "(nobody) MAIL (mailed 37 bytes of output but got status 0x0001",
			want: map[string]string{
				"cron.user":   "nobody",
				"cron.action": "mail",
			},
			none: []string{"cron.command"},
		},
		{
			// #638: verbatim box capture. The detail carries a literal embedded
			// newline before an otherwise-present closing paren -- a DIFFERENT shape
			// from the truncated-no-paren case above, not a variant of it. Before the
			// (?s) fix this line failed to match at all: RE2 '.' does not cross the
			// '\n', and the trailing '$' anchors at the absolute end of the string,
			// so the leftover "\n)" could never be consumed. This was 234 of 239
			// captured /usr/sbin/cron misses (97%) on the prod box.
			name: "MAIL with embedded newline before closing paren",
			msg:  "(nobody) MAIL (mailed 37 bytes of output but got status 0x0001\n)",
			want: map[string]string{
				"cron.user":   "nobody",
				"cron.action": "mail",
			},
			none: []string{"cron.command"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var m missRecorder
			rec, ok := parseCron(cronEnv(tc.msg), nil, m.miss)
			if !ok {
				t.Fatalf("parseCron(%q) returned ok=false, want a structured record", tc.msg)
			}
			if rec.Body != tc.msg {
				t.Errorf("Body = %q, want the raw message verbatim %q", rec.Body, tc.msg)
			}
			assertAttrs(t, rec, tc.want)
			assertNoAttrs(t, rec, tc.none...)
			if len(m.calls) != 0 {
				t.Errorf("parseCron(%q) called miss(%v); this lane performs no enrichment lookups", tc.msg, m.calls)
			}
		})
	}
}

func TestCronNonMatchingLine(t *testing.T) {
	var m missRecorder
	_, ok := parseCron(cronEnv("some random message"), nil, m.miss)
	if ok {
		t.Fatal("parseCron matched a non-cron line, want ok=false")
	}
}

// TestTrimCronDetailNewlineDecision pins the #638 judgement call explicitly:
// given a detail string ending in "\n)" (the embedded-newline MAIL shape),
// trimCronDetail strips BOTH the trailing ')' and the newline that precedes
// it, not just the paren. See the reasoning on trimCronDetail itself.
//
// This is tested directly against the helper — not through parseCron's
// Record output — because the CMD branch is the only caller today (MAIL
// never surfaces cron.command per the grammar comment on reCron), but the
// decision governs the shared trim step regardless of which action reaches
// it, and must stay pinned even though the MAIL branch doesn't consume it
// yet.
func TestTrimCronDetailNewlineDecision(t *testing.T) {
	tests := []struct {
		name   string
		detail string
		want   string
	}{
		{
			name:   "trailing paren only",
			detail: "/usr/libexec/atrun)",
			want:   "/usr/libexec/atrun",
		},
		{
			name:   "no trailing paren, untouched",
			detail: "mailed 37 bytes of output but got status 0x0001",
			want:   "mailed 37 bytes of output but got status 0x0001",
		},
		{
			// The verbatim #638 box capture's third regex group, once (?s)
			// lets the match succeed: both the '\n' and the ')' are gone.
			name:   "embedded newline before closing paren",
			detail: "mailed 37 bytes of output but got status 0x0001\n)",
			want:   "mailed 37 bytes of output but got status 0x0001",
		},
		{
			name:   "nested parens left untouched, only final char pair trimmed",
			detail: "(/usr/local/bin/flock -n) > /dev/null)",
			want:   "(/usr/local/bin/flock -n) > /dev/null",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := trimCronDetail(tc.detail); got != tc.want {
				t.Errorf("trimCronDetail(%q) = %q, want %q", tc.detail, got, tc.want)
			}
		})
	}
}
