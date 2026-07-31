package syslog

import (
	"regexp"

	"github.com/rknightion/opnsense2otel/v4/internal/logship"
	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
)

// OPNsense's cron logs one line per job invocation, in one of two shapes. Both
// were captured verbatim from the live box.
//
//	(root) CMD (/usr/libexec/atrun)
//	(nobody) CMD (/usr/local/sbin/configctl -d -- sfpmetrics run)
//	(nobody) CMD (/usr/local/sbin/configctl -d -- zenarmor periodicals)
//	(root) CMD ((/usr/local/bin/flock -n -E 0 -o /tmp/filter_update_tables.lock /usr/local/opnsense/scripts/filter/update_tables.py --quick) > /dev/null)
//	(nobody) MAIL (mailed 37 bytes of output but got status 0x0001
//
// Attributes emitted:
//
//	cron.user     the user in the leading parens
//	cron.action   cmd | mail
//	cron.command  the full command text (CMD lines only; never set for MAIL)
//
// The grammar is `(<user>) <ACTION> (<detail>)`, but the detail is not a simple
// balanced-paren blob: a CMD line can nest parens in the command itself (the
// flock example), and a MAIL line's detail is observed with NO closing paren at
// all — cron truncates it mid-sentence. Rather than trying to balance parens, the
// action is matched anchored at the front and everything after the action's
// opening paren is taken verbatim as the detail, trimming at most one trailing
// close-paren (present on CMD lines, absent on the MAIL line above).
var reCron = regexp.MustCompile(`^\((\S+)\)\s+(CMD|MAIL)\s+\((.*)$`)

func init() {
	RegisterParser(parseCron, "cron", "/usr/sbin/cron")
}

func parseCron(env Envelope, _ *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	m := reCron.FindStringSubmatch(env.Message)
	if m == nil {
		return logship.Record{}, false
	}
	user, action, detail := m[1], m[2], m[3]

	rec, set := newRecord(env)
	set("cron.user", user)

	switch action {
	case "CMD":
		set("cron.action", "cmd")
		// Trim exactly one trailing ')' when present — the outer close for the
		// detail group. Nested parens inside the command (the flock example) are
		// left untouched; only the final character is ever trimmed.
		if len(detail) > 0 && detail[len(detail)-1] == ')' {
			detail = detail[:len(detail)-1]
		}
		set("cron.command", detail)
	case "MAIL":
		set("cron.action", "mail")
	default:
		return logship.Record{}, false
	}

	return rec, true
}
