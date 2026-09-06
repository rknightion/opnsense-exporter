package syslog

import (
	"regexp"
	"strings"

	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
)

// OPNsense's cron logs one line per job invocation, in one of three shapes.
// All were captured verbatim from the live box.
//
//	(root) CMD (/usr/libexec/atrun)
//	(nobody) CMD (/usr/local/sbin/configctl -d -- sfpmetrics run)
//	(nobody) CMD (/usr/local/sbin/configctl -d -- zenarmor periodicals)
//	(root) CMD ((/usr/local/bin/flock -n -E 0 -o /tmp/filter_update_tables.lock /usr/local/opnsense/scripts/filter/update_tables.py --quick) > /dev/null)
//	(nobody) MAIL (mailed 37 bytes of output but got status 0x0001
//	(nobody) MAIL (mailed 37 bytes of output but got status 0x0001\n)
//
// Attributes emitted:
//
//	cron.user     the user in the leading parens
//	cron.action   cmd | mail
//	cron.command  the full command text (CMD lines only; never set for MAIL)
//
// The grammar is `(<user>) <ACTION> (<detail>)`, but the detail is not a simple
// balanced-paren blob:
//   - a CMD line can nest parens in the command itself (the flock example).
//   - a MAIL line's detail is sometimes observed with NO closing paren at all —
//     cron truncates it mid-sentence (the first MAIL example above).
//   - a MAIL line's detail can ALSO carry a literal embedded newline before an
//     otherwise-present closing paren (the second MAIL example above). This is
//     a distinct shape from the truncated one, not a variant of it, and it is
//     what #638 was about: without `(?s)`, RE2's `.` does not cross the `\n`,
//     so `.*` stops short, and the trailing `$` — anchored at the absolute end
//     of the string, not end-of-line — then fails on the leftover `\n)`. The
//     line simply never matched, silently dropping 234 of 239 (97%) of
//     captured `/usr/sbin/cron` lines on the prod box. `(?s)` makes `.` match
//     `\n` too, so the whole payload (embedded newlines included) is captured.
//
// Rather than trying to balance parens, the action is matched anchored at the
// front and everything after the action's opening paren is taken verbatim as
// the detail, trimming at most one trailing close-paren (present on CMD lines
// and on the second MAIL shape, absent on the truncated MAIL shape) — see
// trimCronDetail for the embedded-newline trim decision.
var reCron = regexp.MustCompile(`(?s)^\((\S+)\)\s+(CMD|MAIL)\s+\((.*)$`)

// trimCronDetail applies the single normalisation step the grammar comment
// above describes: drop at most one trailing close-paren. #638: a MAIL
// detail can also carry a literal embedded newline immediately before that
// close-paren (`...0x0001\n)`) — once the paren is trimmed, also trim one
// trailing newline. A raw '\n' has no business surviving into a single
// attribute value (it breaks line-oriented log rendering and would produce
// an unsafe Loki label/value), so the pinned decision is to drop it too:
// "...0x0001\n)" -> "...0x0001", not "...0x0001\n". Nested parens and
// anything earlier in the string are left untouched; this only ever trims
// the final close-paren plus, at most, one newline directly behind it.
func trimCronDetail(detail string) string {
	detail = strings.TrimSuffix(detail, ")")
	return strings.TrimSuffix(detail, "\n")
}

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
		set("cron.command", trimCronDetail(detail))
	case "MAIL":
		set("cron.action", "mail")
	default:
		return logship.Record{}, false
	}

	return rec, true
}
