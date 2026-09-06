package syslog

import (
	"regexp"

	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
)

// sudo.go structures privilege-escalation on the firewall itself (#669). `sudo`
// already maps to the `auth` subsystem (registry.go), alongside sshd/sshd-session,
// which have had a parser since sshd.go. Leaving `sudo` unparsed was a hole in an
// otherwise-covered subsystem: privilege escalation on the firewall is a
// first-class audit event, and volume is bounded by human activity, not by
// anything on the wire.
//
// CREDENTIAL SAFETY. A sudo COMMAND line can carry a typed password as a literal
// argument (`sudo mytool --password hunter2`) — sudo has no way to distinguish
// that from any other argument, so it logs the command verbatim, and so does the
// generic record this line would otherwise ship as. The command therefore lands
// on auth.command, a RECORD ATTRIBUTE (Loki structured metadata, see
// logship.Record.Attributes), and is NEVER read by any deriver into a metric
// label: this file registers no observeDerived family and derive.go is not
// touched. A record attribute carries exactly the exposure the raw body already
// has today — structuring it makes it queryable by field instead of by regex, it
// does not add a new place the value is stored or a new audience that can see it.
// This mirrors sshd.go's treatment of usernames: named-identity/free-text fields
// are attributes, never labels.
//
// Two upstream shapes, and only one of them is in any capture this repo holds:
//
//   - log_allowed() (plugins/sudoers/logging.c) via the eventlog module's
//     new_logline(), the ONE line actually captured (#669): the actor, an
//     OPTIONAL `TTY=` (present only when sudo runs from a terminal — absent for a
//     cron-invoked or scripted sudo, exactly as in the captured line below), then
//     `PWD=`, `USER=`, `COMMAND=` in that fixed order. One capture is not enough to
//     pin a fixed field count, so the parser treats TTY as optional rather than
//     assuming it is always there.
//   - log_denied()/log_reject() building on the same new_logline(), for a REJECTED
//     attempt: the actor, then a REASON segment ahead of the same TTY?/PWD/USER/
//     COMMAND tail. Neither failure shape is in this repo's capture archive, so
//     both are derived from upstream source rather than invented — see sudo_test.go,
//     where each is commented as source-derived, not capture-derived. The two
//     reasons modelled are the sudoers-policy denial (log_denied() emits the reason
//     "user NOT in sudoers") and the retry-limit failure (fmt_authfail_message() in
//     plugins/sudoers/sudo_auth.c formats "N incorrect password attempt(s)" via
//     ngettext) — these are the two shapes that actually matter for alerting, per
//     the issue.
var (
	// One real captured line (leading whitespace is upstream's own padding, kept
	// out of the regex by TrimSpace at the call site rather than in the pattern):
	//
	//	     rob : PWD=/home/rob ; USER=root ; COMMAND=/usr/bin/true
	//
	// The leading whitespace is upstream's own actor-field padding (new_logline()
	// right-justifies it), which `^\s*` absorbs rather than requiring a caller-side
	// trim. TTY= is optional (absent above); when present it sits between the actor
	// and PWD= per new_logline()'s field order. COMMAND is the tail of the line,
	// kept as `(.+)` rather than split on spaces: sudo does not quote or escape it
	// for the log, so a further split would just be re-deriving sudo's own argv,
	// badly.
	reSudoAllowed = regexp.MustCompile(
		`^\s*(\S+) : (?:TTY=(\S+) ; )?PWD=(\S+) ; USER=(\S+) ; COMMAND=(.+)$`)

	// "<actor> : user NOT in sudoers ; [TTY=... ;] PWD=... ; USER=... ; COMMAND=..."
	//
	// Synthetic, derived from upstream source (log_denied(), plugins/sudoers/
	// logging.c: the reason literal is N_("user NOT in sudoers")), not captured —
	// see sudo_test.go.
	reSudoNotInSudoers = regexp.MustCompile(
		`^\s*(\S+) : user NOT in sudoers ; (?:TTY=(\S+) ; )?PWD=(\S+) ; USER=(\S+) ; COMMAND=(.+)$`)

	// "<actor> : N incorrect password attempt(s) ; [TTY=... ;] PWD=... ; USER=... ; COMMAND=..."
	//
	// Synthetic, derived from upstream source (fmt_authfail_message(),
	// plugins/sudoers/sudo_auth.c: ngettext("%u incorrect password attempt",
	// "%u incorrect password attempts", tries)), not captured — see sudo_test.go.
	reSudoBadPassword = regexp.MustCompile(
		`^\s*(\S+) : \d+ incorrect password attempts? ; (?:TTY=(\S+) ; )?PWD=(\S+) ; USER=(\S+) ; COMMAND=(.+)$`)
)

// The `sudo` attribute keys and their CLOSED, code-defined auth.result vocabulary
// (#669). Deliberately NOT in derive.go: no derived counter was requested for this
// family (see the credential-safety note above for why auth.command in particular
// must never reach a deriver), so these live beside the grammar that writes them.
const (
	attrSudoResult     = "auth.result"
	attrSudoUser       = "auth.user"
	attrSudoTargetUser = "auth.target_user"
	attrSudoCommand    = "auth.command"
	attrSudoPWD        = "auth.pwd"
	attrSudoTTY        = "auth.tty"

	sudoResultAllowed = "allowed"
	sudoResultFailed  = "failed"
)

func init() {
	// sudo resolves no positional network address of its own — PWD/COMMAND are
	// filesystem paths and shell text, not addresses — so it stays out of the
	// body-enrichment opt-in the same way charon/miniupnpd/etc. do not need it
	// either; there is simply nothing for the generic body scan to find here.
	RegisterParser(parseSudo, "sudo")
}

// parseSudo turns one sudo audit line into a structured record. It returns
// ok=false for anything that is not one of the three modelled shapes, so the
// caller degrades it to a generic record carrying the raw body — a line is never
// dropped.
func parseSudo(env Envelope, _ *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	msg := env.Message

	var result, actor, tty, pwd, targetUser, command string

	switch {
	case reSudoAllowed.MatchString(msg):
		m := reSudoAllowed.FindStringSubmatch(msg)
		result, actor, tty, pwd, targetUser, command =
			sudoResultAllowed, m[1], m[2], m[3], m[4], m[5]

	case reSudoNotInSudoers.MatchString(msg):
		m := reSudoNotInSudoers.FindStringSubmatch(msg)
		result, actor, tty, pwd, targetUser, command =
			sudoResultFailed, m[1], m[2], m[3], m[4], m[5]

	case reSudoBadPassword.MatchString(msg):
		m := reSudoBadPassword.FindStringSubmatch(msg)
		result, actor, tty, pwd, targetUser, command =
			sudoResultFailed, m[1], m[2], m[3], m[4], m[5]

	default:
		return logship.Record{}, false
	}

	rec, set := newRecord(env)
	set(attrSudoResult, result)
	set(attrSudoUser, actor)
	set(attrSudoTargetUser, targetUser)
	set(attrSudoCommand, command)
	set(attrSudoPWD, pwd)
	set(attrSudoTTY, tty)

	// A rejected sudo is a security event on the firewall itself — raise it, same
	// two-level rule sshd.go uses: only lift Info/Debug, never downgrade a box that
	// shouted louder.
	if result == sudoResultFailed {
		if rec.Severity == logship.SeverityInfo || rec.Severity == logship.SeverityDebug {
			rec.Severity = logship.SeverityWarn
		}
	}

	return rec, true
}
