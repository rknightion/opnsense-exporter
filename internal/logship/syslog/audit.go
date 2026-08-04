package syslog

import (
	"regexp"
	"strings"

	"github.com/rknightion/opnsense2otel/v4/internal/logship"
	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
)

// OPNsense's config-change audit trail used to be scraped from the diagnostics
// log API (the deleted `diaglog` poll lane) and parsed into config_user /
// config_revision / config_uri. The same events arrive over syslog under
// program=audit, so the API endpoint was only ever re-reading the file syslog-ng
// had already written. This lane restores those attributes from the syslog side.
//
// Three shapes, all verified verbatim against a live OPNsense 26.7 box:
//
//  1. program=audit, facility auth, severity notice — a config change:
//     "user root@127.0.0.1 changed configuration to /conf/backup/config-1784062885.085.xml in /api/syslog/settings/set /api/syslog/settings/set made changes"
//     The URI is repeated at the end ("… made changes"); the repeat is ignored,
//     exactly as the deleted lane's regex did.
//
//  2. program=configd.py, facility auth — an authorisation decision:
//     "action allowed interface.newipv6 for user root"
//
//  3. program=configd.py, facility daemon — an RPC dispatch:
//     "[1d319fef-0428-4250-9cb8-fdd9c4148887] request suricata rule metadata"
//
// Anything else returns ok=false and ships as a generic record. No shape here is
// inferred from documentation: every format guessed rather than captured in this
// package has so far turned out to be wrong.
//
// WebGUI login / session events (#641 item 3), added from six real captures on a
// live production box, 2026-08-04. The issue text claimed these events "arrive
// under the audit and configd.py programs"; that was checked against the box and
// is WRONG — every genuine WebGUI auth event arrives under program=audit only.
// configd.py's only login-adjacent lines are periodic captive-portal RPC command
// names ("[uuid] captive login logout enrich"), already correctly matched by
// configdRPC above, and are NOT auth events — so there is deliberately no
// configd.py branch for this.
//
//  4. program=audit — a successful login is TWO lines, both severity notice:
//     "user root authenticated successfully for WebGui [using OPNsense\Auth\Services\WebGui + OPNsense\Auth\Local]"
//     "/index.php: Successful login for user 'root' from: 10.0.0.120"
//
//  5. program=audit — a failed login is THREE lines, each at a DIFFERENT syslog
//     severity the box itself assigns (<39> auth.debug, <36> auth.warning, <35>
//     auth.err — a real signal this parser preserves rather than collapsing):
//     "user root failed authentication for WebGui on OPNsense\Auth\Services\WebGui via OPNsense\Auth\Local"
//     "user root could not authenticate for WebGui. [using OPNsense\Auth\Services\WebGui + OPNsense\Auth\Local]"
//     "/index.php: Web GUI authentication error for 'root' from 2001:db8:1f05::10be"
//
//  6. program=audit — an authenticated-only route hit with no session:
//     "no active session, user not found (called \"/ui/diagnostics/log/core/gateways\" @ 10.0.0.120)"
//
// Three deliberate design decisions on the login shapes:
//
//   - THREE-LINES-PER-FAILURE, not triple-counted: only the index.php line
//     (reWebGUIIndexPHP) is tagged event="webgui_login" — it is the one line that
//     exists exactly once per real attempt in BOTH the success and failure case,
//     and it is the one that carries the source address. The auth-stack's own
//     confirmation line(s) (reWebGUIAuthBackend) are tagged the DIFFERENT event
//     "webgui_auth_backend" instead of also being "webgui_login", precisely so an
//     operator counting failed logins via event="webgui_login" gets exactly one
//     record per real attempt rather than up to three. This mirrors sshd.go's own
//     multi-line-per-attempt handling: each line is parsed on its own terms, and
//     nothing here tries to correlate lines into a single event — Loki queries
//     select the shape they mean by filtering on `event`.
//   - NO USER ENUMERATION: a wrong password (existing user) and a nonexistent
//     username produce BYTE-IDENTICAL log shapes — verified live across root, rob
//     and a deliberately nonexistent "nouserlol", captured 2026-08-04. There is no
//     "unknown user" branch here because the box gives no such signal; do not add
//     one from assumption.
//   - "no active session" is modeled as its OWN event, "webgui_session_expired",
//     not folded into audit.result=failure: no credentials were submitted, and
//     "user not found" names no real account, so treating it as a rejected login
//     would fabricate a user/outcome pair that was never attempted.
//
// Two traps in the index.php line's shared regex, reWebGUIIndexPHP:
//   - the preposition differs: success is "from: <addr>" (WITH a colon), failure
//     is "from <addr>" (no colon) — "from:?\s+" makes the colon optional so one
//     regex covers both.
//   - the address can be IPv6 ("2001:db8:1f05::10be"), so it is captured whole
//     with \S+ rather than split on ':'.
//
// No logout line was found anywhere in four days of audit logs on the box —
// OPNsense's WebGUI session appears to just time out silently. There is
// deliberately NO logout branch: modeling one from documentation, with no capture
// to verify it against, is exactly the mistake #284 already made twice.
var (
	// auditConfigChange is lifted verbatim from the deleted diaglog lane
	// (diagLogAuditConfigChange), which matched OPNsense's Config::auditLogChange()
	// text. It also covers the "user (root) changed …" form emitted by CLI/php
	// driven changes.
	auditConfigChange = regexp.MustCompile(`^\s*user (\S+) changed configuration to (\S+) in (\S+)`)

	// configdAuthorization matches configd.py's authorisation decisions. Only the
	// allowed/denied wordings observed on a real box are accepted — an unknown
	// wording degrades to generic rather than being force-fitted.
	configdAuthorization = regexp.MustCompile(`^\s*action (allowed|denied) (\S+) for user (\S+)\s*$`)

	// configdRPC matches configd.py's RPC dispatch lines: a task UUID in brackets
	// followed by the command text.
	configdRPC = regexp.MustCompile(`^\s*\[([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\]\s+(\S.*)$`)

	// configdActionNotFound matches configd.py rejecting a requested action that does
	// not exist ("action wireguard.status not found for user root") — a UI or plugin
	// polling an action a not-installed plugin does not register. A benign but common
	// line, worth structuring as the not-found sibling of configdAuthorization.
	configdActionNotFound = regexp.MustCompile(`^\s*action (\S+) not found for user (\S+)\s*$`)

	// configdMessageResult matches a completed configd command:
	// "message <uuid> [<command>] returned <result>". The result is often a large JSON
	// blob (qfeeds stats); it is NOT stored as an attribute — the raw body keeps it —
	// only a short clean status word (OK) is.
	configdMessageResult = regexp.MustCompile(`^\s*message ([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}) \[([^\]]*)\] returned\s*(.*)$`)

	// reWebGUIAuthBackend matches the auth-stack's own confirmation line(s) of a
	// WebGUI login attempt. Only the three phrases observed on a real box are
	// accepted — an unrecognised phrase degrades to generic rather than being
	// force-fitted:
	//    "authenticated successfully" -> success
	//    "failed authentication"      -> failure
	//    "could not authenticate"     -> failure (a second, near-duplicate failure line)
	reWebGUIAuthBackend = regexp.MustCompile(`^\s*user (\S+) (authenticated successfully|failed authentication|could not authenticate) for WebGui\b`)

	// reWebGUIIndexPHP matches index.php's own login-result line: the ONE line per
	// real attempt (success or failure) that carries the source address, and
	// therefore the canonical "webgui_login" event — see the package doc comment
	// above for why reWebGUIAuthBackend is deliberately NOT counted the same way,
	// and for the two traps (optional colon, IPv6 address) this single regex
	// handles.
	reWebGUIIndexPHP = regexp.MustCompile(`^\s*/index\.php: (Successful login for user|Web GUI authentication error for) '(\S+)' from:?\s+(\S+)\s*$`)

	// reWebGUISessionExpired matches an authenticated-only route hit with no (or an
	// expired) session. See the package doc comment for why this is its own event
	// rather than a login outcome.
	reWebGUISessionExpired = regexp.MustCompile(`^\s*no active session, user not found \(called "([^"]+)" @ (\S+)\)\s*$`)
)

func init() {
	RegisterParser(parseAudit, "audit", "configd.py")
}

// parseAudit parses OPNsense's config-change audit trail, configd's
// authorisation/RPC lines, and WebGUI login/session events. The snapshot is only
// used for the WebGUI login/session-expiry branches' best-effort source-address
// enrichment (mirroring sshd.go); every other branch performs no lookups. This
// lane never calls miss(), which is reserved for lookups whose failure means the
// enrichment snapshot is stale — an unrecognised WebGUI client address is normal,
// not a cache problem.
//
// It returns ok=false for any line matching none of the known shapes, so the
// caller degrades it to a generic record carrying the raw body. It never drops a
// line and never panics.
func parseAudit(env Envelope, snap *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	msg := env.Message

	if m := auditConfigChange.FindStringSubmatch(msg); m != nil {
		rec, set := newRecord(env)
		set("event", "config_change")
		set("config_user", m[1])
		set("user.name", m[1]) // semconv: dual-emit the standard identity key
		set("config_revision", m[2])
		set("config_uri", m[3])
		return rec, true
	}

	if m := reWebGUIIndexPHP.FindStringSubmatch(msg); m != nil {
		user, addr := m[2], m[3]
		result := "failure"
		if m[1] == "Successful login for user" {
			result = "success"
		}
		rec, set := newRecord(env)
		set("event", "webgui_login")
		set("audit.user", user)
		set("user.name", user) // semconv: dual-emit the standard identity key
		set("audit.result", result)
		set("src.ip", addr)
		// Best-effort enrichment/geo of the source address, exactly as sshd.go does
		// for its own auth lines. A miss is silent: a login attempt from an address
		// outside the enrichment snapshot is normal, not a sign of a stale snapshot.
		enrichEndpoint(set, snap, "src", addr, "", "")
		geoAttrs(set, "src", addr)
		return rec, true
	}

	if m := reWebGUIAuthBackend.FindStringSubmatch(msg); m != nil {
		result := "failure"
		if m[2] == "authenticated successfully" {
			result = "success"
		}
		rec, set := newRecord(env)
		set("event", "webgui_auth_backend")
		set("audit.user", m[1])
		set("user.name", m[1]) // semconv: dual-emit the standard identity key
		set("audit.result", result)
		return rec, true
	}

	if m := reWebGUISessionExpired.FindStringSubmatch(msg); m != nil {
		resource, addr := m[1], m[2]
		rec, set := newRecord(env)
		set("event", "webgui_session_expired")
		set("audit.resource", resource)
		set("src.ip", addr)
		enrichEndpoint(set, snap, "src", addr, "", "")
		geoAttrs(set, "src", addr)
		return rec, true
	}

	if m := configdAuthorization.FindStringSubmatch(msg); m != nil {
		rec, set := newRecord(env)
		set("event", "authorization")
		set("audit.result", m[1])
		set("audit.action", m[2])
		set("audit.user", m[3])
		set("user.name", m[3]) // semconv: dual-emit the standard identity key
		// A denial is the signal worth keeping: configd ships it at the same
		// severity as an allow, so raise it here rather than lose it in the noise.
		if m[1] == "denied" {
			rec.Severity = logship.SeverityWarn
		}
		return rec, true
	}

	if m := configdRPC.FindStringSubmatch(msg); m != nil {
		cmd := strings.TrimSpace(m[2])
		if cmd == "" {
			return logship.Record{}, false
		}
		rec, set := newRecord(env)
		set("event", "configd_rpc")
		set("configd.task_id", m[1])
		set("configd.command", cmd)
		return rec, true
	}

	if m := configdActionNotFound.FindStringSubmatch(msg); m != nil {
		rec, set := newRecord(env)
		set("event", "authorization")
		set("audit.result", "not_found")
		set("audit.action", m[1])
		set("audit.user", m[2])
		set("user.name", m[2]) // semconv: dual-emit the standard identity key
		return rec, true
	}

	if m := configdMessageResult.FindStringSubmatch(msg); m != nil {
		cmd := strings.TrimSpace(m[2])
		if cmd == "" {
			return logship.Record{}, false
		}
		rec, set := newRecord(env)
		set("event", "configd_result")
		set("configd.task_id", m[1])
		set("configd.command", cmd)
		// Store only a short, clean status word. A JSON/array blob (qfeeds stats) stays
		// in the raw body rather than becoming a high-cardinality attribute.
		if r := strings.TrimSpace(m[3]); r != "" && len(r) <= 32 &&
			!strings.HasPrefix(r, "{") && !strings.HasPrefix(r, "[") {
			set("configd.result", r)
		}
		return rec, true
	}

	return logship.Record{}, false
}
