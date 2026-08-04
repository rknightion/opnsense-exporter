package syslog

import (
	"testing"

	"github.com/rknightion/opnsense2otel/v4/internal/logship"
)

// configd.py runs at facility daemon (3); severity info (6).
func configdEnv(msg string) Envelope {
	return auditEnv("configd.py", 3, 6, msg)
}

// TestConfigdActionNotFound: an action a not-installed plugin never registered.
func TestConfigdActionNotFound(t *testing.T) {
	rec, ok := parseAudit(configdEnv("action wireguard.status not found for user root"), nil, func(string) {})
	if !ok {
		t.Fatal("parseAudit returned ok=false for an action-not-found line")
	}
	assertAttrs(t, rec, map[string]string{
		"event":        "authorization",
		"audit.result": "not_found",
		"audit.action": "wireguard.status",
		"audit.user":   "root",
		"user.name":    "root",
	})
}

// TestConfigdMessageResultOK: a completed configd command with a short status word.
func TestConfigdMessageResultOK(t *testing.T) {
	rec, ok := parseAudit(configdEnv("message 16ae3b8d-0588-4a04-a7b9-d89b1875cd4c [interface newipv6 pppoe0] returned OK "), nil, func(string) {})
	if !ok {
		t.Fatal("parseAudit returned ok=false for a message-result line")
	}
	assertAttrs(t, rec, map[string]string{
		"event":           "configd_result",
		"configd.task_id": "16ae3b8d-0588-4a04-a7b9-d89b1875cd4c",
		"configd.command": "interface newipv6 pppoe0",
		"configd.result":  "OK",
	})
}

// TestConfigdMessageResultJSONNotStored: a large JSON result stays in the raw body
// and is NOT promoted to a high-cardinality attribute.
func TestConfigdMessageResultJSONNotStored(t *testing.T) {
	rec, ok := parseAudit(configdEnv(`message f3a37b2f-39f2-4d71-9b97-11749f19db64 [qfeeds stats] returned {"feeds":[{"name":"malware_ip","total_entries":306172}]}`), nil, func(string) {})
	if !ok {
		t.Fatal("parseAudit returned ok=false for a JSON message-result line")
	}
	assertAttrs(t, rec, map[string]string{
		"event":           "configd_result",
		"configd.command": "qfeeds stats",
	})
	assertNoAttrs(t, rec, "configd.result")
}

// --- WebGUI login / session events (issue #641 item 3) ---
//
// Every fixture below is VERBATIM from a live production OPNsense box,
// 2026-08-04 — including the three failure lines' real syslog priorities
// (decoded PRI = facility*8 + severity; facility auth = 4). The issue text
// claimed these events arrive under "audit and configd.py"; that was checked
// and is WRONG — every genuine WebGUI auth event arrives under program=audit
// only. configd.py's login-adjacent lines are periodic captive-portal RPC
// command names ("[uuid] captive login logout enrich"), already correctly
// matched by configdRPC, and are NOT auth events — so there is deliberately no
// configd.py branch here.

// TestParseAudit_WebGUILoginSuccess: the two lines a successful login emits,
// both program=audit, severity notice (PRI 37 = facility 4, severity 5). The
// backend line carries no address; the index.php line is the canonical
// per-attempt "webgui_login" event and carries the source IPv4 address after
// "from:" WITH a colon (the success preposition form — see the failure test
// for the no-colon form).
func TestParseAudit_WebGUILoginSuccess(t *testing.T) {
	backend, ok := parseAudit(auditEnv("audit", 4, 5,
		`user root authenticated successfully for WebGui [using OPNsense\Auth\Services\WebGui + OPNsense\Auth\Local]`),
		nil, func(string) {})
	if !ok {
		t.Fatal("parseAudit returned ok=false for the WebGUI success backend line")
	}
	assertAttrs(t, backend, map[string]string{
		"event":        "webgui_auth_backend",
		"audit.user":   "root",
		"user.name":    "root",
		"audit.result": "success",
	})
	assertNoAttrs(t, backend, "src.ip")
	if backend.Severity != logship.SeverityInfo {
		t.Errorf("Severity = %v, want Info (syslog notice, unmodified)", backend.Severity)
	}

	login, ok := parseAudit(auditEnv("audit", 4, 5,
		`/index.php: Successful login for user 'root' from: 10.0.0.120`),
		nil, func(string) {})
	if !ok {
		t.Fatal("parseAudit returned ok=false for the WebGUI success index.php line")
	}
	assertAttrs(t, login, map[string]string{
		"event":        "webgui_login",
		"audit.user":   "root",
		"user.name":    "root",
		"audit.result": "success",
		"src.ip":       "10.0.0.120",
	})
}

// TestParseAudit_WebGUILoginFailure: the three lines ONE failed login emits,
// each at a DIFFERENT syslog severity the box itself assigns (<39> auth.debug,
// <36> auth.warning, <35> auth.err). That is itself a signal worth preserving,
// so parseAudit must NOT collapse or override it the way sshd.go nudges info up
// to warn for a failed SSH attempt — WebGUI failures already arrive
// pre-differentiated. Only the third line (index.php) is the canonical
// "webgui_login" event; the first two are "webgui_auth_backend" — see the
// package doc comment near parseAudit for why: an operator counting failed
// logins via event="webgui_login" gets exactly one record per real attempt, not
// three.
func TestParseAudit_WebGUILoginFailure(t *testing.T) {
	rec1, ok := parseAudit(auditEnv("audit", 4, 7, // <39> auth.debug
		`user root failed authentication for WebGui on OPNsense\Auth\Services\WebGui via OPNsense\Auth\Local`),
		nil, func(string) {})
	if !ok {
		t.Fatal("parseAudit returned ok=false for the first WebGUI failure backend line")
	}
	assertAttrs(t, rec1, map[string]string{
		"event":        "webgui_auth_backend",
		"audit.user":   "root",
		"audit.result": "failure",
	})
	if rec1.Severity != logship.SeverityDebug {
		t.Errorf("Severity = %v, want Debug (auth.debug, PRI 39)", rec1.Severity)
	}

	rec2, ok := parseAudit(auditEnv("audit", 4, 4, // <36> auth.warning
		`user root could not authenticate for WebGui. [using OPNsense\Auth\Services\WebGui + OPNsense\Auth\Local]`),
		nil, func(string) {})
	if !ok {
		t.Fatal("parseAudit returned ok=false for the second WebGUI failure backend line")
	}
	assertAttrs(t, rec2, map[string]string{
		"event":        "webgui_auth_backend",
		"audit.user":   "root",
		"audit.result": "failure",
	})
	if rec2.Severity != logship.SeverityWarn {
		t.Errorf("Severity = %v, want Warn (auth.warning, PRI 36)", rec2.Severity)
	}

	rec3, ok := parseAudit(auditEnv("audit", 4, 3, // <35> auth.err
		`/index.php: Web GUI authentication error for 'root' from 2001:db8:1f05::10be`),
		nil, func(string) {})
	if !ok {
		t.Fatal("parseAudit returned ok=false for the WebGUI failure index.php line")
	}
	assertAttrs(t, rec3, map[string]string{
		"event":        "webgui_login",
		"audit.user":   "root",
		"audit.result": "failure",
		"src.ip":       "2001:db8:1f05::10be",
	})
	if rec3.Severity != logship.SeverityError {
		t.Errorf("Severity = %v, want Error (auth.err, PRI 35)", rec3.Severity)
	}
	if got := rec3.Attributes["src.ip"]; got != "2001:db8:1f05::10be" {
		t.Fatalf("src.ip = %q, the IPv6 address must not be truncated by splitting on ':'", got)
	}
}

// TestParseAudit_WebGUILoginFailure_NoUserEnumeration: OPNsense's log output is
// BYTE-IDENTICAL in shape for an existing user with a wrong password (root, rob)
// and a user that does not exist at all (nouserlol) — captured live, 2026-08-04.
// This is not a parser gap: there is no "unknown user" branch to write, because
// the box gives no such signal (no user enumeration). Asserting identical
// treatment here pins that finding so a future reader does not go looking for a
// distinction that does not exist.
func TestParseAudit_WebGUILoginFailure_NoUserEnumeration(t *testing.T) {
	for _, user := range []string{"root", "rob", "nouserlol"} {
		t.Run(user, func(t *testing.T) {
			msg := `/index.php: Web GUI authentication error for '` + user + `' from 10.0.0.120`
			rec, ok := parseAudit(auditEnv("audit", 4, 3, msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseAudit returned ok=false for user %q", user)
			}
			assertAttrs(t, rec, map[string]string{
				"event":        "webgui_login",
				"audit.user":   user,
				"user.name":    user,
				"audit.result": "failure",
				"src.ip":       "10.0.0.120",
			})
		})
	}
}

// TestParseAudit_WebGUISessionExpired: "no active session, user not found" is a
// DIFFERENT event kind from a login attempt — no credentials were submitted,
// and no real username is known ("user not found" is never treated as a
// username). Modeled as its own event rather than folded into
// audit.result=failure, which would misrepresent an expired/absent session as a
// rejected login attempt.
func TestParseAudit_WebGUISessionExpired(t *testing.T) {
	const msg = `no active session, user not found (called "/ui/diagnostics/log/core/gateways" @ 10.0.0.120)`
	rec, ok := parseAudit(auditEnv("audit", 4, 5, msg), nil, func(string) {})
	if !ok {
		t.Fatal("parseAudit returned ok=false for the session-expiry line")
	}
	assertAttrs(t, rec, map[string]string{
		"event":          "webgui_session_expired",
		"audit.resource": "/ui/diagnostics/log/core/gateways",
		"src.ip":         "10.0.0.120",
	})
	assertNoAttrs(t, rec, "audit.user", "user.name", "audit.result")
}

// TestParseAudit_WebGUIUnrecognisedDegrades: near-miss lines that must NOT match
// any WebGUI branch, so BuildRecord ships them as generic records.
func TestParseAudit_WebGUIUnrecognisedDegrades(t *testing.T) {
	lines := []string{
		"user root authenticated unsuccessfully for WebGui",           // not a real phrase
		"user  authenticated successfully for WebGui",                 // empty user
		"user root authenticated successfully for SSH",                // not WebGui
		"/index.php: Successful login for user 'root'",                // no address
		`/index.php: Successful login for user root from: 10.0.0.120`, // unquoted user
		"no active session, user not found",                           // no parenthetical
		`no active session, user not found (called "/ui/x")`,          // no address
	}
	for _, line := range lines {
		if _, ok := parseAudit(auditEnv("audit", 4, 5, line), nil, func(string) {}); ok {
			t.Errorf("parseAudit(%q) = ok, want ok=false (degrade to generic)", line)
		}
	}
}
