package syslog

import (
	"regexp"
	"strings"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
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
)

func init() {
	RegisterParser(parseAudit, "audit", "configd.py")
}

// parseAudit parses OPNsense's config-change audit trail and configd's
// authorisation/RPC lines. The snapshot is unused — this lane performs no
// enrichment lookups, so it never calls miss(), which is reserved for lookups
// whose failure means the enrichment snapshot is stale.
//
// It returns ok=false for any line matching none of the three shapes, so the
// caller degrades it to a generic record carrying the raw body. It never drops a
// line and never panics.
func parseAudit(env Envelope, _ *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
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

	return logship.Record{}, false
}
