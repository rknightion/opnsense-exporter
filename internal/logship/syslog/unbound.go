package syslog

import (
	"log/slog"
	"regexp"
	"time"

	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
	"github.com/rknightion/opnsense2otel/v5/internal/options"
)

// Unbound's local-zone query log (`log-local-actions: yes`), the dominant syslog
// line on a busy resolver — ~94% of all otherwise-unparsed volume on the live box
// (#332). Every shape here was taken verbatim from a camden capture, not guessed.
//
// Format:
//
//	[<pid>:<thread>] info: <local-zone> <zone-type> <client-ip>@<port> <qname> <qtype> <qclass>
//
// e.g.
//
//	[46775:2] info: example.com. transparent 10.0.0.141@51967 _ldap._tcp.dc._msdcs.example.com. SRV IN
//	[46775:0] info: 10.in-addr.arpa. typetransparent 127.0.0.1@7365 20.100.0.10.in-addr.arpa. PTR IN
//	[46775:1] info: example.com. transparent 2001:db8::105b@52824 lb._dns-sd._udp.example.com. PTR IN
//
// Attributes emitted:
//
//	dns.query_name    the queried name
//	dns.query_type    A | AAAA | PTR | SRV | TXT | SVCB | ...
//	dns.query_class   IN (always, in practice)
//	dns.local_zone    the matched local-zone name
//	dns.local_action  the zone type: transparent | typetransparent | static
//	src.ip / src.port the querying client, plus src.hostname / src.mac / src.scope
//	                  from enrichment
//
// The client address is enriched here rather than by BuildRecord's generic body
// scan, exactly like the other structured lanes: it is a positional field, not
// something to discover by scanning.
//
// Alongside the query log, this parser also structures the SERVFAIL error shape
// (below) and the DNSBL/blocklist subsystem + service lifecycle chatter (#631).
// Everything else unbound logs — the multi-line recursion-stats/histogram dump,
// unrecognized plugin status lines — returns ok=false and degrades to a generic
// record carrying the raw body, so a line is never dropped.
//
// The client is `(\S+)@(\d+)`: a single non-space token before the port, so an IPv6
// client (colons and all) is captured whole, and the greedy match locks onto the
// line's only `@<digits>` — the client's — never anything in the query name.
var reUnboundQuery = regexp.MustCompile(
	`^\[\d+:\d+\]\s+info:\s+(\S+)\s+(\S+)\s+(\S+)@(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$`)

// A resolution failure, the only other unbound shape worth structuring (#334).
//
// Captured verbatim:
//
//	[46775:9] error: SERVFAIL <api.ipify.org.saga-turtle.ts.net. AAAA IN>: all the configured stub or forward servers failed, at zone saga-turtle.ts.net. from 100.100.100.100 got SERVFAIL
//	[46775:6] error: SERVFAIL <res.dod.cdn.office.net. AAAA IN>: all the configured stub or forward servers failed, at zone . from 162.159.36.20 upstream server timeout
//
// The reason clause ("all the configured stub or forward servers failed") is
// constant boilerplate and dropped; the trailing detail ("got SERVFAIL" / "upstream
// server timeout") is the discriminating signal and kept as dns.error.
var reUnboundServfail = regexp.MustCompile(
	`^\[\d+:\d+\]\s+error:\s+SERVFAIL\s+<(\S+)\s+(\S+)\s+(\S+)>:\s+.*?,\s+at zone\s+(\S+)\s+from\s+(\S+)\s+(.*?)\s*$`)

// A cached negative answer being replayed rather than a live resolution failure
// (#641) — operationally different: this SERVFAIL never touched an upstream on
// this query, unbound is serving a prior failure straight out of the cache. The
// trailer is SHORTER than reUnboundServfail's, so a loosened live regex would
// blur the two signals together; this is its own branch instead.
//
// Captured verbatim:
//
//	[9284:5] error: SERVFAIL <wpad.saga-turtle.ts.net. A IN>: SERVFAIL in cache
//	[9284:6] error: SERVFAIL <wpad.saga-turtle.ts.net. AAAA IN>: SERVFAIL in cache
//
// dns.cached is the discriminator: present (and only present) on this shape, so
// a consumer can tell a cached SERVFAIL apart from a live one without having to
// know which regex an absent dns.error_zone/dns.upstream implies.
var reUnboundServfailCached = regexp.MustCompile(
	`^\[\d+:\d+\]\s+error:\s+SERVFAIL\s+<(\S+)\s+(\S+)\s+(\S+)>:\s+SERVFAIL in cache\s*$`)

// The DNSBL/blocklist subsystem (#631) — dnsbl_module status chatter plus the
// service lifecycle pair. This was originally left to fall through to a generic
// record; that call is reversed as of #631 because it turned out to be the
// single largest steady source of unparsed volume on the box (~1550 entries over
// 8 days: blocklist reload cycles logging thousands of times).
//
// Captured verbatim:
//
//	[48126:7] info: dnsbl_module: updating blocklist.
//	[48126:7] info: dnsbl_module: blocklist loaded. length is 509328
//	blocklist parsing done in 2.26 seconds (509328 records)
//	[10176:8] info: dnsbl_module: attempting to open pipe
//	[10176:7] info: dnsbl_module: successfully opened pipe
//	[10176:8] info: dnsbl_module: no logging backend found.
//	[92242:5] info: dnsbl_module: Logging backend closed connection. Closing pipe and continuing.
//	[10176:0] info: start of service (unbound 1.25.1).
//	[53465:0] info: service stopped (unbound 1.25.1).
//
// The "blocklist parsing done" line is the odd one out: every other line here
// carries the standard [pid:thread] prefix, this one never does (verified against
// the capture, not an oversight) — so its regex has no prefix and its record
// never carries unbound.thread.
//
// dnsbl.event is a CLOSED, code-defined vocabulary (blocklist_updating,
// blocklist_loaded, blocklist_parsed, pipe_opening, pipe_opened, pipe_closed,
// backend_missing); an unrecognized dnsbl_module line falls through to a generic
// record rather than inventing a catch-all event value. dnsbl.entries is the
// blocklist size and is emitted on both "blocklist loaded" and "blocklist parsing
// done" — they report the same quantity by two different routes, and a consumer
// should not have to know which line it came from.
//
// The pid ([48126:...]) is deliberately NOT captured: it changes on every unbound
// restart and carries no operational meaning. Only the thread number is kept, as
// unbound.thread.
//
// The remaining unbound chatter — the "server stats for thread N" / histogram /
// percentile / "average recursion processing time" block, "init module N:",
// "Closing logger", "Backgrounding unbound logging backend.", and "Database auto
// restore from ..." — is a multi-line statistics dump whose shape varies per
// thread and per build. Half-parsing one line of a multi-line report produces a
// record that looks complete but is not, so all of it deliberately keeps falling
// through to a generic record, exactly as sshd's non-auth chatter does — still
// shipped, never dropped.
var (
	reDnsblUpdating = regexp.MustCompile(
		`^\[\d+:(\d+)\]\s+info:\s+dnsbl_module:\s+updating blocklist\.\s*$`)
	reDnsblLoaded = regexp.MustCompile(
		`^\[\d+:(\d+)\]\s+info:\s+dnsbl_module:\s+blocklist loaded\. length is (\d+)\s*$`)
	reDnsblParsed = regexp.MustCompile(
		`^blocklist parsing done in ([\d.]+) seconds \((\d+) records\)\s*$`)
	reDnsblPipeOpening = regexp.MustCompile(
		`^\[\d+:(\d+)\]\s+info:\s+dnsbl_module:\s+attempting to open pipe\s*$`)
	reDnsblPipeOpened = regexp.MustCompile(
		`^\[\d+:(\d+)\]\s+info:\s+dnsbl_module:\s+successfully opened pipe\s*$`)
	reDnsblBackendMissing = regexp.MustCompile(
		`^\[\d+:(\d+)\]\s+info:\s+dnsbl_module:\s+no logging backend found\.\s*$`)
	reDnsblPipeClosed = regexp.MustCompile(
		`^\[\d+:(\d+)\]\s+info:\s+dnsbl_module:\s+Logging backend closed connection\. Closing pipe and continuing\.\s*$`)

	reUnboundServiceStarted = regexp.MustCompile(
		`^\[\d+:(\d+)\]\s+info:\s+start of service \(unbound ([\d.]+)\)\.\s*$`)
	reUnboundServiceStopped = regexp.MustCompile(
		`^\[\d+:(\d+)\]\s+info:\s+service stopped \(unbound ([\d.]+)\)\.\s*$`)
)

// The per-query log lines produced when `log-queries: yes` / `log-replies: yes`
// AND `log-tag-queryreply: yes` are all enabled on the resolver (#659). All three
// are a prerequisite: without log-tag-queryreply, unbound tags these lines
// `info:` instead of `query:`/`reply:` and they fall through undetected (they
// never collide with reUnboundQuery, which requires the `@<port>` local-actions
// shape) — see the frozen spec on #659 for the full prerequisite analysis.
//
// Format:
//
//	[<pid>:<thread>] query: <client> <qname> <qtype> <qclass>
//	[<pid>:<thread>] reply: <client> <qname> <qtype> <qclass> <rcode> <resolve_time> <from_cache> <size>[ on <proto> <ip> <port>]
//
// Captured verbatim (camden, capture-010.ndjson, 2026-08-07 16:24-17:19 local):
//
//	[96463:4] query: 127.0.0.1 www.tleechreload.org. A IN
//	[96463:9] query: 10.0.0.5 profiles-prod-023.grafana.net. AAAA IN
//	[96463:0] query: fd6b:d9cd:7613:4c33:301f:7ada:8457:a679 www.msftconnecttest.com. A IN
//	[96463:8] reply: 127.0.0.1 tvchaosuk.com. AAAA IN NOERROR 0.012482 0 90
//	[96463:0] reply: fd6b:d9cd:7613:4c33:301f:7ada:8457:a679 www.msftconnecttest.com. A IN NOERROR 0.010623 0 151
//	[96463:10] reply: 10.0.0.183 safebrowsing-proxy.g.aaplimg.com. HTTPS IN NOERROR 0.000000 1 110
//	[96463:5] reply: 10.0.0.199 _ldap._tcp.dc._msdcs.mgmt.rob-knight.net. SRV IN NXDOMAIN 0.000981 0 58
//
// The client is a raw IP always (no PTR substitution, unlike the poll lane, #660);
// an IPv6 client appears bare with no brackets and no port, so a single (\S+)
// captures either family whole.
//
// qname edge cases, from unbound's dname_str (util/data/dname.c:639), which both
// the query and reply lanes share, and which the capture cannot itself produce:
//
//   - root/empty dname -> "." (bare single dot)
//   - any byte outside [a-zA-Z0-9_*-] -> "?", one char only — the qname can never
//     contain whitespace, which is what makes (\S+) safe
//   - name >= LDNS_MAX_DOMAINLEN -> truncated + "&", NO trailing dot
//   - label > 63 bytes -> "#" alone, NO trailing dot
//
// A regex requiring a trailing "." on the qname is therefore wrong. qtype/qclass
// fall back to TYPE%d / CLASS%d for unrecognized values (util/net_help.c:586).
//
// The reply line has two shapes the capture never produced but upstream source
// confirms:
//
//   - FORMERR: `log_reply("%s - - - %s - - -%s", ...)` -> `<client> - - - FORMERR - - -`
//     (util/data/msgreply.c:1046) — still 8 tokens, but qname/qtype/qclass/
//     resolve_time/cached/size are all literal "-".
//   - null qname: qname_buf is the literal string "null" when qinf->qname is NULL
//     (msgreply.c:1058).
//
// And an optional trailing destination clause, appended only when
// `log-destaddr: yes` is also set (off by OPNsense's default template, but
// reachable via the GUI's custom options box): ` on <proto> <ip> <port>`.
//
// set() skips empty values (generic.go:106), so the "-" placeholders on a
// FORMERR line are mapped explicitly to empty via setOrDash below — otherwise a
// FORMERR line would ship dns.query_name="-" instead of an absent attribute.
//
// dns.cached reuses the existing key from reUnboundServfailCached
// (unbound.go:167) rather than minting dns.from_cache. dns.resolve_time_seconds
// is kept verbatim at 6dp, as on the wire — the poll lane reports milliseconds,
// and this must NOT be silently unit-converted to match it.
//
// These are two separate patterns, not one alternation: "query:" has no numeric
// trailer and "reply:" must never be allowed to match a bare 4-token line.
var reUnboundQueryLog = regexp.MustCompile(
	`^\[(\d+):(\d+)\] query: (\S+) (\S+) (\S+) (\S+)$`)

var reUnboundReplyLog = regexp.MustCompile(
	`^\[(\d+):(\d+)\] reply: (\S+) (\S+) (\S+) (\S+) (\S+) (\d+\.\d{6}|-) (\d+|-) (\d+|-)` +
		`(?: on (udp|tcp|dot|doh|unix|raw) (\S+) (\d+))?$`)

// reUnboundPerQueryTag is the cheap discriminator for "this is a per-query line at
// all", independent of whether the rest of it parses. It exists so the opt-in gate and
// the duplication warning key on the TAG rather than on a successful full match — a
// line that is unmistakably a query:/reply: record but whose body we fail to parse must
// still count as the route being active, or a future upstream field-order change would
// silently disable the guard.
//
// The `query:`/`reply:` tag only appears when log-tag-queryreply is on; without it
// unbound tags these lines `info:` and none of this matches, which is why that setting
// is a documented prerequisite rather than an optional extra.
var reUnboundPerQueryTag = regexp.MustCompile(`^\[\d+:\d+\] (?:query|reply): `)

func isUnboundPerQueryLine(msg string) bool {
	return reUnboundPerQueryTag.MatchString(msg)
}

// setOrDash sets k=v unless v is unbound's "-" placeholder (used throughout the
// FORMERR reply shape), in which case it does nothing — set() already skips
// empty values, but "-" is not empty and must be mapped explicitly or a FORMERR
// line ships literal "-" strings.
func setOrDash(set func(k, v string), k, v string) {
	if v == "-" {
		return
	}
	set(k, v)
}

func init() {
	RegisterParser(parseUnbound, "unbound")
}

// perQueryDupeWarn throttles the both-routes-active warning. The condition is a
// standing misconfiguration rather than an event, so it is re-reported every 15
// minutes for as long as it holds: a single startup warning scrolls away and the
// operator keeps paying twice, and the whole point of #659's guard is that a silently
// doubled per-query panel reads as a real number.
//
// The startup refusal in options.ValidateUnboundPerQueryRoutes catches the case where
// both EXPORTER flags are set. It cannot catch this one — the firewall may be sending
// query:/reply: lines with only the poll lane enabled here, which is invisible until a
// line actually arrives.
var perQueryDupeWarn = logship.NewLogLimiter(15*time.Minute, 4)

// Indirection over the two flags so tests can exercise the gate and the duplication
// warning without mutating process-global kingpin state (which would leak across
// tests). Production never reassigns these.
var (
	perQueryRouteEnabled = options.LogsSyslogUnboundPerQueryEnabled
	pollLaneEnabled      = options.LogsUnboundEnabled
)

// warnIfBothPerQueryRoutesActive reports the duplication the moment it is observable.
//
// Note the condition is "the firewall is sending per-query lines AND the poll lane is
// on", NOT "both flags are set". Unparsed lines still ship as generic records
// (source.go: "The line itself still ships"), so the second Loki record per query
// exists whether or not we structure it — which makes the flag irrelevant to whether
// the operator is being billed twice, and irrelevant to this warning.
func warnIfBothPerQueryRoutesActive(log *slog.Logger) {
	if !pollLaneEnabled() {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	if !perQueryDupeWarn.Allow("unbound-per-query-dupe") {
		return
	}
	log.Warn("both DNS per-query routes are active; every query is being shipped to Loki twice",
		"poll_lane", "--logs.unbound.enabled",
		"syslog_lane", "unbound log-queries/log-replies on the firewall",
		"impact", "per-query panels double-count; ~2 extra log lines per DNS query",
		"fix", "disable --logs.unbound.enabled, or turn off log-queries/log-replies on the firewall")
}

func parseUnbound(env Envelope, snap *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	// The per-query route (#659) is opt-in. When it is off these lines fall through to
	// a generic record exactly as they did before the parser existed — they are NOT
	// dropped, because an unparsed line still ships and silently discarding data is a
	// thing this pipeline does not do. The flag therefore buys STRUCTURE, not volume:
	// the ~2 log lines per query are the firewall's doing and arrive either way.
	//
	// The warning fires regardless of the flag, because being billed twice does not
	// depend on whether we parsed the line.
	if isUnboundPerQueryLine(env.Message) {
		warnIfBothPerQueryRoutesActive(nil)
		if !perQueryRouteEnabled() {
			return logship.Record{}, false
		}
	}

	if m := reUnboundReplyLog.FindStringSubmatch(env.Message); m != nil {
		thread := m[2]
		ip := m[3]
		qname, qtype, qclass := m[4], m[5], m[6]
		rcode := m[7]
		resolveTime, cached, size := m[8], m[9], m[10]

		rec, set := newRecord(env)
		set("dns.event", "reply")
		setOrDash(set, "dns.query_name", qname)
		setOrDash(set, "dns.query_type", qtype)
		setOrDash(set, "dns.query_class", qclass)
		setOrDash(set, "dns.rcode", rcode)
		setOrDash(set, "dns.resolve_time_seconds", resolveTime)
		switch cached {
		case "1":
			set("dns.cached", "true")
		case "0":
			set("dns.cached", "false")
		}
		setOrDash(set, "dns.response_size_bytes", size)
		set("src.ip", ip)
		set("unbound.thread", thread)
		enrichEndpoint(set, snap, "src", ip, "", "")

		if len(m) > 13 && m[11] != "" {
			set("net.transport", m[11])
			set("dst.ip", m[12])
			set("dst.port", m[13])
		}

		return rec, true
	}

	if m := reUnboundQueryLog.FindStringSubmatch(env.Message); m != nil {
		thread := m[2]
		ip := m[3]
		qname, qtype, qclass := m[4], m[5], m[6]

		rec, set := newRecord(env)
		set("dns.event", "query")
		set("dns.query_name", qname)
		set("dns.query_type", qtype)
		set("dns.query_class", qclass)
		set("src.ip", ip)
		set("unbound.thread", thread)
		enrichEndpoint(set, snap, "src", ip, "", "")

		return rec, true
	}

	if m := reUnboundServfail.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("dns.query_name", m[1])
		set("dns.query_type", m[2])
		set("dns.query_class", m[3])
		set("dns.rcode", "SERVFAIL")
		set("dns.error_zone", m[4])
		set("dns.upstream", m[5])
		set("dns.error", m[6])
		return rec, true
	}

	if m := reUnboundServfailCached.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("dns.query_name", m[1])
		set("dns.query_type", m[2])
		set("dns.query_class", m[3])
		set("dns.rcode", "SERVFAIL")
		set("dns.cached", "true")
		return rec, true
	}

	if m := reUnboundQuery.FindStringSubmatch(env.Message); m != nil {
		localZone, zoneType := m[1], m[2]
		ip, port := m[3], m[4]
		qname, qtype, qclass := m[5], m[6], m[7]

		rec, set := newRecord(env)
		set("dns.query_name", qname)
		set("dns.query_type", qtype)
		set("dns.query_class", qclass)
		set("dns.local_zone", localZone)
		set("dns.local_action", zoneType)
		set("src.ip", ip)
		set("src.port", port)

		// Best-effort client enrichment. An unknown client is normal (a device
		// that has never held a lease, or unbound's own loopback reverse
		// lookups from 127.0.0.1), so a miss is silent and NEVER signals a
		// stale snapshot. Empty port+proto skips the service lookup: a
		// resolver client's ephemeral source port names no service.
		enrichEndpoint(set, snap, "src", ip, "", "")

		return rec, true
	}

	if m := reDnsblUpdating.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("dnsbl.event", "blocklist_updating")
		set("unbound.thread", m[1])
		return rec, true
	}
	if m := reDnsblLoaded.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("dnsbl.event", "blocklist_loaded")
		set("dnsbl.entries", m[2])
		set("unbound.thread", m[1])
		return rec, true
	}
	if m := reDnsblParsed.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("dnsbl.event", "blocklist_parsed")
		set("dnsbl.parse_duration_seconds", m[1])
		set("dnsbl.entries", m[2])
		return rec, true
	}
	if m := reDnsblPipeOpening.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("dnsbl.event", "pipe_opening")
		set("unbound.thread", m[1])
		return rec, true
	}
	if m := reDnsblPipeOpened.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("dnsbl.event", "pipe_opened")
		set("unbound.thread", m[1])
		return rec, true
	}
	if m := reDnsblBackendMissing.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("dnsbl.event", "backend_missing")
		set("unbound.thread", m[1])
		return rec, true
	}
	if m := reDnsblPipeClosed.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("dnsbl.event", "pipe_closed")
		set("unbound.thread", m[1])
		return rec, true
	}

	if m := reUnboundServiceStarted.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("dns.event", "service_started")
		set("dns.version", m[2])
		set("unbound.thread", m[1])
		return rec, true
	}
	if m := reUnboundServiceStopped.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("dns.event", "service_stopped")
		set("dns.version", m[2])
		set("unbound.thread", m[1])
		return rec, true
	}

	return logship.Record{}, false
}
