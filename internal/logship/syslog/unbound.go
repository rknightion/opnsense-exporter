package syslog

import (
	"regexp"

	"github.com/rknightion/opnsense2otel/v4/internal/logship"
	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
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

func init() {
	RegisterParser(parseUnbound, "unbound")
}

func parseUnbound(env Envelope, snap *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
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
