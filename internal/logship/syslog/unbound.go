package syslog

import (
	"regexp"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
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
//	[46775:2] info: rob-knight.net. transparent 10.0.0.141@51967 _ldap._tcp.dc._msdcs.rob-knight.net. SRV IN
//	[46775:0] info: 10.in-addr.arpa. typetransparent 127.0.0.1@7365 20.100.0.10.in-addr.arpa. PTR IN
//	[46775:1] info: rob-knight.net. transparent 2001:8b0:1f05::105b@52824 lb._dns-sd._udp.rob-knight.net. PTR IN
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
// Only the local-action query log is parsed. Everything else unbound logs —
// SERVFAIL/error lines, startup and cache chatter — returns ok=false and degrades
// to a generic record carrying the raw body, so a line is never dropped.
//
// The client is `(\S+)@(\d+)`: a single non-space token before the port, so an IPv6
// client (colons and all) is captured whole, and the greedy match locks onto the
// line's only `@<digits>` — the client's — never anything in the query name.
var reUnboundQuery = regexp.MustCompile(
	`^\[\d+:\d+\]\s+info:\s+(\S+)\s+(\S+)\s+(\S+)@(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$`)

func init() {
	RegisterParser(parseUnbound, "unbound")
}

func parseUnbound(env Envelope, snap *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	m := reUnboundQuery.FindStringSubmatch(env.Message)
	if m == nil {
		return logship.Record{}, false
	}
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

	// Best-effort client enrichment. An unknown client is normal (a device that has
	// never held a lease, or unbound's own loopback reverse lookups from 127.0.0.1),
	// so a miss is silent and NEVER signals a stale snapshot. Empty port+proto skips
	// the service lookup: a resolver client's ephemeral source port names no service.
	enrichEndpoint(set, snap, "src", ip, "", "")

	return rec, true
}
