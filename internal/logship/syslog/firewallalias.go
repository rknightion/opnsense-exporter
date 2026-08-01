package syslog

import (
	"regexp"

	"github.com/rknightion/opnsense2otel/v4/internal/logship"
	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
)

// firewallalias parses OPNsense's alias/table maintenance logger (#631).
//
// THE APP-NAME HERE IS `firewall`, AND THAT NAME INVITES THE WRONG GUESS: this
// is NOT packet filtering. Packet-filter decisions are logged by pf itself and
// already parsed by filterlog.go under the program `filterlog`. This program
// is filter_alias / update_alias's own logger — DNS-hostname alias resolution,
// URL-table alias fetches, and the GeoIP database refresh. Confirm the
// registry split before touching either file: registry.go maps both
// `filterlog` and `firewall` onto the `firewall` subsystem label, but only one
// program name (`firewall`) reaches this parser.
//
// Every shape below is a verbatim capture from a real box, taken from 8 days
// of production log traffic:
//
//	resolving 4 hostnames (24 addresses) for acme_dns took 0.01 seconds       (624 occurrences)
//	resolving 24 hostnames (60 addresses) for overaaisp took 0.03 seconds     (616 occurrences)
//	resolving 5 hostnames (8 addresses) for meraki_IPs_Core_web took 0.08 seconds (163 occurrences)
//	fetch alias url https://allowlists.grafana.com/synthetics (bytes: 12921)  (164 occurrences)
//	fetch alias url https://ip-ranges.amazonaws.com/ip-ranges.json (bytes: 2529294)
//	fetch alias url https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv6.txt (lines: 1283)
//	fetch alias url https://uptimerobot.com/inc/files/ips/IPv4.txt (lines: 103)
//	processing alias url https://allowlists.grafana.com/synthetics took 0.00s (163 occurrences)
//	processing alias url https://ip-ranges.amazonaws.com/ip-ranges.json took 0.14s
//	processing alias url https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv6.txt took 0.02s
//	processing alias url https://uptimerobot.com/inc/files/ips/IPv4.txt took 0.00s
//	found .zip format, process                                                (6 occurrences)
//	geoip updated (files: 502 lines: 1111384)                                 (6 occurrences)
//
// THE DURATION SUFFIX DIFFERS BY GRAMMAR, AND THAT IS DELIBERATE, NOT A TYPO:
// `resolving ... took <d> seconds` (a space, the full word) is the DNS
// resolver's own logging; `processing alias url ... took <d>s` (no space, a
// bare `s` unit) is the URL-table fetch/parse timer. Getting the two patterns
// swapped is the obvious bug here, which is why a dedicated test
// (TestFirewallAliasCapturedLines' "processing alias url - aws" case) pins the
// `0.14s` shape byte-for-byte against a "took 0.08 seconds" sibling.
//
// THE fetch GRAMMAR REPORTS EITHER A BYTE COUNT OR A LINE COUNT, NEVER BOTH,
// depending on whether the alias URL served a raw byte-count-tracked payload
// or a line-oriented text list; the two counters are mutually exclusive on
// the wire, and the parser only emits whichever one the line actually
// carried (`newRecord`'s `set` already drops empty values, and the
// bytes/lines regexes are alternatives, so only one ever fires per line).
//
// alias.url IS A BOUNDED, OPERATOR-CONFIGURED VALUE. It is structured log
// metadata, not a Prometheus label, so it carries no cardinality-blowup risk
// the way a metric label would; it is emitted in full, never truncated.
var (
	// `resolving <hostnames> hostnames (<addresses> addresses) for <alias> took <duration> seconds`.
	// The alias name is a user-configured string (could contain almost any
	// non-whitespace token an operator picked), so it is captured as `\S+`
	// rather than a narrower charset.
	reFirewallAliasResolved = regexp.MustCompile(`^resolving (\d+) hostnames \((\d+) addresses\) for (\S+) took ([0-9]+(?:\.[0-9]+)?) seconds$`)

	// `fetch alias url <url> (bytes: <n>)` and `fetch alias url <url> (lines: <n>)`
	// are the same grammar reporting two different counters depending on the
	// fetched payload's shape. Kept as two patterns (not one with an
	// alternation group over the label) so each capture group is unambiguous
	// about which counter it holds.
	reFirewallAliasFetchedBytes = regexp.MustCompile(`^fetch alias url (\S+) \(bytes: (\d+)\)$`)
	reFirewallAliasFetchedLines = regexp.MustCompile(`^fetch alias url (\S+) \(lines: (\d+)\)$`)

	// `processing alias url <url> took <duration>s` — note the trailing `s` is
	// NOT preceded by a space, unlike the `resolving ... took <d> seconds`
	// grammar above. See the doc comment for why this distinction matters.
	reFirewallAliasProcessed = regexp.MustCompile(`^processing alias url (\S+) took ([0-9]+(?:\.[0-9]+)?)s$`)

	// `geoip updated (files: <n> lines: <m>)` — the plugin's periodic GeoIP
	// database refresh.
	reFirewallAliasGeoIPUpdated = regexp.MustCompile(`^geoip updated \(files: (\d+) lines: (\d+)\)$`)

	// `found .zip format, process` carries no data of its own: it is logged
	// once per URL-table alias whose fetched payload turned out to be a zip
	// archive, immediately before that archive is unpacked. Parsed as a plain
	// event so it stops landing in the unparsed-line capture, per #631.
	reFirewallAliasArchiveDetected = regexp.MustCompile(`^found \.zip format, process$`)
)

func init() {
	RegisterParser(parseFirewallAlias, "firewall")
}

func parseFirewallAlias(env Envelope, _ *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	if m := reFirewallAliasResolved.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("alias.event", "resolved")
		set("alias.name", m[3])
		set("alias.hostnames", m[1])
		set("alias.addresses", m[2])
		set("alias.duration_seconds", m[4])
		return rec, true
	}
	if m := reFirewallAliasFetchedBytes.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("alias.event", "fetched")
		set("alias.url", m[1])
		set("alias.bytes", m[2])
		return rec, true
	}
	if m := reFirewallAliasFetchedLines.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("alias.event", "fetched")
		set("alias.url", m[1])
		set("alias.lines", m[2])
		return rec, true
	}
	if m := reFirewallAliasProcessed.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("alias.event", "processed")
		set("alias.url", m[1])
		set("alias.duration_seconds", m[2])
		return rec, true
	}
	if m := reFirewallAliasGeoIPUpdated.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("alias.event", "geoip_updated")
		set("geoip.files", m[1])
		set("geoip.lines", m[2])
		return rec, true
	}
	if reFirewallAliasArchiveDetected.MatchString(env.Message) {
		rec, set := newRecord(env)
		set("alias.event", "archive_detected")
		return rec, true
	}
	// Anything else on the firewall program degrades to a generic record,
	// carrying the body verbatim — never a drop.
	return logship.Record{}, false
}
