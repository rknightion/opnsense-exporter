package syslog

import (
	"net/netip"
	"sync"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// Parser turns one program's message into structured attributes. It returns
// ok=false when the line does not match any shape it knows, in which case the
// caller degrades to a generic record carrying the raw body.
//
// A parser NEVER drops a record and NEVER panics: an OPNsense box emits malformed
// rows in practice (pf's own header parse degrades on truncated packets), and a
// receiver that discards what it cannot understand is worse than useless.
//
// `miss` reports an enrichment lookup miss for a named table. Call it ONLY for
// lookups whose failure means the snapshot is stale (an unknown firewall rule id).
// Never call it for an address that simply is not ours — an unknown WAN IP is
// normal, not a cache problem.
type Parser func(env Envelope, snap *enrich.Snapshot, miss func(table string)) (logship.Record, bool)

// parsers maps a syslog program (app-name) to its parser. Each parser lane
// registers itself from an init() in its own file, mirroring the collector and
// log-source registration idiom used elsewhere in this repo — so adding a program
// means adding one file, and no two lanes ever contend for a shared dispatch
// table.
var parsers = map[string]Parser{}

// parserPrefixes maps a program-name PREFIX to its parser, for the families whose
// program name is not a fixed string. OpenVPN is the reason it exists: OPNsense
// names one syslog program per configured instance — openvpn_server40,
// openvpn_client2 — so an exact-match table can never reach any of them, exactly
// as subsystemFor already had to special-case (#406).
//
// Deliberately separate from `parsers` rather than folded into it: prefix matching
// is a fallback, and a table that mixes the two makes "which registration won"
// unanswerable by reading the call sites.
var parserPrefixes = map[string]Parser{}

// bodyEnrichedPrograms and bodyEnrichedPrefixes are the NARROW opt-in list of
// parsers that keep the generic body scan (enrichMessage) instead of the
// parsed-record default of skipping it.
//
// The default exists because a parser that already emitted its own POSITIONAL
// addresses would otherwise emit them a second time under peer.* — filterlog's
// src.*/dst.* is the case it was written for, and that double-emit hazard is real
// and must not be reintroduced. But the rationale is about parsers that extract
// addresses, and charon/openvpn extract NONE: their whole contract is
// backend/event/result. Suppressing the scan for them would silently drop the
// peer.* attributes those programs' lines have carried since #250, the moment their
// parsers start matching — an operator-visible regression in any existing Loki query,
// with no double-emit being prevented in exchange.
//
// So this is opt-in, not a changed default: no existing parser's behaviour moves.
// A parser belongs here ONLY if it emits no positional address of its own.
var (
	bodyEnrichedPrograms = map[string]bool{}
	bodyEnrichedPrefixes = map[string]bool{}
)

// RegisterParser binds a parser to one or more program names. Panics on a
// duplicate registration: two parsers claiming the same program is a programming
// error that must surface at startup, not silently let one win.
func RegisterParser(p Parser, programs ...string) {
	for _, prog := range programs {
		if _, dup := parsers[prog]; dup {
			panic("syslog: duplicate parser registered for program " + prog)
		}
		parsers[prog] = p
	}
}

// RegisterParserPrefix binds a parser to every program name starting with one of
// the given prefixes. Panics on a duplicate prefix, mirroring RegisterParser, and
// on an empty prefix — an empty string is a prefix of everything, so it would
// silently claim every unparsed program on the box.
func RegisterParserPrefix(p Parser, prefixes ...string) {
	for _, prefix := range prefixes {
		if prefix == "" {
			panic("syslog: parser registered for an empty program prefix")
		}
		if _, dup := parserPrefixes[prefix]; dup {
			panic("syslog: duplicate parser registered for program prefix " + prefix)
		}
		parserPrefixes[prefix] = p
	}
}

// RegisterParserWithBodyEnrichment is RegisterParser for a parser that extracts NO
// positional address of its own and therefore keeps the generic body scan. See
// bodyEnrichedPrograms for why that is opt-in rather than the default.
func RegisterParserWithBodyEnrichment(p Parser, programs ...string) {
	RegisterParser(p, programs...)
	for _, prog := range programs {
		bodyEnrichedPrograms[prog] = true
	}
}

// RegisterParserPrefixWithBodyEnrichment is RegisterParserPrefix for a parser that
// extracts no positional address of its own. Same opt-in, for dynamic program names.
func RegisterParserPrefixWithBodyEnrichment(p Parser, prefixes ...string) {
	RegisterParserPrefix(p, prefixes...)
	for _, prefix := range prefixes {
		bodyEnrichedPrefixes[prefix] = true
	}
}

// parserFor returns the parser for a program, if any.
//
// An EXACT registration always wins; only then do the prefixes get a look, and
// among those the LONGEST match wins. Longest-match is what makes dispatch
// deterministic: Go randomises map iteration, so "first prefix that matches" would
// pick differently between runs the moment two prefixes overlap.
func parserFor(program string) (Parser, bool) {
	if p, ok := parsers[program]; ok {
		return p, true
	}
	_, p, ok := longestPrefixMatch(parserPrefixes, program)
	return p, ok
}

// parserEnrichesBody reports whether the parser that ACTUALLY HANDLES program opted
// in to the generic body scan.
//
// It resolves through the dispatch tables (`parsers`, `parserPrefixes`) and only then
// asks the opt-in tables, rather than prefix-matching the opt-in table directly. That
// is not a stylistic choice — the direct version is WRONG and a test caught it: with
// an opted prefix "testprog" and a plain exact "testprog_exact", the exact parser wins
// dispatch while the opt-in table's prefix still matched, so a parser that owns its
// own addresses would have been handed body enrichment it never asked for. The same
// trap exists between a short opted prefix and a longer plain one. Resolving the
// WINNER first and then asking about it cannot diverge from dispatch.
func parserEnrichesBody(program string) bool {
	if _, exact := parsers[program]; exact {
		return bodyEnrichedPrograms[program]
	}
	prefix, _, ok := longestPrefixMatch(parserPrefixes, program)
	return ok && bodyEnrichedPrefixes[prefix]
}

// longestPrefixMatch returns the KEY and value of the entry whose key is the longest
// prefix of s.
//
// One helper rather than copies of the loop: parserFor, parserEnrichesBody and
// deriveFamily must all resolve a dynamic program name the SAME way, and separate
// hand-rolled loops are separate chances for one of them to disagree with the others —
// which would route a line to a parser while denying it a family or a body scan. It
// returns the key as well as the value precisely so a caller can resolve the winner in
// the dispatch table and then look THAT up in a side table.
func longestPrefixMatch[T any](table map[string]T, s string) (string, T, bool) {
	var (
		bestKey string
		best    T
		bestN   int
	)
	for prefix, v := range table {
		if len(prefix) > bestN && hasPrefix(s, prefix) {
			bestKey, best, bestN = prefix, v, len(prefix)
		}
	}
	return bestKey, best, bestN > 0
}

// subsystems maps a program to a coarse subsystem, so a Loki query can select
// "everything DHCP" without enumerating the three backends that might be serving
// it, or "everything auth" without knowing whether sshd renamed itself again.
//
// This is deliberately coarse and low-cardinality. It is a routing aid, not a
// taxonomy.
var subsystems = map[string]string{
	"filterlog":      "firewall",
	"firewall":       "firewall",
	"pf":             "firewall",
	"audit":          "audit",
	"configd.py":     "audit",
	"configd":        "audit",
	"sshd":           "auth",
	"sshd-session":   "auth",
	"su":             "auth",
	"sudo":           "auth",
	"radiusd":        "auth",
	"unbound":        "dns",
	"dnsmasq":        "dns",
	"dnsmasq-dhcp":   "dhcp",
	"kea-dhcp4":      "dhcp",
	"kea-dhcp6":      "dhcp",
	"kea-ctrl-agent": "dhcp",
	"kea-dhcp-ddns":  "dhcp",
	"dhcpd":          "dhcp",
	"dhcrelay":       "dhcp",
	"dhcp6c":         "dhcp",
	// dhclient is the WAN DHCP CLIENT, not a server. It shares the coarse `dhcp`
	// subsystem because this map is a Loki routing aid rather than a taxonomy —
	// "everything DHCP" should reach it — and its records are told apart from the
	// server families by their dhcp_client.* attributes, not by the subsystem (#541).
	// Before this entry existed its lines shipped with a BLANK subsystem.
	"dhclient":        "dhcp",
	"radvd":           "dhcp",
	"charon":          "ipsec",
	"openvpn":         "vpn",
	"wireguard":       "vpn",
	"netbird":         "vpn",
	"tailscaled":      "vpn",
	"suricata":        "ids",
	"crowdsec":        "ids",
	"haproxy":         "proxy",
	"nginx":           "proxy",
	"relayd":          "proxy",
	"lighttpd":        "proxy",
	"bgpd":            "routing",
	"ospfd":           "routing",
	"ospf6d":          "routing",
	"ripd":            "routing",
	"zebra":           "routing",
	"staticd":         "routing",
	"dpinger":         "gateways",
	"upsmon":          "ups",
	"upsd":            "ups",
	"apcupsd":         "ups",
	"monit":           "monitoring",
	"ntpd":            "ntp",
	"chronyd":         "ntp",
	"clamd":           "antivirus",
	"freshclam":       "antivirus",
	"captiveportal":   "captiveportal",
	"pkg":             "packages",
	"pkg-static":      "packages",
	"cron":            "cron",
	"/usr/sbin/cron":  "cron",
	"syslog-ng":       "logging",
	"kernel":          "kernel",
	"acme.sh":         "certificates",
	"squid":           "proxy",
	"miniupnpd":       "upnp",
	"unbound-control": "dns",
}

// subsystemFor maps a program to its subsystem. OpenVPN instances arrive as
// openvpn_server1 / openvpn_client2 (one program name per configured instance),
// so an exact-match table alone would miss every one of them; the prefix check
// catches the whole family.
func subsystemFor(program string) string {
	if s, ok := subsystems[program]; ok {
		return s
	}
	switch {
	case hasPrefix(program, "openvpn"):
		return "vpn"
	case hasPrefix(program, "kea-"):
		return "dhcp"
	case hasPrefix(program, "wg"):
		return "vpn"
	}
	return ""
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// ProgramProcessor gets first refusal on a line whose program it Handles(). When it
// returns handled=true it has fully processed the line (built, counted and emitted
// on its own), so the generic dispatch is skipped. peer is the sender address (for
// self-traffic recognition); ports are the receiver's bound listen ports.
type ProgramProcessor interface {
	Handles(program string) bool
	Process(env Envelope, peer netip.Addr, ports []int, emit func(logship.Record)) (handled bool)
	// EmittedSource is the `source` value this processor stamps on the records it emits
	// (via Record.Source), so the pipeline can pre-initialise that source's metrics.
	EmittedSource() string
}

// programProcessor is the single stateful, config-built processor registered by a
// consumer (e.g. the zenarmor package), guarded by programProcessorMu.
//
// It is package-global on purpose, not per-source: this is deliberately NOT
// multi-firewall-in-one-process support (#401), just lifecycle hardening around
// the existing single-processor design. Production builds it once, from the
// zenarmor push-source factory.
var (
	programProcessorMu sync.RWMutex
	programProcessor   ProgramProcessor
)

// RegisterProgramProcessor installs the single stateful, config-built processor,
// REPLACING whatever was registered before it. Called from a source factory (not
// an init), so it may carry runtime config.
//
// A second call no longer panics (changed by #401). It used to: at the time, two
// registrations in one process could only mean two factories racing to claim the
// same slot, a wiring bug that had to surface at startup. That stopped being true
// once a rebuild — a test constructing the pipeline twice, or a future in-process
// reload — became a normal, expected event; a rebuild-safe registry has to let a
// later build's registration cleanly replace an earlier one instead of aborting
// the process. Nothing from the replaced processor survives: the very next
// registeredProgramProcessor call sees only the new one.
func RegisterProgramProcessor(p ProgramProcessor) {
	programProcessorMu.Lock()
	defer programProcessorMu.Unlock()
	programProcessor = p
}

// ResetProgramProcessor clears any registered processor. It exists so a caller
// with a well-defined rebuild boundary (a test tearing down between cases, or a
// future graceful shutdown/reload path) can leave the registry exactly as it
// found it, rather than relying on the next RegisterProgramProcessor call to
// overwrite a leftover registration. Safe to call when nothing is registered.
func ResetProgramProcessor() {
	programProcessorMu.Lock()
	defer programProcessorMu.Unlock()
	programProcessor = nil
}

// registeredProgramProcessor returns the registered processor, if any. Safe for
// concurrent use with RegisterProgramProcessor and ResetProgramProcessor from any
// number of goroutines.
func registeredProgramProcessor() ProgramProcessor {
	programProcessorMu.RLock()
	defer programProcessorMu.RUnlock()
	return programProcessor
}
