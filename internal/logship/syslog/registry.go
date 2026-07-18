package syslog

import (
	"net/netip"

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

// parserFor returns the parser for a program, if any.
func parserFor(program string) (Parser, bool) {
	p, ok := parsers[program]
	return p, ok
}

// subsystems maps a program to a coarse subsystem, so a Loki query can select
// "everything DHCP" without enumerating the three backends that might be serving
// it, or "everything auth" without knowing whether sshd renamed itself again.
//
// This is deliberately coarse and low-cardinality. It is a routing aid, not a
// taxonomy.
var subsystems = map[string]string{
	"filterlog":       "firewall",
	"firewall":        "firewall",
	"pf":              "firewall",
	"audit":           "audit",
	"configd.py":      "audit",
	"configd":         "audit",
	"sshd":            "auth",
	"sshd-session":    "auth",
	"su":              "auth",
	"sudo":            "auth",
	"unbound":         "dns",
	"dnsmasq":         "dns",
	"kea-dhcp4":       "dhcp",
	"kea-dhcp6":       "dhcp",
	"kea-ctrl-agent":  "dhcp",
	"kea-dhcp-ddns":   "dhcp",
	"dhcpd":           "dhcp",
	"dhcrelay":        "dhcp",
	"dhcp6c":          "dhcp",
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
}

// programProcessor is the single stateful, config-built processor registered by a
// consumer (e.g. the zenarmor package). At most one may be registered; a second
// registration is a wiring bug that must surface at startup.
var programProcessor ProgramProcessor

// RegisterProgramProcessor installs the single stateful, config-built processor.
// Called from a source factory (not an init), so it may carry runtime config.
func RegisterProgramProcessor(p ProgramProcessor) {
	if programProcessor != nil {
		panic("syslog: duplicate ProgramProcessor registration")
	}
	programProcessor = p
}

// registeredProgramProcessor returns the registered processor, if any.
func registeredProgramProcessor() ProgramProcessor { return programProcessor }
