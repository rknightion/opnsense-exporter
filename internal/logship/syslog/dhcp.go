package syslog

import (
	"net/netip"
	"regexp"
	"strings"

	"github.com/rknightion/opnsense2otel/v4/internal/logship"
	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
)

// DHCP lease events, normalised across the three backends an OPNsense box might
// be running. A lease *gauge* tells you a lease exists; a lease *event* tells you
// when the device appeared. Whichever backend serves the box, the record carries
// the same attributes, so a query for "which device joined my network, and when"
// does not have to know which one it is:
//
//	dhcp.action  discover|offer|request|ack|nak|release|expire|alloc|reuse
//	dhcp.ip, dhcp.mac, dhcp.hostname, dhcp.lease_seconds
//	interface (raw device) + interface.name (resolved)
//
// The three wire formats (all captured verbatim from a live 26.7 box):
//
//	ISC dhcpd   DHCPACK on 172.16.30.100 to bc:24:11:eb:db:3d (exporter-traffgen) via vlan02
//	dnsmasq     DHCPACK(vlan01) 172.16.20.117 bc:24:11:3c:79:6b exporter-traffgen
//	Kea         DHCP4_LEASE_ALLOC [hwtype=1 bc:24:11:a5:a6:34], cid=[no info], tid=0x8a1b2c3d: lease 172.16.9.100 has been allocated for 4000 s
//
// These programs also emit plenty that is NOT a lease event — Kea's
// COMMAND_RECEIVED control-plane chatter, dnsmasq's DNS query log, dhcpd's
// housekeeping. Those return ok=false and ship as generic records, verbatim.
func init() {
	// dnsmasq-dhcp is dnsmasq's DHCP-server program name (distinct from the DNS-side
	// "dnsmasq"); its DHCPREQUEST/DHCPACK lines are the same wire shape dnsmasqLineRE
	// already handles, so registering the name is the whole change.
	RegisterParser(parseDHCP, "dhcpd", "dnsmasq", "dnsmasq-dhcp", "kea-dhcp4", "kea-dhcp6", "dhcrelay")
}

// iscActions is the allowlist of DHCP message types we normalise from the
// ISC/dnsmasq wire words. It is an allowlist on purpose: an unknown verb is a
// shape we have not seen on a real box, and guessing at it is how parsers start
// lying. Anything not here degrades to a generic record.
var iscActions = map[string]string{
	"DHCPDISCOVER": "discover",
	"DHCPOFFER":    "offer",
	"DHCPREQUEST":  "request",
	"DHCPACK":      "ack",
	"DHCPNAK":      "nak",
	"DHCPRELEASE":  "release",
	"DHCPEXPIRE":   "expire",
	// DHCPDECLINE/DHCPINFORM (#641) already matched dnsmasqLineRE and fell through
	// only because this allowlist did not name them — verified against the parser
	// on a live capture, not assumed from the tracking issue.
	"DHCPDECLINE": "decline",
	"DHCPINFORM":  "inform",
}

// keaActions maps the tail of a Kea DHCP{4,6}_LEASE_* message id onto the same
// action vocabulary.
var keaActions = map[string]string{
	"ALLOC":  "alloc",
	"OFFER":  "offer",
	"REUSE":  "reuse",
	"RENEW":  "request",
	"EXPIRE": "expire",
	// ADVERT (#641) is DHCP6_LEASE_ADVERT — the DHCPv6 server's response to a
	// SOLICIT, the v6 counterpart of a v4 OFFER, named "advertise" rather than
	// reusing "offer" so the two backends stay distinguishable. The highest-volume
	// of the #641 gaps (41-125/day on the live box).
	"ADVERT": "advertise",
}

var (
	// dnsmasqLineRE matches "DHCPACK(vlan01) 172.16.20.117 bc:… hostname": the
	// interface is welded onto the action word in parentheses.
	dnsmasqLineRE = regexp.MustCompile(`^(DHCP[A-Z]+)\(([^)]*)\)\s*(.*)$`)

	// dnsmasqConflictRE matches dnsmasq refusing to register a DHCP client's requested
	// name because a static host entry already claims it: "not giving name
	// <name> to the DHCP lease of <ip> because the name exists in …". A real recurring
	// naming misconfiguration, worth surfacing as a name_conflict event.
	dnsmasqConflictRE = regexp.MustCompile(`^not giving name (\S+) to the DHCP lease of (\S+)`)

	// dnsmasqAbandonRE matches dnsmasq's standalone "abandoning lease to <mac> of
	// <ip>" line (#641) — a distinct sentence, not the parenthesized
	// DHCP<VERB>(iface) shape dnsmasqLineRE handles. Signals an address conflict,
	// the same operational event a DHCPDECLINE from the client reports; captured on
	// a live box 2 seconds after the matching DHCPDECLINE, same MAC/IP/pid. This
	// parser does not attempt to correlate the pair — that is a downstream question.
	dnsmasqAbandonRE = regexp.MustCompile(`^abandoning lease to (\S+) of (\S+)`)

	macRE = regexp.MustCompile(`^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`)

	// keaLevelRE / keaLoggerRE strip the optional leading level word and
	// "[logger.0xPTR]" prefix Kea puts on some shapes.
	keaLevelRE  = regexp.MustCompile(`^(?:INFO|WARN|WARNING|ERROR|FATAL|DEBUG)\s+`)
	keaLoggerRE = regexp.MustCompile(`^\[[^\]]*\]\s+`)

	keaMsgIDRE = regexp.MustCompile(`^DHCP[46]_LEASE_([A-Z]+)$`)
	// keaPacketRE matches the DHCPv{4,6} packet-lifecycle message ids. Unlike a LEASE
	// event they carry no assigned address (that comes later) — the signal is the
	// client identity (DUID), the transaction id, and, on a received packet, the DHCP
	// message type. The captured group is the event kind, lowercased into dhcp.kea_event.
	keaPacketRE = regexp.MustCompile(`^DHCP[46]_(PACKET_RECEIVED|PACKET_SEND|QUERY_LABEL)$`)
	// keaDUIDRE / keaTIDRE read the DHCPv6 client id and transaction id.
	keaDUIDRE = regexp.MustCompile(`duid=\[([0-9a-fA-F:]+)]`)
	keaTIDRE  = regexp.MustCompile(`tid=(0x[0-9a-fA-F]+)`)
	// keaMsgTypeRE reads the DHCP message type a PACKET_RECEIVED line ends with
	// ("…tid=0x…: RENEW"). SOLICIT/REQUEST/RENEW/RELEASE/CONFIRM/REBIND/DECLINE/…
	keaMsgTypeRE = regexp.MustCompile(`:\s*([A-Z][A-Z0-9-]*)\s*$`)
	// keaCommandRE reads the control-plane command out of a COMMAND_RECEIVED line
	// ("Received command 'lease6-get-page'").
	keaCommandRE = regexp.MustCompile(`command '([^']+)'`)
	// keaHWRE takes the MAC only from an explicit "[hwtype=1 <mac>]" block. A
	// DHCPv6 DUID is also colon-separated hex and a looser scan would happily
	// slice its first six octets and call them a MAC.
	keaHWRE = regexp.MustCompile(`\[hwtype=\d+\s+((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})]`)
	// keaLeaseRE reads the address out of "…: lease <addr> has been allocated…"
	// (v6 spells it "lease for address <addr>").
	keaLeaseRE = regexp.MustCompile(`lease (?:for address )?([^\s,]+)`)
	// keaSecsRE reads the duration, spelled "for 4000 s" or "for 3869 seconds".
	keaSecsRE = regexp.MustCompile(`\bfor (\d+) (?:s|secs?|seconds?)\b`)

	// keaAllocFailV6RE matches the DHCPv6 allocation-failure message ids (#546). It is
	// anchored on V6 on purpose: kea spells the v4 family ALLOC_ENGINE_V4_ALLOC_FAIL_*,
	// and a loosened `V[46]` here would count LAN IPv4 exhaustion on the IPv6 counter.
	// The optional suffix group is empty for the bare ALLOC_FAIL.
	keaAllocFailV6RE = regexp.MustCompile(`^ALLOC_ENGINE_V6_ALLOC_FAIL(|_SHARED_NETWORK|_SUBNET|_NO_POOLS|_CLASSES)$`)
	// keaAllocFailSubnetRE reads the subnet and its id out of the SUBNET scope line
	// ("…: failed to allocate an IPv6 lease in the subnet 2001:db8::/64, subnet-id 1,
	// shared network (none)"). Both are ATTRIBUTES; the subnet is an IPv6 prefix and
	// this exporter never puts one on a label.
	keaAllocFailSubnetRE = regexp.MustCompile(`in the subnet (\S+), subnet-id (\d+)`)
	// keaAllocFailClassesRE reads the client-class list off the CLASSES line. An
	// attribute: the list is named by whoever wrote the classification rules.
	keaAllocFailClassesRE = regexp.MustCompile(`with classes: (\S.*)$`)

	// keaReleaseNARE matches Kea's DHCPv6 NA-release message pair (#641): a real
	// release fires both DHCP6_RELEASE_NA and DHCP6_RELEASE_NA_EXPIRED, back to
	// back, same tid — the memfile lease record expiring is a direct consequence of
	// the release, not a second event. (The tracking issue names this
	// "DHCP6_RELEASE_NA_EXP"; the box actually emits the full "_EXPIRED" suffix.)
	// The capture group is empty for the bare RELEASE_NA line.
	keaReleaseNARE = regexp.MustCompile(`^DHCP6_RELEASE_NA(_EXPIRED)?$`)
	// keaBindingAddrRE reads the address and IAID out of "…: binding for address
	// <addr> and iaid=<n> …". iaid is a diagnostic attribute, never a label.
	keaBindingAddrRE = regexp.MustCompile(`binding for address (\S+) and iaid=(\d+)`)
)

// keaAllocFailLines maps kea's ALLOC_ENGINE_V6_ALLOC_FAIL* suffix onto the closed
// line vocabulary, and keaAllocFailCountedReasons says which of those lines is the
// authoritative one-per-failure signal.
//
// Kea's alloc_engine.cc emits, for ONE failed allocation: exactly one SCOPE line
// (SHARED_NETWORK when the client is in a shared network, SUBNET otherwise), exactly
// one CAUSE line (NO_POOLS when zero pools were even attempted, the bare ALLOC_FAIL
// otherwise), and optionally CLASSES. All three share one tid. Counting every line
// would report three failures for one, so only the CAUSE pair is counted — it is
// one-per-failure like the scope pair, and unlike it, it carries the reason.
var (
	keaAllocFailLines = map[string]string{
		"_SUBNET":         keaAllocFailLineSubnet,
		"_SHARED_NETWORK": keaAllocFailLineSharedNetwork,
		"_NO_POOLS":       keaAllocFailLineNoPools,
		"":                keaAllocFailLineExhausted,
		"_CLASSES":        keaAllocFailLineClasses,
	}

	keaAllocFailCountedReasons = map[string]string{
		keaAllocFailLineNoPools:   keaAllocFailReasonNoPools,
		keaAllocFailLineExhausted: keaAllocFailReasonExhausted,
	}
)

// dhcpFields is the backend-independent shape all three parsers produce. The final
// group (duid…keaEvent) is Kea-only: a DHCPv6 packet or control-plane event carries
// no leased address, so those lines set these instead of ip/mac/action.
type dhcpFields struct {
	action       string
	ip           string
	mac          string
	hostname     string
	iface        string
	serverIP     string
	leaseSeconds string

	duid        string // DHCPv6 client id (DUID)
	tid         string // Kea transaction id (0x…)
	messageType string // DHCP message type on a PACKET_RECEIVED line (RENEW, REQUEST, …)
	keaCommand  string // control-plane command on a COMMAND_RECEIVED line
	keaEvent    string // packet_received | command_received | alloc_fail

	// The DHCPv6 allocation-failure group (#546). allocFailLine names WHICH line of
	// the burst this is; allocFailReason is set ONLY on the two cause lines and is what
	// the deriver counts, so the scope and classes lines of the same burst cannot
	// double-count the failure.
	allocFailLine     string
	allocFailReason   string
	allocFailSubnet   string
	allocFailSubnetID string
	allocFailClasses  string

	// iaid is the DHCPv6 identity association id off a NA-release line (#641). A
	// diagnostic, never a label.
	iaid string
}

// parseDHCP dispatches on the shape of the line, not on the program name: a box
// can run more than one backend, and dhcrelay/dnsmasq both emit lines that are
// not lease events at all. Returns ok=false for anything it does not recognise,
// so the caller ships it as a generic record — never a drop, never a panic.
//
// miss is unused: an address the snapshot does not know is normal (the lease is
// being created by the very line we are reading), so a lookup failure here is not
// evidence of a stale snapshot.
func parseDHCP(env Envelope, snap *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	msg := strings.TrimSpace(env.Message)
	if msg == "" {
		return logship.Record{}, false
	}

	var (
		f  dhcpFields
		ok bool
	)
	switch {
	case dnsmasqConflictRE.MatchString(msg):
		f, ok = parseDnsmasqConflict(msg)
	case dnsmasqAbandonRE.MatchString(msg):
		f, ok = parseDnsmasqAbandon(msg)
	case dnsmasqLineRE.MatchString(msg):
		f, ok = parseDnsmasqDHCP(msg)
	case isISCDHCPLine(msg):
		f, ok = parseISCDHCP(msg)
	default:
		f, ok = parseKeaDHCP(msg)
	}
	if !ok {
		return logship.Record{}, false
	}

	rec, set := newRecord(env)
	set("dhcp.action", f.action)
	set("dhcp.ip", f.ip)
	set("dhcp.mac", f.mac)
	set("dhcp.hostname", f.hostname)
	set("dhcp.server_ip", f.serverIP)
	set("dhcp.lease_seconds", f.leaseSeconds)
	set("interface", f.iface)
	// Kea packet/control-plane fields (empty for a lease event, so set drops them).
	set("dhcp.duid", f.duid)
	set("dhcp.tid", f.tid)
	set("dhcp.message_type", f.messageType)
	set("dhcp.kea_command", f.keaCommand)
	set("dhcp.kea_event", f.keaEvent)
	// The DHCPv6 allocation-failure group. dhcp.alloc_fail_reason is the ONLY one the
	// deriver reads; the rest are diagnostics on the shipped record.
	set("dhcp.alloc_fail_line", f.allocFailLine)
	set("dhcp.alloc_fail_reason", f.allocFailReason)
	set("dhcp.alloc_fail_subnet", f.allocFailSubnet)
	set("dhcp.alloc_fail_subnet_id", f.allocFailSubnetID)
	set("dhcp.alloc_fail_classes", f.allocFailClasses)
	set("dhcp.iaid", f.iaid)

	if name, ok := ifaceName(snap, f.iface); ok {
		set("interface.name", name)
	}

	// Best-effort enrichment of the leased address, exactly as filterlog does it:
	// the hostname/MAC the box already knows fills the gaps a line leaves (a
	// DHCPDISCOVER carries neither), and the scope says where the address sits.
	// A lookup that misses is normal and is NEVER reported as a cache miss.
	if f.ip != "" && snap != nil {
		if f.hostname == "" {
			if host, ok := snap.Hostname(f.ip); ok {
				set("dhcp.hostname", host)
			}
		}
		if f.mac == "" {
			if mac, ok := snap.MAC(f.ip); ok {
				set("dhcp.mac", mac)
			}
		}
		set("dhcp.scope", snap.Scope(f.ip))
	}

	return rec, true
}

// isISCDHCPLine reports whether the line opens with a bare ISC action word. Kea's
// "DHCP4_LEASE_ALLOC" also starts with "DHCP", so the test is an exact lookup of
// the first token, not a prefix.
func isISCDHCPLine(msg string) bool {
	first, _, _ := strings.Cut(msg, " ")
	_, ok := iscActions[first]
	return ok
}

// parseISCDHCP walks the ISC dhcpd token stream. The grammar varies per message
// type — "on <ip> to <mac>", "for <ip> (<server>) from <mac>", "from <mac>" —
// so we read the prepositions rather than fixing on field positions, and classify
// each value by its own shape.
//
// The parenthetical is overloaded: it is the server identifier after an address
// ("(172.16.30.1)"), the client hostname after a MAC ("(exporter-traffgen)"), and
// on a DHCPRELEASE a trailing "(found)" that is neither. Only a parenthetical
// directly following the MAC is taken as a hostname.
func parseISCDHCP(msg string) (dhcpFields, bool) {
	var f dhcpFields
	tok := strings.Fields(msg)
	if len(tok) == 0 {
		return f, false
	}
	action, ok := iscActions[tok[0]]
	if !ok {
		return f, false
	}
	f.action = action

	afterMAC := false
	for i := 1; i < len(tok); i++ {
		t := tok[i]

		if strings.HasPrefix(t, "(") && strings.HasSuffix(t, ")") {
			v := strings.TrimSuffix(strings.TrimPrefix(t, "("), ")")
			switch {
			case isIPAddr(v):
				if f.serverIP == "" {
					f.serverIP = v
				}
			case isMAC(v):
				if f.mac == "" {
					f.mac = v
				}
			case afterMAC && f.hostname == "":
				f.hostname = v
			}
			continue
		}
		afterMAC = false

		switch t {
		case "via":
			if i+1 < len(tok) {
				f.iface = tok[i+1]
				i++
			}
		case "on", "for", "of", "to", "from":
			if i+1 >= len(tok) {
				continue
			}
			v := tok[i+1]
			switch {
			case isMAC(v):
				if f.mac == "" {
					f.mac = v
				}
				afterMAC = true
				i++
			case isIPAddr(v):
				if f.ip == "" {
					f.ip = v
				}
				i++
			}
		}
	}

	// An action word with neither a client nor an address is not an event worth
	// structuring — ship it verbatim instead of inventing a lease from nothing.
	if f.ip == "" && f.mac == "" {
		return dhcpFields{}, false
	}
	return f, true
}

// parseDnsmasqDHCP handles "DHCPACK(vlan01) 172.16.20.117 bc:… exporter-traffgen":
// the interface is parenthesised onto the action and the remaining tokens are
// positional-ish, so each is classified by shape (address, MAC, otherwise the
// hostname).
func parseDnsmasqDHCP(msg string) (dhcpFields, bool) {
	var f dhcpFields
	m := dnsmasqLineRE.FindStringSubmatch(msg)
	if m == nil {
		return f, false
	}
	action, ok := iscActions[m[1]]
	if !ok {
		return f, false
	}
	f.action = action
	f.iface = m[2]

	for _, t := range strings.Fields(m[3]) {
		switch {
		case isMAC(t):
			if f.mac == "" {
				f.mac = t
			}
		case isIPAddr(t):
			if f.ip == "" {
				f.ip = t
			}
		default:
			if f.hostname == "" {
				f.hostname = t
			}
		}
	}

	if f.ip == "" && f.mac == "" {
		return dhcpFields{}, false
	}
	return f, true
}

// parseKeaDHCP handles Kea's structured message ids. The line may carry a leading
// level word and a "[logger.0xPTR]" prefix; both are stripped before the message
// id is read.
//
// Three shapes are structured: DHCP{4,6}_LEASE_* lease events (address/mac/lease),
// DHCP{4,6}_PACKET_RECEIVED handshake packets (DUID + message type, no address yet),
// and COMMAND_RECEIVED control-plane calls (the command name). Any other Kea id —
// PACKET_SEND, QUERY_LABEL, and the rest — returns ok=false and ships generic.
func parseKeaDHCP(msg string) (dhcpFields, bool) {
	var f dhcpFields

	s := keaLevelRE.ReplaceAllString(msg, "")
	s = keaLoggerRE.ReplaceAllString(s, "")

	id, rest, _ := strings.Cut(s, " ")

	if m := keaMsgIDRE.FindStringSubmatch(id); m != nil {
		action, ok := keaActions[m[1]]
		if !ok {
			return f, false
		}
		f.action = action

		if hw := keaHWRE.FindStringSubmatch(rest); hw != nil {
			f.mac = hw[1]
		}
		if lease := keaLeaseRE.FindStringSubmatch(rest); lease != nil && isIPAddr(lease[1]) {
			f.ip = lease[1]
		}
		if secs := keaSecsRE.FindStringSubmatch(rest); secs != nil {
			f.leaseSeconds = secs[1]
		}

		if f.ip == "" && f.mac == "" {
			return dhcpFields{}, false
		}
		return f, true
	}

	// A DHCPv6 packet-lifecycle event: the client handshake
	// (SOLICIT/REQUEST/RENEW/RELEASE/…), identified by DUID rather than an address the
	// box has not assigned yet. Received packets carry the message type; sends and
	// query-labels carry only DUID/tid.
	if pm := keaPacketRE.FindStringSubmatch(id); pm != nil {
		f.keaEvent = strings.ToLower(pm[1]) // packet_received | packet_send | query_label
		if d := keaDUIDRE.FindStringSubmatch(rest); d != nil {
			f.duid = d[1]
		}
		if t := keaTIDRE.FindStringSubmatch(rest); t != nil {
			f.tid = t[1]
		}
		if mt := keaMsgTypeRE.FindStringSubmatch(rest); mt != nil {
			f.messageType = mt[1]
		}
		// Only a genuine packet event, not an empty shell: it must name at least the
		// client or the message type, else ship it generic.
		if f.duid == "" && f.messageType == "" {
			return dhcpFields{}, false
		}
		return f, true
	}

	// A DHCPv6 allocation failure: a v6 client was refused a lease (#546). Identified
	// by DUID and transaction id, neither of which may ever become a label.
	if am := keaAllocFailV6RE.FindStringSubmatch(id); am != nil {
		line, ok := keaAllocFailLines[am[1]]
		if !ok {
			return dhcpFields{}, false
		}
		f.keaEvent = keaEventAllocFail
		f.allocFailLine = line
		// Set ONLY on the two cause lines. This is the whole de-duplication: the burst's
		// scope and classes lines parse and ship, but reach the deriver with no reason and
		// so count nothing.
		f.allocFailReason = keaAllocFailCountedReasons[line]

		if d := keaDUIDRE.FindStringSubmatch(rest); d != nil {
			f.duid = d[1]
		}
		if t := keaTIDRE.FindStringSubmatch(rest); t != nil {
			f.tid = t[1]
		}
		if sm := keaAllocFailSubnetRE.FindStringSubmatch(rest); sm != nil {
			f.allocFailSubnet = sm[1]
			f.allocFailSubnetID = sm[2]
		}
		if cm := keaAllocFailClassesRE.FindStringSubmatch(rest); cm != nil {
			f.allocFailClasses = cm[1]
		}
		return f, true
	}

	// DHCPv6 NA-release pair (#641). See keaReleaseNARE's doc comment for why only
	// the bare RELEASE_NA line sets f.action: it mirrors the ALLOC_FAIL burst's
	// counted-once-per-failure pattern above, so a downstream counter gated on
	// dhcp.action counts the release once, not twice, per real release.
	if rm := keaReleaseNARE.FindStringSubmatch(id); rm != nil {
		if d := keaDUIDRE.FindStringSubmatch(rest); d != nil {
			f.duid = d[1]
		}
		if t := keaTIDRE.FindStringSubmatch(rest); t != nil {
			f.tid = t[1]
		}
		if b := keaBindingAddrRE.FindStringSubmatch(rest); b != nil && isIPAddr(b[1]) {
			f.ip = b[1]
			f.iaid = b[2]
		}
		if rm[1] == "" {
			// DHCP6_RELEASE_NA: the primary, counted event.
			f.action = "release"
		} else {
			// DHCP6_RELEASE_NA_EXPIRED: same release, memfile-expiry detail only —
			// deliberately NOT f.action, see above.
			f.keaEvent = "release_expired"
		}
		if f.duid == "" && f.ip == "" {
			return dhcpFields{}, false
		}
		return f, true
	}

	// Control-plane command. On this box the bulk of these are the exporter's own
	// lease polling (lease6-get-page, config-get) reflected back; structuring them
	// labels that volume as control-plane so it is filterable, rather than leaving it
	// an opaque unparsed line.
	if id == "COMMAND_RECEIVED" {
		if c := keaCommandRE.FindStringSubmatch(rest); c != nil {
			f.keaEvent = "command_received"
			f.keaCommand = c[1]
			return f, true
		}
	}

	return f, false
}

// parseDnsmasqConflict structures dnsmasq's "not giving name … to the DHCP lease of
// …" warning: the client asked for a name a static host entry already owns. The
// rejected name and the lease address are what an operator needs to find and fix it.
func parseDnsmasqConflict(msg string) (dhcpFields, bool) {
	m := dnsmasqConflictRE.FindStringSubmatch(msg)
	if m == nil {
		return dhcpFields{}, false
	}
	f := dhcpFields{action: "name_conflict", hostname: m[1]}
	if isIPAddr(m[2]) {
		f.ip = m[2]
	}
	return f, true
}

// parseDnsmasqAbandon structures dnsmasq's standalone "abandoning lease to <mac>
// of <ip>" line (#641): dnsmasq refusing to keep handing out a lease because of
// an address conflict, the server-side counterpart of a client's DHCPDECLINE.
func parseDnsmasqAbandon(msg string) (dhcpFields, bool) {
	m := dnsmasqAbandonRE.FindStringSubmatch(msg)
	if m == nil {
		return dhcpFields{}, false
	}
	f := dhcpFields{action: "abandoned"}
	if isMAC(m[1]) {
		f.mac = m[1]
	}
	if isIPAddr(m[2]) {
		f.ip = m[2]
	}
	if f.ip == "" && f.mac == "" {
		return dhcpFields{}, false
	}
	return f, true
}

func isMAC(s string) bool { return macRE.MatchString(s) }

func isIPAddr(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}
