package syslog

import (
	"regexp"
	"strconv"

	"github.com/rknightion/opnsense2otel/v4/internal/logship"
	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
)

// dhcp6c is the WIDE-DHCPv6 client that holds this firewall's own IPv6 uplink and,
// far more importantly, its DELEGATED PREFIX (#546). It is the IPv6 twin of #541's
// dhclient work: before this file existed it was the largest single unparsed program
// on the box (1,444 lines in the reference capture window), and nothing in the
// exporter reported v6 WAN state, prefix-delegation lifetimes, or a failure to renew.
//
// WHY THE PREFIX MATTERS MORE THAN THE ADDRESS: losing a v4 WAN lease costs the
// firewall one address. Losing a delegated prefix takes down v6 on EVERY downstream
// network at once, because every LAN address is derived from it — which is exactly
// what the `add an address <pd-derived>/64 on ixl0` lines below are doing.
//
// THE SIX GRAMMARS CAPTURED VERBATIM on the production box (WAN = pppoe0, /48 PD),
// 48 occurrences each per 24h — a healthy box emits nothing else:
//
//	Sending Renew on pppoe0
//	Received REPLY for RENEW
//	dhcp6c_script: RENEW on pppoe0 executing
//	update a prefix 2001:db8::/48 pltime=3600, vltime=3600
//	add an address 2001:db8:0:9ab7:85ff:fe21:aff2/64 on ixl0
//	add an address 2001:db8:100:0:ff:fe00:64/64 on ixl0_vlan100
//
// EVERY OTHER SHAPE MODELLED HERE IS READ OFF THE FORMAT STRING THAT PRODUCED THE
// CAPTURED ONE, not guessed. Each captured line is one branch of a `%s`-driven
// format, so its siblings are provable rather than invented:
//
//   - opnsense/dhcp6c dhcp6c.c:1033-1053 (client6_send) — six literal
//     `Sending <Msg> on %s` calls: Solicit, Request, Renew, Rebind, Release,
//     Information Request. No seventh exists.
//   - opnsense/dhcp6c dhcp6c.c:1652 (client6_recvreply) — `Received REPLY for %s`
//     where %s is dhcp6_event_statestr(). The guard immediately above that call
//     restricts the reachable states to INFOREQ, REQUEST, RENEW, REBIND, RELEASE and
//     (with rapid commit) SOLICIT.
//   - opnsense/dhcp6c prefixconf.c:211 (update_prefix) —
//     `%s a prefix %s/%d pltime=%u, vltime=%u` where %s is the ternary
//     `spcreate ? "create" : "update"`. Exactly two values.
//   - opnsense/dhcp6c common.c (ifaddrconf) — `%s an address %s/%d on %s` where %s is
//     "add" or "remove", the only two members of ifaddrconf_cmd_t.
//   - opnsense/core src/opnsense/scripts/interfaces/dhcp6c_script.sh — the four
//     `logger -t dhcp6c "dhcp6c_script: ${REASON} on ${IFNAME} <suffix>"` calls, with
//     REASON restricted by the script's own `case` to INFOREQ|REBIND|RENEW|REQUEST|
//     SOLICIT|EXIT|RELEASE and everything else falling to the `ignored` arm.
//
// THE OPTIONAL FUNCTION-NAME PREFIX. dhcp6c logs through d_printf, which emits
// `syslog(level, "%s%s%s", fname, ": ", logbuf)` with fname = __func__ on any build
// where HAVE_ANSI_FUNC or HAVE_GCC_FUNCTION is defined (configure.ac defines one of
// them on FreeBSD). So the same line is `client6_send: Sending Renew on pppoe0` on
// one build and bare `Sending Renew on pppoe0` on another — and the reference
// capture shows the bare form. Rather than betting on either, the C-source grammars
// are matched after stripping an OPTIONAL leading identifier-and-colon. The script
// grammars are matched FIRST, with their literal `dhcp6c_script: ` intact, so that
// strip can never eat their prefix.
//
// THE WAN ADDRESS LEASE (IA_NA), #560. #546 deliberately left addrconf.c's
// `create|update an address %s pltime=%u, vltime=%u` unmodelled: the reference box
// was PD-only and never emitted it, and standing up a gauge family on a shape no
// capture supports is how #284's phantom generation got built. A real capture has
// since turned up on testbed VM 102 (2026-07-30) — a box that takes its WAN address
// directly by DHCPv6 rather than only a delegated prefix — so this is now modelled
// from that capture, not from the format string alone. The address literal in every
// fixture and comment below is RFC 3849 documentation space (2001:db8::/32); the
// real capture used a globally-routable prefix, anonymised here because this repo is
// public (#565).
//
// THE LINE CARRIES NO INTERFACE, same trap as the prefix line, resolved the same
// way: the daemon's PID, taught only by the preceding `Sending … on <iface>`. The
// FOLLOWING `add an address <addr>/128 on <iface>` line (ifaddrconf.c, already
// modelled below as a downstream address_added/removed event) happens to name the
// interface explicitly when the address is the WAN's own, but that is a
// happenstance of this shape and is not relied on here.
//
// UPDATE IS ~66x MORE COMMON THAN CREATE on the captured box, and both must produce
// the gauge triple — a parser matching only `create` would set the gauges once and
// then never refresh them, indistinguishable from a stalled lease.
//
// REMOVAL CLEARS THE GAUGES rather than leaving them frozen: a frozen lifetime gauge
// reads as a healthy lease that simply stopped being renewed, which is a worse
// failure mode than the series disappearing when dhcp6c has told us the lease is
// gone. The bare `remove an address %s` (no lifetime, no interface) is addrconf.c's
// own removal call — distinct from ifaddrconf.c's `remove an address %s/%d on %s`
// matched by reDHCP6CAddress below, which removes a DOWNSTREAM address.
//
// DELIBERATELY NOT PARSED: `dhcp6c_script: missing REASON or IFNAME` (it names
// neither, so the record would be empty of everything a query would filter on).
var (
	// The OPNsense shell script's four `logger` calls. Matched BEFORE the function-name
	// strip below, because `dhcp6c_script: ` looks exactly like one.
	//
	// The suffix alternation is the closed set of the script's own log calls. `prefix
	// now <PDINFO>` is split out because its tail is the delegated prefix list, which is
	// record data rather than part of the grammar.
	reDHCP6CScript = regexp.MustCompile(
		`^dhcp6c_script: ([A-Z][A-Z0-9_]*) on ([0-9A-Za-z._-]+) (executing|connected to server|ignored)$`)
	reDHCP6CScriptPrefix = regexp.MustCompile(
		`^dhcp6c_script: ([A-Z][A-Z0-9_]*) on ([0-9A-Za-z._-]+) prefix now (\S.*)$`)

	// The optional `<funcname>: ` d_printf prefix. See the file comment.
	reDHCP6CFuncPrefix = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*: `)

	// client6_send's six literals. Anchored to the closed vocabulary rather than to
	// `[A-Za-z ]+`, so an unexpected verb fails to match and ships generically instead
	// of silently minting a new label value — same call as dhclient.go's verb group.
	reDHCP6CSending = regexp.MustCompile(
		`^Sending (Solicit|Request|Renew|Rebind|Release|Information Request) on ([0-9A-Za-z._-]+)$`)

	// client6_recvreply. It names NO interface — hence the PID correlation below.
	// IDLE, INIT and EXIT are deliberately absent: dhcp6_event_statestr can return them
	// but the guard above the call site makes them unreachable here.
	reDHCP6CReply = regexp.MustCompile(`^Received REPLY for (SOLICIT|REQUEST|RENEW|REBIND|RELEASE|INFOREQ)$`)

	// update_prefix. The address group is hex-and-colons rather than `\S+` so the
	// `/<plen>` split cannot land inside the prefix itself.
	reDHCP6CPrefix = regexp.MustCompile(
		`^(create|update) a prefix ([0-9a-fA-F:]+)/(\d+) pltime=(\d+), vltime=(\d+)$`)

	// ifaddrconf. The interface here is the DOWNSTREAM device the delegated prefix was
	// applied to (ixl0, ixl0_vlan100), NOT the WAN — which is why this line must never
	// teach the PID correlation table.
	reDHCP6CAddress = regexp.MustCompile(
		`^(add|remove) an address ([0-9a-fA-F:]+)/(\d+) on ([0-9A-Za-z._-]+)$`)

	// addrconf.c's WAN ADDRESS LEASE line (#560) — the IA_NA counterpart of
	// reDHCP6CPrefix above. No interface, no /<plen>: this is the address itself, not
	// a downstream configuration event.
	reDHCP6CAddressLease = regexp.MustCompile(
		`^(create|update) an address ([0-9a-fA-F:]+) pltime=(\d+), vltime=(\d+)$`)

	// addrconf.c's bare removal of the WAN address lease: no lifetime, no interface.
	// Distinct from reDHCP6CAddress's `remove an address <addr>/<plen> on <iface>`,
	// which is ifaddrconf.c removing a DOWNSTREAM address.
	reDHCP6CAddressLeaseRemove = regexp.MustCompile(`^remove an address ([0-9a-fA-F:]+)$`)
)

// dhcp6cSentTypes and dhcp6cReplyTypes fold dhcp6c's two spellings of the same
// exchange onto ONE closed label vocabulary, so a Renew and the REPLY answering it
// share a `type`. Maps rather than strings.ToLower, mirroring dhcpClientTypes: the
// vocabulary then stays closed by construction even if a regex above is loosened.
var (
	dhcp6cSentTypes = map[string]string{
		"Solicit":             dhcp6cTypeSolicit,
		"Request":             dhcp6cTypeRequest,
		"Renew":               dhcp6cTypeRenew,
		"Rebind":              dhcp6cTypeRebind,
		"Release":             dhcp6cTypeRelease,
		"Information Request": dhcp6cTypeInformationRequest,
	}

	dhcp6cReplyTypes = map[string]string{
		"SOLICIT": dhcp6cTypeSolicit,
		"REQUEST": dhcp6cTypeRequest,
		"RENEW":   dhcp6cTypeRenew,
		"REBIND":  dhcp6cTypeRebind,
		"RELEASE": dhcp6cTypeRelease,
		"INFOREQ": dhcp6cTypeInformationRequest,
	}

	// dhcp6c_script.sh's own REASON set, from its `case` statement. A REASON outside it
	// reaches the script's `*)` arm and is logged as `ignored` — and is then NOT mapped
	// here, so the untrusted token never becomes a label value. The event alone
	// (script_ignored) says what happened.
	dhcp6cScriptReasons = map[string]string{
		"SOLICIT": dhcp6cTypeSolicit,
		"REQUEST": dhcp6cTypeRequest,
		"RENEW":   dhcp6cTypeRenew,
		"REBIND":  dhcp6cTypeRebind,
		"RELEASE": dhcp6cTypeRelease,
		"INFOREQ": dhcp6cTypeInformationRequest,
		"EXIT":    dhcp6cTypeExit,
	}

	// dhcp6cPrefixEvents and dhcp6cAddressEvents map the two upstream ternaries onto
	// the event vocabulary.
	dhcp6cPrefixEvents = map[string]string{
		"create": dhcp6cEventPrefixCreated,
		"update": dhcp6cEventPrefixUpdated,
	}

	dhcp6cAddressEvents = map[string]string{
		"add":    dhcp6cEventAddressAdded,
		"remove": dhcp6cEventAddressRemoved,
	}

	// dhcp6cAddressLeaseEvents maps addrconf.c's create/update ternary onto the
	// WAN address-lease event vocabulary (#560) — distinct from dhcp6cAddressEvents
	// above, which is ifaddrconf.c's downstream add/remove.
	dhcp6cAddressLeaseEvents = map[string]string{
		"create": dhcp6cEventAddressLeaseCreated,
		"update": dhcp6cEventAddressLeaseUpdated,
	}

	// dhcp6cScriptEvents maps the script's log-line suffix onto the event vocabulary.
	dhcp6cScriptEvents = map[string]string{
		"executing":           dhcp6cEventScriptExecuting,
		"connected to server": dhcp6cEventScriptConnected,
		"ignored":             dhcp6cEventScriptIgnored,
	}
)

// dhcp6cIfaces remembers which WAN interface each dhcp6c daemon PID last named.
//
// WHY IT EXISTS: `Received REPLY for RENEW` and `update a prefix …` carry NO
// interface, and both the message counter and the prefix gauges are keyed by one.
// Both come from the same daemon process as the `Sending Renew on <iface>` that
// preceded them, so the PID resolves them — the identical mechanism #541 uses for
// dhclient's `DHCPACK from <ip>`, and bounded the same way.
//
// ONLY THE `Sending … on <iface>` LINE MAY TEACH IT. The `add an address … on ixl0`
// line comes from the SAME daemon PID but names a DOWNSTREAM interface, so letting
// it write here would file the next reply and the next prefix update under a LAN
// device. The script's lines come from a different process entirely (a shell running
// `logger -t dhcp6c`), so they must not write here either.
//
// An unknown PID resolves to the empty string, which the metric carries honestly as
// "no interface known" — it never guesses.
var dhcp6cIfaces = newPIDIfaceMemory(maxDHCPClientPIDs)

func init() {
	// WithBodyEnrichment, the same call dhclient.go made: these lines already carry
	// interface / interface.name / peer.* from the generic body scan today, and
	// suppressing it would be a live regression in any existing Loki query in exchange
	// for removing a redundancy that is already shipping.
	RegisterParserWithBodyEnrichment(parseDHCP6C, "dhcp6c")
}

func parseDHCP6C(env Envelope, snap *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	// The script grammars go first: their literal `dhcp6c_script: ` prefix is
	// indistinguishable from the d_printf function-name prefix stripped below.
	if m := reDHCP6CScript.FindStringSubmatch(env.Message); m != nil {
		event, ok := dhcp6cScriptEvents[m[3]]
		if !ok {
			return logship.Record{}, false
		}
		rec, set := newRecord(env)
		set(attrDHCP6CEvent, event)
		// An unmapped REASON stays off the record entirely rather than being lowercased
		// onto a label — the `ignored` arm exists precisely for reasons nobody has closed.
		set(attrDHCP6CScriptReason, dhcp6cScriptReasons[m[1]])
		setDHCP6CInterface(set, snap, m[2])
		return rec, true
	}

	if m := reDHCP6CScriptPrefix.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set(attrDHCP6CEvent, dhcp6cEventScriptPrefixUpdated)
		set(attrDHCP6CScriptReason, dhcp6cScriptReasons[m[1]])
		setDHCP6CInterface(set, snap, m[2])
		// The delegated prefix list, verbatim. An ATTRIBUTE, never a label.
		set(attrDHCP6CPrefix, m[3])
		return rec, true
	}

	msg := reDHCP6CFuncPrefix.ReplaceAllString(env.Message, "")

	if m := reDHCP6CSending.FindStringSubmatch(msg); m != nil {
		t, ok := dhcp6cSentTypes[m[1]]
		if !ok {
			return logship.Record{}, false
		}
		// The ONE line that teaches the correlation table: the daemon is sending, so it
		// names the WAN interface it is sending on.
		dhcp6cIfaces.remember(env.PID, m[2])
		rec, set := newRecord(env)
		set(attrDHCP6CDirection, dhcp6cDirectionSent)
		set(attrDHCP6CType, t)
		setDHCP6CInterface(set, snap, m[2])
		return rec, true
	}

	if m := reDHCP6CReply.FindStringSubmatch(msg); m != nil {
		t, ok := dhcp6cReplyTypes[m[1]]
		if !ok {
			return logship.Record{}, false
		}
		rec, set := newRecord(env)
		set(attrDHCP6CDirection, dhcp6cDirectionReceived)
		set(attrDHCP6CType, t)
		setDHCP6CInterface(set, snap, dhcp6cIfaces.lookup(env.PID))
		return rec, true
	}

	if m := reDHCP6CPrefix.FindStringSubmatch(msg); m != nil {
		return dhcp6cPrefixRecord(env, snap, m[1], m[2], m[3], m[4], m[5])
	}

	if m := reDHCP6CAddressLease.FindStringSubmatch(msg); m != nil {
		return dhcp6cAddressLeaseRecord(env, snap, m[1], m[2], m[3], m[4])
	}

	if m := reDHCP6CAddressLeaseRemove.FindStringSubmatch(msg); m != nil {
		rec, set := newRecord(env)
		set(attrDHCP6CEvent, dhcp6cEventAddressLeaseRemoved)
		set(attrDHCP6CAddress, m[1])
		// Same PID correlation as the create/update line: this removal names no
		// interface either.
		setDHCP6CInterface(set, snap, dhcp6cIfaces.lookup(env.PID))
		return rec, true
	}

	if m := reDHCP6CAddress.FindStringSubmatch(msg); m != nil {
		event, ok := dhcp6cAddressEvents[m[1]]
		if !ok {
			return logship.Record{}, false
		}
		rec, set := newRecord(env)
		set(attrDHCP6CEvent, event)
		set(attrDHCP6CAddress, m[2])
		set(attrDHCP6CPrefixLength, m[3])
		// The interface NAMED ON THE LINE, which is the downstream device the address was
		// configured on. It must not be remembered as the WAN — see dhcp6cIfaces.
		setDHCP6CInterface(set, snap, m[4])
		return rec, true
	}

	// Everything else — the daemon's protocol chatter, the script's missing-environment
	// warning, and any shape this box has never emitted — keeps shipping as the generic
	// record it always was.
	return logship.Record{}, false
}

// dhcp6cPrefixRecord builds the prefix-delegation record, which carries the three
// lifetime gauges — #546's stated highest-value signal.
//
// THE GAUGES ARE ABSOLUTE TIMESTAMPS, NOT COUNTDOWNS, for exactly the reason #541
// established for the v4 lease: a countdown has to be recomputed against wall-clock
// at scrape time, and a stale countdown is indistinguishable from a fresh one — the
// precise failure the metric exists to catch. Three absolute deadlines survive a
// scrape gap unchanged and make "the delegation stopped being renewed" directly
// expressible as `<metric> - time() < 0`.
//
// THE BASE IS THE LINE'S OWN SYSLOG TIMESTAMP, not time.Now(): a replayed or
// buffered line must produce the deadline the firewall meant. A line whose envelope
// carried no timestamp gets NO gauge attributes at all — an invented base would
// silently mis-date the deadline — though the record still ships with the prefix and
// both raw lifetimes.
//
// pltime and vltime are read independently even though this box sends them equal:
// they are separate `%u` arguments upstream, and a preferred lifetime shorter than
// the valid lifetime is the normal shape when an ISP is deprecating a prefix ahead
// of withdrawing it. Collapsing them would hide exactly that warning.
func dhcp6cPrefixRecord(env Envelope, snap *enrich.Snapshot, verb, prefix, plen, pltime, vltime string) (logship.Record, bool) {
	event, ok := dhcp6cPrefixEvents[verb]
	if !ok {
		return logship.Record{}, false
	}

	rec, set := newRecord(env)
	set(attrDHCP6CEvent, event)
	// The prefix ships in its full CIDR form as an ATTRIBUTE. Never a label, even
	// though it is the firewall's own: it changes on re-delegation, which is the event
	// these metrics exist to watch.
	set(attrDHCP6CPrefix, prefix+"/"+plen)
	set(attrDHCP6CPrefixLength, plen)
	set(attrDHCP6CPreferredSeconds, pltime)
	set(attrDHCP6CValidSeconds, vltime)
	// The prefix line names no interface; the WAN comes from the daemon's PID.
	setDHCP6CInterface(set, snap, dhcp6cIfaces.lookup(env.PID))

	pl, plErr := strconv.ParseInt(pltime, 10, 64)
	vl, vlErr := strconv.ParseInt(vltime, 10, 64)
	if plErr != nil || vlErr != nil || env.Timestamp.IsZero() {
		return rec, true
	}
	updated := env.Timestamp.Unix()
	set(attrDHCP6CPrefixUpdatedTimestamp, strconv.FormatInt(updated, 10))
	set(attrDHCP6CPrefixPreferredTimestamp, strconv.FormatInt(updated+pl, 10))
	set(attrDHCP6CPrefixValidTimestamp, strconv.FormatInt(updated+vl, 10))
	return rec, true
}

// dhcp6cAddressLeaseRecord builds the WAN address-lease record (#560) — the IA_NA
// twin of dhcp6cPrefixRecord, for a box that takes its WAN address directly by
// DHCPv6 rather than only a delegated prefix.
//
// Same absolute-timestamp reasoning as dhcp6cPrefixRecord: the base is the line's
// OWN syslog timestamp, never time.Now(), and an undated line ships with the raw
// lifetimes but no gauge attributes. pltime and vltime are read independently for
// the same reason: an ISP deprecating the address ahead of withdrawing it shortens
// the preferred lifetime first.
func dhcp6cAddressLeaseRecord(env Envelope, snap *enrich.Snapshot, verb, addr, pltime, vltime string) (logship.Record, bool) {
	event, ok := dhcp6cAddressLeaseEvents[verb]
	if !ok {
		return logship.Record{}, false
	}

	rec, set := newRecord(env)
	set(attrDHCP6CEvent, event)
	// The address ships as an ATTRIBUTE, never a label: it is this firewall's own WAN
	// address and changes on re-bind, which is one of the conditions this metric
	// watches for.
	set(attrDHCP6CAddress, addr)
	set(attrDHCP6CAddressLeasePreferredSeconds, pltime)
	set(attrDHCP6CAddressLeaseValidSeconds, vltime)
	// The line names no interface; resolved from the daemon's PID, same as the prefix
	// line above.
	setDHCP6CInterface(set, snap, dhcp6cIfaces.lookup(env.PID))

	pl, plErr := strconv.ParseInt(pltime, 10, 64)
	vl, vlErr := strconv.ParseInt(vltime, 10, 64)
	if plErr != nil || vlErr != nil || env.Timestamp.IsZero() {
		return rec, true
	}
	updated := env.Timestamp.Unix()
	set(attrDHCP6CAddressLeaseUpdatedTimestamp, strconv.FormatInt(updated, 10))
	set(attrDHCP6CAddressLeasePreferredTimestamp, strconv.FormatInt(updated+pl, 10))
	set(attrDHCP6CAddressLeaseValidTimestamp, strconv.FormatInt(updated+vl, 10))
	return rec, true
}

// setDHCP6CInterface writes the family's own interface attribute and, when the
// enrichment snapshot can resolve the device, the shared interface/interface.name
// pair every other parser sets. An empty device writes nothing at all — `set` drops
// empties — so an unresolved reply is honestly interface-less rather than blank-keyed.
func setDHCP6CInterface(set func(k, v string), snap *enrich.Snapshot, dev string) {
	set(attrDHCP6CInterface, dev)
	if dev == "" {
		return
	}
	set("interface", dev)
	if name, ok := ifaceName(snap, dev); ok {
		set("interface.name", name)
	}
}
