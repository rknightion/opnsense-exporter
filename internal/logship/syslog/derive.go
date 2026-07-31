package syslog

import (
	"strconv"

	"github.com/rknightion/opnsense-exporter/internal/logship"
)

// attrHTTPResponseStatusCode is the attribute key haproxy.go's httplog parser
// writes the response status under, and the one observeDerived reads to bucket it
// into a status_class label.
//
// It is a shared const, not two string literals, because it WAS two string
// literals: the parser wrote "http.response.status_code" while the deriver read
// "http.status_code", so the lookup always missed and the status_class label was
// empty for every HAProxy line from the day it shipped. It failed in the safe
// direction — an empty label is a case the metric legitimately supports — so the
// counter looked plausible rather than broken. One const means the two sides
// cannot drift again.
const attrHTTPResponseStatusCode = "http.response.status_code"

// The `vpn` family's attribute keys and its three CLOSED, code-defined
// vocabularies (#406). charon.go and openvpn.go write them; observeDerived below
// reads them; nothing on the wire can add a value. They live here, beside the
// family decision that consumes them, for the same reason
// attrHTTPResponseStatusCode does: a parser and its deriver spelling the same key
// two different ways is a bug that fails silently into an empty label.
//
// A wire-derived value must NEVER be added to any of these vocabularies. The
// connection dimension is the one deployment-scale label, and it is the
// API-RESOLVED configured name only (see observeDerived's familyVPN case).
const (
	attrVPNBackend = "vpn.backend"
	attrVPNEvent   = "vpn.event"
	attrVPNResult  = "vpn.result"

	vpnBackendIPsec   = "ipsec"
	vpnBackendOpenVPN = "openvpn"

	// The two SERVICE-LIFECYCLE backends added by #596 (wireguard.go, tailscaled.go).
	// They are RECORD attribute values only: their programs sit in nonDerivedPrograms
	// below, so neither ever reaches a metric label, and the #406 counter's backend
	// dimension is still exactly {ipsec, openvpn}. See nonDerivedPrograms for why, and
	// for what promoting them would have to move at the same time.
	vpnBackendWireGuard = "wireguard"
	vpnBackendTailscale = "tailscale"

	vpnEventEstablished          = "established"
	vpnEventTerminated           = "terminated"
	vpnEventAuthenticationFailed = "authentication_failed"
	vpnEventLivenessFailed       = "liveness_failed"
	vpnEventCertificateFailed    = "certificate_failed"

	vpnResultSuccess = "success"
	vpnResultFailure = "failure"
)

// The `carp` family's attribute keys and its two CLOSED, code-defined vocabularies
// (#405). carp.go writes them; observeDerived below reads them. They live here for
// the same reason the vpn block above does: a parser and its deriver spelling one
// key two different ways fails silently into an empty label, and the whole point of
// this family is that its label values are closed.
//
// The kernel's CAUSE string is deliberately absent from these constants and from
// the label tuple. It is free text from FreeBSD's carp.c (`initialization
// complete`, `master timed out`, `hardware interface up`, `pfsync bulk start`,
// `pfsync bulk fail`, and whatever a future release adds), so it is an open-ended
// vocabulary no capture can close. It ships as attrCARPReason on the record and
// must never become a metric label, nor be bucketed into a reason_class — that
// would be inventing a taxonomy the evidence does not support.
const (
	attrCARPEvent         = "carp.event"
	attrCARPStatePrevious = "carp.state.previous"
	attrCARPStateCurrent  = "carp.state.current"
	attrCARPInterface     = "carp.interface"
	attrCARPVHID          = "carp.vhid"
	attrCARPReason        = "carp.reason"
	attrCARPDemotionDelta = "carp.demotion.delta"
	attrCARPDemotionTotal = "carp.demotion.total"

	// carpEventDemoted / carpEventPromoted are decided by the SIGN of the kernel's
	// demotion delta: positive raises the demotion total (this node is less willing
	// to be master), negative lowers it. There is no separate "promoted" line in
	// FreeBSD — a promotion is a negative `demoted by`.
	carpEventStateChanged = "state_changed"
	carpEventDemoted      = "demoted"
	carpEventPromoted     = "promoted"

	carpStateMaster = "master"
	carpStateBackup = "backup"
	carpStateInit   = "init"
)

// The `upnp` family's attribute keys and its three CLOSED, code-defined
// vocabularies (#409). miniupnpd.go writes them; observeDerived below reads them.
// Same reason they live here as the two blocks above: a parser and its deriver
// spelling one key two different ways fails silently into an empty label.
//
// THE PORT NUMBERS ARE ATTRIBUTES AND NEVER LABELS. An ephemeral client port is
// unbounded, and a per-port series would multiply with every mapping a client makes,
// so they stay on the shipped record where they are still queryable. The `addr=`
// token and the lease-file path are not even attributes — see miniupnpd.go.
//
// There is deliberately NO mapping-count value of any kind here: #409 forbids an
// active-mapping gauge, and `expired` is a decrement with no matching increment.
const (
	attrUPnPEvent        = "upnp.event"
	attrUPnPResult       = "upnp.result"
	attrUPnPProtocol     = "upnp.protocol"
	attrUPnPPortExternal = "upnp.port.external"
	attrUPnPPortInternal = "upnp.port.internal"

	// upnpEventExpired is the ONE event whose result is ok: a mapping reached the end
	// of its lease and the daemon tore it down, which is the lifecycle working. The
	// other three are failures. A successful ADD or DELETE is absent because no
	// captured grammar proves one — see miniupnpd.go.
	upnpEventExpired        = "expired"
	upnpEventCleanupFailed  = "cleanup_failed"
	upnpEventUnauthorized   = "unauthorized"
	upnpEventLeaseFileError = "lease_file_error"

	upnpResultOK      = "ok"
	upnpResultFailure = "failure"

	upnpProtocolTCP = "tcp"
	upnpProtocolUDP = "udp"
)

// The `kernel` family's netmap and ARP attribute keys and their CLOSED,
// code-defined event vocabularies (#536). kernel.go writes them; observeDerived
// below reads them. Same reason they live here as the blocks above: a parser and
// its deriver spelling one key two different ways fails silently into an empty
// label.
//
// THE NETMAP RING COUNTERS ARE ATTRIBUTES AND NEVER LABELS. hwcur, hwtail and qlen
// are ring indices that change on every occurrence, so a label built from any of
// them would mint a series per log line. They are genuinely useful diagnostics —
// hwcur == hwtail is a completely full ring, and qlen tells you how deep the host
// ring was — so they ship on the record.
//
// THE ARP LINE'S IP AND BOTH MAC ADDRESSES ARE ATTRIBUTES AND NEVER LABELS either.
// A duplicate-address event names whichever host is fighting over the address, so
// the value set is unbounded and PII-shaped. Only the interface is a label.
const (
	attrNetmapEvent  = "netmap.event"
	attrNetmapDevice = "netmap.device"
	attrNetmapHWCur  = "netmap.hwcur"
	attrNetmapHWTail = "netmap.hwtail"
	attrNetmapQLen   = "netmap.qlen"

	// netmapEventRingFull is the ONLY netmap event modelled. It is deliberately named
	// for the REPORT, not for a packet: the kernel rate-limits this line (see
	// kernel.go), so it can never be read as a drop count.
	netmapEventRingFull = "ring_full"

	attrARPEvent       = "arp.event"
	attrARPInterface   = "arp.interface"
	attrARPAddress     = "arp.address"
	attrARPMACPrevious = "arp.mac.previous"
	attrARPMACCurrent  = "arp.mac.current"

	arpEventAddressMoved = "address_moved"
)

// The `dhcp_client` family's attribute keys and its two CLOSED, code-defined
// vocabularies (#541). dhclient.go writes them; observeDerived below reads them.
//
// THE SERVER AND LEASED ADDRESSES ARE ATTRIBUTES AND NEVER LABELS. A WAN DHCP
// server address changes when the ISP re-homes the circuit and the leased address
// changes on every re-bind, so both would churn a metric's series set. They stay on
// the record, where they are still queryable — and where the leased address, which
// is the box's own public IP, is not being copied into a metric that outlives it.
//
// The two lease TIMESTAMP attributes are absolute Unix seconds computed by the
// parser from the line's own syslog timestamp, not the raw "renewal in N seconds"
// countdown. See dhclient.go for why the gauges are timestamps.
const (
	attrDHCPClientType             = "dhcp_client.type"
	attrDHCPClientInterface        = "dhcp_client.interface"
	attrDHCPClientServer           = "dhcp_client.server"
	attrDHCPClientAddress          = "dhcp_client.address"
	attrDHCPClientRenewalSeconds   = "dhcp_client.lease.renewal_seconds"
	attrDHCPClientBoundTimestamp   = "dhcp_client.lease.bound_timestamp"
	attrDHCPClientRenewalTimestamp = "dhcp_client.lease.renewal_timestamp"
	attrDHCPClientScriptReason     = "dhcp_client.script.reason"

	// The DHCP message-type vocabulary, lowercased. Closed by construction:
	// dhclient.go resolves a wire token through a map, so an unrecognised verb can
	// never reach a label even if a regex is loosened.
	dhcpClientTypeDiscover = "discover"
	dhcpClientTypeRequest  = "request"
	dhcpClientTypeAck      = "ack"
	dhcpClientTypeNak      = "nak"
	dhcpClientTypeOffer    = "offer"
	dhcpClientTypeDecline  = "decline"
	dhcpClientTypeRelease  = "release"
	dhcpClientTypeInform   = "inform"

	// dhclient-script's REASON vocabulary, lowercased. It is dhclient's own closed
	// set (dhclient-script(8)), not a taxonomy invented here.
	dhcpClientReasonMedium   = "medium"
	dhcpClientReasonPreinit  = "preinit"
	dhcpClientReasonArpcheck = "arpcheck"
	dhcpClientReasonArpsend  = "arpsend"
	dhcpClientReasonBound    = "bound"
	dhcpClientReasonRenew    = "renew"
	dhcpClientReasonRebind   = "rebind"
	dhcpClientReasonReboot   = "reboot"
	dhcpClientReasonExpire   = "expire"
	dhcpClientReasonFail     = "fail"
	dhcpClientReasonTimeout  = "timeout"
	dhcpClientReasonStop     = "stop"
	dhcpClientReasonRelease  = "release"
	dhcpClientReasonNBI      = "nbi"
)

// The `dhcp6c` family's attribute keys and its CLOSED, code-defined vocabularies
// (#546). dhcp6c.go writes them; observeDHCP6C below reads them.
//
// THE DELEGATED PREFIX AND EVERY CONFIGURED IPv6 ADDRESS ARE ATTRIBUTES AND NEVER
// LABELS — including the firewall's OWN /48. An ISP re-delegates on a circuit
// change, which is exactly the event these metrics exist to catch, so a prefix as a
// label would churn the series set precisely during the incident. The PREFIX LENGTH
// is the one part that IS a label: it is the delegation SIZE, it does not change
// when the prefix does, and it is what distinguishes a second delegation of a
// different size on the same WAN.
//
// The three prefix TIMESTAMP attributes are absolute Unix seconds computed by the
// parser from the line's own syslog timestamp plus dhcp6c's pltime/vltime, not a
// countdown. See dhcp6c.go, and #541 for why a countdown is the wrong shape.
const (
	attrDHCP6CInterface    = "dhcp6c.interface"
	attrDHCP6CDirection    = "dhcp6c.direction"
	attrDHCP6CType         = "dhcp6c.type"
	attrDHCP6CEvent        = "dhcp6c.event"
	attrDHCP6CScriptReason = "dhcp6c.script.reason"
	attrDHCP6CPrefix       = "dhcp6c.prefix"
	attrDHCP6CPrefixLength = "dhcp6c.prefix_length"
	attrDHCP6CAddress      = "dhcp6c.address"

	attrDHCP6CPreferredSeconds = "dhcp6c.prefix.pltime_seconds"
	attrDHCP6CValidSeconds     = "dhcp6c.prefix.vltime_seconds"

	attrDHCP6CPrefixUpdatedTimestamp   = "dhcp6c.prefix.updated_timestamp"
	attrDHCP6CPrefixPreferredTimestamp = "dhcp6c.prefix.preferred_expiry_timestamp"
	attrDHCP6CPrefixValidTimestamp     = "dhcp6c.prefix.valid_expiry_timestamp"

	// The WAN ADDRESS-LEASE (IA_NA) attributes (#560) — addrconf.c's
	// `create|update an address %s pltime=%u, vltime=%u`, the v6 twin of the v4 WAN
	// lease #541 covers and the address counterpart of the prefix triple above. Same
	// absolute-timestamp shape and same reasoning: a countdown recomputed at scrape
	// time cannot be told apart from a stale one.
	attrDHCP6CAddressLeasePreferredSeconds = "dhcp6c.address_lease.pltime_seconds"
	attrDHCP6CAddressLeaseValidSeconds     = "dhcp6c.address_lease.vltime_seconds"

	attrDHCP6CAddressLeaseUpdatedTimestamp   = "dhcp6c.address_lease.updated_timestamp"
	attrDHCP6CAddressLeasePreferredTimestamp = "dhcp6c.address_lease.preferred_expiry_timestamp"
	attrDHCP6CAddressLeaseValidTimestamp     = "dhcp6c.address_lease.valid_expiry_timestamp"

	// The message DIRECTION. Two values, decided by which of dhcp6c's two format
	// strings matched — never by anything on the wire.
	dhcp6cDirectionSent     = "sent"
	dhcp6cDirectionReceived = "received"

	// The DHCPv6 exchange vocabulary, lowercased. It is dhcp6c's own closed set: the
	// six `Sending <Msg> on %s` literals in client6_send and the state names
	// dhcp6_event_statestr returns, folded onto one vocabulary so a Renew and the
	// REPLY that answers it carry the same `type`. INFOREQ and "Information Request"
	// are the same exchange spelled two ways upstream and both map to
	// information_request.
	dhcp6cTypeSolicit            = "solicit"
	dhcp6cTypeRequest            = "request"
	dhcp6cTypeRenew              = "renew"
	dhcp6cTypeRebind             = "rebind"
	dhcp6cTypeRelease            = "release"
	dhcp6cTypeInformationRequest = "information_request"
	// dhcp6cTypeExit is reachable ONLY as a script reason: dhcp6c never sends an
	// "Exit" message, but OPNsense's dhcp6c_script.sh handles an EXIT reason.
	dhcp6cTypeExit = "exit"

	// The dhcp6c EVENT vocabulary. Every value names a shape upstream can actually
	// produce: prefix_created/prefix_updated are prefixconf.c's `create`/`update`
	// literals, address_added/address_removed are common.c's `add`/`remove`, and the
	// four script_* values are the four `logger -t dhcp6c` calls in OPNsense's
	// dhcp6c_script.sh.
	dhcp6cEventPrefixCreated       = "prefix_created"
	dhcp6cEventPrefixUpdated       = "prefix_updated"
	dhcp6cEventAddressAdded        = "address_added"
	dhcp6cEventAddressRemoved      = "address_removed"
	dhcp6cEventScriptExecuting     = "script_executing"
	dhcp6cEventScriptConnected     = "script_connected"
	dhcp6cEventScriptPrefixUpdated = "script_prefix_updated"
	dhcp6cEventScriptIgnored       = "script_ignored"

	// The WAN ADDRESS-LEASE (IA_NA) events (#560): addrconf.c's `create`/`update`
	// literals on the address-with-lifetimes line, and its bare `remove`. Distinct
	// from address_added/address_removed above, which are ifaddrconf.c's
	// downstream-interface configuration events and name neither a lifetime.
	dhcp6cEventAddressLeaseCreated = "address_lease_created"
	dhcp6cEventAddressLeaseUpdated = "address_lease_updated"
	dhcp6cEventAddressLeaseRemoved = "address_lease_removed"
)

// The kea-dhcp6 ALLOCATION FAILURE vocabularies (#546). dhcp.go writes them;
// observeDHCP below reads dhcp.alloc_fail_reason to decide what counts.
//
// ONE FAILED ALLOCATION EMITS A BURST OF UP TO THREE LINES SHARING ONE tid, so
// counting every ALLOC_ENGINE_V6_ALLOC_FAIL_* line would report three failures for
// one. Kea's alloc_engine.cc (the `if (network) … else …` and `if (total_attempts ==
// 0) … else …` pairs) guarantees that exactly ONE scope line
// (SHARED_NETWORK|SUBNET) and exactly ONE cause line (NO_POOLS|the bare ALLOC_FAIL)
// fire per failure, with CLASSES an optional extra. The CAUSE line is what is
// counted: it is one-per-failure like the scope line, and unlike it, it carries the
// actionable reason. The scope and classes lines are parsed onto the record and
// deliberately counted nowhere.
//
// THE DUID, THE TRANSACTION ID AND THE SUBNET PREFIX ARE ATTRIBUTES AND NEVER
// LABELS. A DUID is unbounded and identifies a client; a tid is unique per exchange
// and would mint a series per failure; the subnet is an IPv6 prefix, which this
// exporter does not put on labels.
const (
	keaEventAllocFail = "alloc_fail"

	keaAllocFailLineSubnet        = "subnet"
	keaAllocFailLineSharedNetwork = "shared_network"
	keaAllocFailLineNoPools       = "no_pools"
	keaAllocFailLineExhausted     = "exhausted"
	keaAllocFailLineClasses       = "classes"

	// The two COUNTED reasons, and the only two: exactly one of them fires per failed
	// allocation. no_pools means no configured pool was usable for this client at all
	// (a classification or configuration problem); exhausted means pools were tried
	// and every candidate address was already taken.
	keaAllocFailReasonNoPools   = "no_pools"
	keaAllocFailReasonExhausted = "exhausted"
)

// family is the derived metric family a syslog program belongs to (#258).
// familyUnknown is the zero value: a program not in programFamily below.
type family int

const (
	familyUnknown family = iota
	familyFirewall
	familyHAProxy
	familySSHD
	familyDHCP
	familyAudit
	familyIDS
	familyGateway
	familyRADIUS
	familyVPN
	// familyKernel is the FreeBSD kernel's family. It covers THREE observations that
	// share one program name — CARP transitions (#405), netmap host-ring-full reports
	// and ARP address moves (#536) — because `kernel` is a single app-name and a
	// program maps to exactly one family. Which observation fires is decided by which
	// parser's event attribute is present on the record, not by the program.
	//
	// It was `familyCARP` until #536. The rename is not cosmetic: a family named for
	// one of three co-tenants invites the next lane to assume every kernel line is a
	// CARP line, which is the exact mistake the catch-all program name makes easy.
	familyKernel
	familyUPnP
	// familyDHCPClient is the WAN-side DHCP CLIENT (#541), and it is deliberately
	// separate from familyDHCP, which is the DHCP SERVER families (kea, dnsmasq,
	// dhcpd, dhcrelay). They answer opposite questions — "is this firewall handing out
	// leases" versus "does this firewall still have its own WAN address" — and folding
	// the client into the server counter would make the WAN's renewal storm
	// indistinguishable from LAN lease churn, which is precisely the incident #541 was
	// filed for.
	familyDHCPClient
	// familyDHCP6C is the WAN-side DHCPv6 CLIENT (#546) — the IPv6 twin of
	// familyDHCPClient, and separate from it for the same reason familyDHCPClient is
	// separate from familyDHCP. A v4 and a v6 uplink fail independently and their
	// message vocabularies do not overlap (discover/request/ack against
	// solicit/renew/rebind), so folding them into one counter would both mix two closed
	// vocabularies into one open-looking label and make a v6-only outage invisible
	// behind a healthy v4 rate. It also carries what v4 has no equivalent of: the
	// delegated PREFIX and its independent lifetimes.
	familyDHCP6C
)

// programFamily maps every program name a parser in this package registers
// (see the RegisterParser calls in filterlog.go, haproxy.go, sshd.go, dhcp.go,
// audit.go, suricata.go, dpinger.go, freeradius.go and charon.go) onto its derived
// metric family. Dynamic program names go in programPrefixFamily below instead.
// It is built from
// explicit program lists mirroring those calls, on purpose, so it stays in
// lockstep with the parsers: a program registered there without a matching
// entry here — or in nonDerivedPrograms below — fails
// TestEveryParserProgramHasAFamilyDecision (derive_test.go) at build time,
// rather than silently falling through to familyUnknown and under-counting a
// metric forever (#396: dnsmasq-dhcp shipped as a DHCP parser alias with no
// entry here for months before anyone noticed the counter never moved).
var programFamily = map[string]family{
	"filterlog": familyFirewall,

	"haproxy": familyHAProxy,

	"sshd":         familySSHD,
	"sshd-session": familySSHD,

	"dhcpd":        familyDHCP,
	"dnsmasq":      familyDHCP,
	"dnsmasq-dhcp": familyDHCP,
	"kea-dhcp4":    familyDHCP,
	"kea-dhcp6":    familyDHCP,
	"dhcrelay":     familyDHCP,

	"audit":      familyAudit,
	"configd.py": familyAudit,

	"suricata": familyIDS,

	"dpinger": familyGateway,

	"radiusd": familyRADIUS,

	"charon": familyVPN,

	// `kernel` is the FreeBSD CARP (#405), netmap and ARP (#536) source, and it is the
	// ONE entry in this map whose program is a catch-all: every kernel line on the box
	// lands on familyKernel, not just the ones we model. That is safe only because the
	// kernel parsers return ok=false for everything outside a captured shape, so an
	// unrelated kernel line arrives here as a GENERIC record with no carp.event, no
	// netmap.event and no arp.event, and the familyKernel case below refuses to count
	// it. If those parsers are ever loosened, this entry becomes a way to count
	// link-state changes as CARP transitions.
	//
	// Facility-14 CONSOLE output is mis-attributed to `kernel` on OPNsense — rc-script
	// output, interface summaries, SSH host-key fingerprints, Zenarmor's embedded
	// Elasticsearch startup — so the catch-all is wider than "things the kernel said".
	"kernel": familyKernel,

	"miniupnpd": familyUPnP,

	// `dhclient` is the WAN DHCP CLIENT (#541). It is NOT familyDHCP: see the
	// familyDHCPClient comment above.
	"dhclient": familyDHCPClient,

	// `dhcp6c` is the WAN DHCPv6 CLIENT (#546). Same reasoning as dhclient above: it is
	// NOT familyDHCP, which is the DHCP SERVERS this firewall runs.
	"dhcp6c": familyDHCP6C,
}

// programPrefixFamily is programFamily for PREFIX registrations
// (RegisterParserPrefix, registry.go). OpenVPN needs it because OPNsense names one
// syslog program per configured instance — openvpn_server40, openvpn_client2 — so
// no exact entry above can ever reach them.
//
// It gets the same totality guard as programFamily: a registered prefix missing
// from both this map and nonDerivedProgramPrefixes below fails
// TestEveryParserPrefixHasAFamilyDecision (derive_test.go). Without that, a
// dynamic-program family would be the one lane able to parse-and-ship while never
// counting — #396 with a different key type.
var programPrefixFamily = map[string]family{
	"openvpn": familyVPN,
}

// nonDerivedProgramPrefixes is nonDerivedPrograms for PREFIX registrations: an
// explicit, test-pinned decision that a prefix-registered parser deliberately
// derives no metric. Empty today, and that is fine — the guard test requires a
// decision to EXIST, and the only prefix registered so far derives one.
var nonDerivedProgramPrefixes = map[string]bool{}

// nonDerivedPrograms is the explicit, test-pinned allowlist of programs this
// package parses (each has a RegisterParser call of its own) that deliberately
// do NOT belong to any derived metric family. A program earns a
// place here, not by omission: cron/radvd/unbound lines are structured and
// shipped as records, but there is no derived counter family for "a cron job
// ran" or "a router advertisement went out", so observeDerived has nothing to
// bucket them into. TestEveryParserProgramHasAFamilyDecision (derive_test.go)
// requires every registered parser program to appear in exactly one of this map
// or programFamily — never both, never neither — so a future parser alias with
// no derived-family decision fails the build instead of silently
// under-counting, which is exactly how #396 (dnsmasq-dhcp) went unnoticed.
var nonDerivedPrograms = map[string]bool{
	"cron":           true,
	"/usr/sbin/cron": true,
	"radvd":          true,
	"unbound":        true,

	// wireguard and tailscaled (#596) are the awkward pair here, and the decision is
	// deliberate rather than an oversight: both DO write the vpn.event attribute, so
	// they feed the dashboard's Tunnel lifecycle annotation layer (a Loki query over
	// log records, which is what #596 was filed to fix), but neither is counted into
	// opnsense_log_events_vpn_total.
	//
	// Why not: that counter is #406's FROZEN tuple. Its backend dimension is a closed
	// two-value vocabulary, its help text states in so many words that it counts "IPsec
	// (charon) and OpenVPN tunnel lifecycle transitions" from the grammar captured on
	// OPNsense 27.1.a_40, and its `connection` label is resolved from an IPsec ikeid or
	// an OpenVPN instance UUID — identifiers a WireGuard or Tailscale line does not
	// contain, so both would count under a permanently empty connection. Adding a
	// backend value without moving the help text, the generated metrics reference and
	// the log_events panel description in the same change would leave the metric
	// documenting something it no longer does, which is exactly the class of silent
	// drift attrHTTPResponseStatusCode above exists to prevent.
	//
	// Consequence to know about: observeDerived returns false for these programs, so
	// sampleKeep NEVER drops their lines (an uncounted line is always kept). The
	// records themselves are unaffected — they ship with the full vpn triple.
	//
	// Promoting them later is one coherent piece of work, not a one-line edit: add both
	// to programFamily, widen the counter's help text, regenerate docs, and update the
	// panel description that names the two backends.
	"wireguard":  true,
	"tailscaled": true,
}

// deriveFamily reports the derived metric family for a syslog program name.
// ok is false for anything outside the derived families.
//
// Resolution mirrors parserFor exactly — exact name first, then the LONGEST
// matching prefix — because the two must never disagree: a program routed to a
// parser by prefix but to familyUnknown by name would parse, ship, and silently
// never count.
func deriveFamily(program string) (family, bool) {
	if f, ok := programFamily[program]; ok {
		return f, true
	}
	_, f, ok := longestPrefixMatch(programPrefixFamily, program)
	if !ok {
		return familyUnknown, false
	}
	return f, true
}

// observeDerived counts one record's attributes against sink, if program
// belongs to a derived family. counted reports whether a call actually
// happened: a derived program whose key attribute is missing (e.g. a
// filterlog line that failed structured parsing and carries no "action")
// returns false rather than counting a blank label value, so the caller never
// treats an uncounted line as handled — see sampleKeep, which never drops a
// line observeDerived did not count.
func observeDerived(sink logship.MetricSink, program string, attrs map[string]string) (counted bool) {
	fam, ok := deriveFamily(program)
	if !ok {
		return false
	}

	switch fam {
	case familyFirewall:
		// The GATE is the raw wire verb — its presence is what proves the line parsed
		// structurally — but the LABEL is the normalised disposition filterlog.go already
		// computed under AttrAction. Reading the raw verb into the label (which is what
		// this did until #311/#326) put pf's whole open vocabulary on a metric: pass,
		// block and reject where two values exist, plus whatever a NAT/rdr rule emits.
		//
		// MapFilterlogAction returns "" for a verb that is neither a pass nor a deny, so
		// AttrAction is legitimately absent on such a line. It is still COUNTED, under an
		// empty action: refusing it would under-report the counter and, via sampleKeep,
		// exempt the line from sampling for no reason. An empty action means "no stated
		// disposition", which is honest; guessing "block" would not be.
		if attrs["action"] == "" {
			return false
		}
		iface := firstNonEmpty(attrs["interface.name"], attrs["interface"])
		ruleID := firstNonEmpty(attrs["rule.id"], attrs["rule.ref"])
		return sink.ObserveFirewall(attrs[logship.AttrAction], iface, ruleID, attrs["rule.description"], attrs["src.scope"])

	case familyHAProxy:
		event := attrs["haproxy.event"]
		if event == "" {
			return false
		}
		return sink.ObserveHAProxy(event, attrs["haproxy.backend"], attrs["haproxy.server"], attrs["haproxy.state"], statusClass(attrs[attrHTTPResponseStatusCode]))

	case familySSHD:
		result := attrs["auth.result"]
		if result == "" {
			return false
		}
		return sink.ObserveSSHD(result, attrs["auth.method"], attrs["src.scope"])

	case familyDHCP:
		return observeDHCP(sink, attrs)

	case familyAudit:
		event := attrs["event"]
		if event == "" {
			return false
		}
		return sink.ObserveAudit(event, attrs["audit.result"])

	case familyIDS:
		// Same split as familyFirewall: gate on the raw event_type, label with the
		// bounded forms. event_type and severity fold through suricata.go's closed
		// vocabularies, and the action label is the normalised AttrAction rather than
		// Suricata's own "blocked"/"allowed" wire words — alert_category is the one
		// dimension left free-form (rule authors name it), which is what the
		// log_events key budget bounds.
		if attrs["event_type"] == "" {
			return false
		}
		return sink.ObserveIDS(
			mapEveEventType(attrs["event_type"]),
			attrs[logship.AttrAction],
			attrs["alert_category"],
			mapEveSeverity(attrs["alert_severity"]),
		)

	case familyGateway:
		event := attrs["gateway.event"]
		gateway := attrs["gateway.name"]
		if event == "" || gateway == "" {
			return false
		}
		return sink.ObserveGateway(event, gateway)

	case familyRADIUS:
		event := attrs["radius.event"]
		result := attrs["radius.result"]
		clientScope := attrs["radius.client_scope"]
		if event == "" || result == "" || clientScope == "" {
			return false
		}
		return sink.ObserveRADIUS(event, result, clientScope)

	case familyVPN:
		// backend/event/result are the parser's closed, code-defined vocabularies
		// (charon.go, openvpn.go). All three are required: a partial tuple would put a
		// blank value on a dimension that is supposed to be closed.
		backend := attrs[attrVPNBackend]
		event := attrs[attrVPNEvent]
		result := attrs[attrVPNResult]
		if backend == "" || event == "" || result == "" {
			return false
		}
		// connection is the ONE deployment-scale dimension, and it is the API-RESOLVED
		// CONFIGURED NAME only — the #255 tunnel enrichment (tunnels.go) resolving the
		// ikeid / instance UUID against the inventory the metrics collectors already
		// fetch. EMPTY when unresolved, and never the raw UUID: ipsec.connection_id and
		// openvpn.instance_id are deliberately NOT read here. A UUID label would be
		// unbounded (a rebuilt tunnel mints a new one), unreadable, and would leak an
		// internal object id into a metric that outlives the object.
		connection := firstNonEmpty(attrs["ipsec.connection"], attrs["openvpn.instance"])
		return sink.ObserveVPN(backend, event, result, connection)

	case familyKernel:
		return observeKernel(sink, attrs)

	case familyDHCPClient:
		return observeDHCPClient(sink, attrs)

	case familyDHCP6C:
		return observeDHCP6C(sink, attrs)

	case familyUPnP:
		// event and result are both required: they are the two closed dimensions the
		// parser always sets together, so a partial tuple would mean the parser matched a
		// grammar and then failed to classify it. Their absence is also what keeps the
		// EXCLUDED lines uncounted — an `AddPortMapping:` attempt or a `Returning
		// UPnPError` response arrives here as a generic record with no upnp.event.
		event := attrs[attrUPnPEvent]
		result := attrs[attrUPnPResult]
		if event == "" || result == "" {
			return false
		}
		// protocol is LEGITIMATELY EMPTY on three of the five grammars — the two cleanup
		// failures and the lease-file error name no protocol — so it must not gate the
		// observation. Requiring it would refuse the 1,527-occurrence dominant record.
		//
		// The port numbers are deliberately NOT passed: an ephemeral port is unbounded,
		// and they stay on the shipped record. Nor is any mapping count, which #409
		// forbids.
		return sink.ObserveUPnP(event, result, attrs[attrUPnPProtocol])
	}

	return false
}

// observeKernel routes ONE kernel record to whichever of the three co-tenant
// observations its event attribute names (#536).
//
// The dispatch is on the ATTRIBUTE, never on the message text, and every branch is
// gated on an event key the parser only ever sets after a captured shape matched.
// That gate carries the whole weight of `kernel` being a catch-all app-name: every
// kernel line on the box — plus the facility-14 console output OPNsense
// mis-attributes to `kernel` — reaches this function, and the ones no parser
// claimed carry none of these keys, so they fall through uncounted and keep
// shipping as the generic records they always were.
func observeKernel(sink logship.MetricSink, attrs map[string]string) bool {
	if event := attrs[attrNetmapEvent]; event != "" {
		// The DEVICE is the only label. hwcur/hwtail/qlen are ring indices that change
		// on every occurrence and stay on the record.
		return sink.ObserveNetmapRingFull(attrs[attrNetmapDevice])
	}
	if event := attrs[attrARPEvent]; event != "" {
		// The INTERFACE is the only label. The contested IP and both MAC addresses are
		// unbounded and PII-shaped, and stay on the record.
		return sink.ObserveARPMove(attrs[attrARPInterface])
	}
	{
		// carp.event is the gate for the CARP co-tenant, exactly as it was before #536
		// split this out of the inline case: its presence is the proof that a captured
		// CARP shape matched.
		event := attrs[attrCARPEvent]
		if event == "" {
			return false
		}
		// from/to/interface/vhid are LEGITIMATELY EMPTY on a demotion record —
		// FreeBSD's carp_demote_adj is global to the node and names neither an
		// interface nor a vhid — so unlike the vpn case above, they must NOT gate the
		// observation. Requiring them would silently drop half the captured evidence.
		//
		// attrCARPReason, attrCARPDemotionDelta and attrCARPDemotionTotal are
		// deliberately NOT passed. The cause is open-ended free text from the kernel
		// across FreeBSD versions, and the delta/total are unbounded integers; all
		// three stay on the shipped record. Bucketing the cause into a reason_class
		// would invent a taxonomy no capture supports.
		return sink.ObserveCARP(
			event,
			attrs[attrCARPStatePrevious],
			attrs[attrCARPStateCurrent],
			attrs[attrCARPInterface],
			attrs[attrCARPVHID],
		)
	}
}

// observeDHCPClient counts ONE dhclient record (#541). Unlike every other family
// here it can fire MORE THAN ONE observation for a single record, because a
// dhclient line legitimately carries more than one thing worth recording: the
// `bound to` line is both a successful bind (two gauges) and the start of a new
// renewal window.
//
// Each branch is gated on an attribute dhclient.go only sets after a captured shape
// matched, so the daemon's other chatter — `New Hostname (ixl1): opnsense`,
// `Creating resolv.conf` — reaches this function with none of them and is not
// counted.
func observeDHCPClient(sink logship.MetricSink, attrs map[string]string) bool {
	counted := false

	// The message-type counter. `type` is dhclient.go's closed vocabulary, resolved
	// through a map from the wire verb, so an unrecognised verb never reaches a label.
	// interface is EMPTY when the line named none and no PID correlation was available
	// — see dhclient.go. An empty interface is the honest answer, not a missing one.
	if t := attrs[attrDHCPClientType]; t != "" {
		counted = sink.ObserveDHCPClient(attrs[attrDHCPClientInterface], t) || counted
	}

	// The lease gauges. Both are absolute Unix seconds already computed by the parser,
	// so nothing here does wall-clock arithmetic. They are set TOGETHER or not at all:
	// they come from one `bound to` line, and a bound time without its renewal deadline
	// would leave the "renewal stopped" query with nothing to compare against.
	bound, boundOK := parseUnixSeconds(attrs[attrDHCPClientBoundTimestamp])
	renewal, renewalOK := parseUnixSeconds(attrs[attrDHCPClientRenewalTimestamp])
	if boundOK && renewalOK {
		counted = sink.ObserveDHCPClientLease(attrs[attrDHCPClientInterface], bound, renewal) || counted
	}

	// dhclient-script's Reason lines. reason is dhclient's own closed vocabulary from
	// dhclient-script(8), lowercased.
	if reason := attrs[attrDHCPClientScriptReason]; reason != "" {
		counted = sink.ObserveDHCPClientScript(attrs[attrDHCPClientInterface], reason) || counted
	}

	return counted
}

// observeDHCP counts ONE record from a DHCP SERVER program (dhcpd, dnsmasq-dhcp, the
// kea-dhcp{4,6} pair, dhcrelay). Like observeDHCPClient it can fire more than one
// observation, because kea's allocation-failure lines are a different question from
// its lease lines and arrive on the same program.
func observeDHCP(sink logship.MetricSink, attrs map[string]string) bool {
	counted := false

	if action := attrs["dhcp.action"]; action != "" {
		iface := firstNonEmpty(attrs["interface.name"], attrs["interface"])
		counted = sink.ObserveDHCP(action, iface, attrs["dhcp.server_ip"]) || counted
	}

	// The DHCPv6 allocation-failure counter. The gate is deliberately the REASON and
	// not the more general dhcp.alloc_fail_line: only the two CAUSE lines set a reason,
	// so the scope and classes lines of the same burst reach here, find nothing to
	// count, and leave the failure counted exactly once. See the keaAllocFail* block.
	if reason := attrs["dhcp.alloc_fail_reason"]; reason != "" {
		counted = sink.ObserveDHCP6AllocFail(reason) || counted
	}

	return counted
}

// observeDHCP6C counts ONE dhcp6c record (#546). Like observeDHCPClient it can fire
// more than one observation for a single record: a prefix line is both a
// configuration event and the moment three lifetime deadlines are re-established.
//
// Every branch is gated on an attribute dhcp6c.go only sets after a captured or
// source-verified shape matched, so the daemon's other chatter reaches this function
// carrying none of them and is not counted.
func observeDHCP6C(sink logship.MetricSink, attrs map[string]string) bool {
	counted := false

	// The wire-message counter. direction and type are both closed code-defined
	// vocabularies resolved through maps, so no wire token can reach a label. interface
	// is EMPTY on a `Received REPLY` the PID correlation could not resolve — the honest
	// answer, not a missing one.
	if direction := attrs[attrDHCP6CDirection]; direction != "" {
		counted = sink.ObserveDHCP6CMessage(attrs[attrDHCP6CInterface], direction, attrs[attrDHCP6CType]) || counted
	}

	// The configuration/script event counter. reason is legitimately EMPTY on the
	// prefix and address events, which have none, and on script_ignored, whose REASON
	// is a token no capture closes — so it must not gate the observation.
	if event := attrs[attrDHCP6CEvent]; event != "" {
		counted = sink.ObserveDHCP6CEvent(attrs[attrDHCP6CInterface], event, attrs[attrDHCP6CScriptReason]) || counted
	}

	// The prefix-delegation gauges. All three are absolute Unix seconds already
	// computed by the parser, so nothing here does wall-clock arithmetic. They are set
	// TOGETHER or not at all: they come from one line, and a refresh time without its
	// two deadlines leaves "the delegation stopped being renewed" with nothing to
	// compare against.
	updated, updatedOK := parseUnixSeconds(attrs[attrDHCP6CPrefixUpdatedTimestamp])
	preferred, preferredOK := parseUnixSeconds(attrs[attrDHCP6CPrefixPreferredTimestamp])
	valid, validOK := parseUnixSeconds(attrs[attrDHCP6CPrefixValidTimestamp])
	if updatedOK && preferredOK && validOK {
		counted = sink.ObserveDHCP6CPrefix(
			attrs[attrDHCP6CInterface], attrs[attrDHCP6CPrefixLength],
			updated, preferred, valid,
		) || counted
	}

	// The WAN ADDRESS-LEASE gauges (#560), the IA_NA twin of the prefix triple above.
	// Same together-or-not-at-all rule: they come from one line, and a refresh time
	// with no deadlines leaves "the lease stopped renewing" with nothing to compare
	// against.
	addrUpdated, addrUpdatedOK := parseUnixSeconds(attrs[attrDHCP6CAddressLeaseUpdatedTimestamp])
	addrPreferred, addrPreferredOK := parseUnixSeconds(attrs[attrDHCP6CAddressLeasePreferredTimestamp])
	addrValid, addrValidOK := parseUnixSeconds(attrs[attrDHCP6CAddressLeaseValidTimestamp])
	if addrUpdatedOK && addrPreferredOK && addrValidOK {
		counted = sink.ObserveDHCP6CAddress(attrs[attrDHCP6CInterface], addrUpdated, addrPreferred, addrValid) || counted
	}

	// An explicit removal CLEARS the gauge rather than leaving a frozen deadline in
	// place: a frozen lifetime gauge reads as a healthy lease that simply stopped
	// being renewed, which is worse than the series going absent.
	if attrs[attrDHCP6CEvent] == dhcp6cEventAddressLeaseRemoved {
		counted = sink.ClearDHCP6CAddress(attrs[attrDHCP6CInterface]) || counted
	}

	return counted
}

// parseUnixSeconds reads one of the parser's absolute lease timestamps back out of
// the record's string attributes. ok is false for an absent or unparseable value,
// which is what stops a malformed attribute setting a gauge to zero — a zero
// timestamp reads as 1970 and would make every "renewal is overdue" query fire.
func parseUnixSeconds(s string) (float64, bool) {
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return float64(n), true
}

// firstNonEmpty returns a, falling back to b when a is empty.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// statusClass buckets an HTTP status code string into "2xx".."5xx". Empty or
// unparseable input (including anything outside 100-599) yields "".
func statusClass(status string) string {
	if status == "" {
		return ""
	}
	code, err := strconv.Atoi(status)
	if err != nil || code < 100 || code > 599 {
		return ""
	}
	return strconv.Itoa(code/100) + "xx"
}
