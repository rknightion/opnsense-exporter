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
	familyCARP
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

	// `kernel` is the FreeBSD CARP source (#405), and it is the ONE entry in this map
	// whose program is a catch-all: every kernel line on the box lands on
	// familyCARP, not just the CARP ones. That is safe only because carp.go returns
	// ok=false for everything that is not one of the two captured CARP shapes, so an
	// unrelated kernel line arrives here as a GENERIC record with no carp.event, and
	// the familyCARP case below refuses to count it. If that parser is ever loosened,
	// this entry becomes a way to count link-state changes as CARP transitions.
	"kernel": familyCARP,
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
		action := attrs["dhcp.action"]
		if action == "" {
			return false
		}
		iface := firstNonEmpty(attrs["interface.name"], attrs["interface"])
		return sink.ObserveDHCP(action, iface, attrs["dhcp.server_ip"])

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

	case familyCARP:
		// carp.event is the ONLY gate, and it carries the whole weight of the `kernel`
		// program being a catch-all: every kernel line on the box reaches this case, and
		// the ones carp.go declined to parse have no carp.event, so they are not counted.
		// Its presence is therefore the proof that a captured CARP shape matched.
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

	return false
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
