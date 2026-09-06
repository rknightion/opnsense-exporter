package syslog

import (
	"net/netip"
	"regexp"

	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
)

// ppp is mpd5, the PPPoE dialler that brings the WAN up on OPNsense (#631). It logs
// under program tag "ppp" and, distinctly, the rc.d linkup/linkdown scripts log under
// their own literal `ppp-linkup:`/`ppp-linkdown:` message prefix (still program
// "ppp") once the interface change has been applied. A single WAN flap produces
// three interleaved state machines — LCP (per-LINK), IPCP/IPV6CP (per-BUNDLE) — plus
// the bundle and interface framing around them, which is why this parser is scoped
// down to the operationally meaningful subset rather than modelling every mpd log
// line: mpd's chatter is enormous (100+ distinct shapes in one flap) and most of it
// (COMPPROTO/MAGICNUM/MRU negotiation trivia, interface renames, `is OK` pings) has
// no metric or query anyone would write against it.
//
// ALL SHAPES BELOW ARE FROM ONE VERBATIM CAPTURE (2026-07-27) of a single flap event
// on a real WAN (bundle "opt7", link "opt7_link0"). Nothing here is inferred from mpd
// source — only the subset actually seen is modelled, and everything else
// deliberately falls through to a generic record.
//
// BUNDLE VS LINK SCOPING IS DERIVED FROM THE CAPTURE, NOT GUESSED: mpd brackets every
// line with the name of the state machine that emitted it — `[opt7]` for
// bundle-level machinery (IFACE, Bundle, IPCP, IPV6CP, the assigned-address lines)
// and `[opt7_link0]` for link-level machinery (Link, LCP, PPPoE, CHAP auth). The
// capture shows this split consistently: LCP negotiates per physical link, IPCP and
// IPV6CP negotiate per bundle (mpd's architecture — a bundle can stack multiple
// links). So each branch below hardcodes which of ppp.bundle/ppp.link it emits based
// on which protocol/context produced it in the capture, rather than trying to infer
// bundle-vs-link from the bracket name's shape.
//
// PRIVACY (non-negotiable, #631): mpd's authentication lines carry the subscriber's
// own PPPoE credentials on the wire — the CHAP authname (`rk83@a.1`), the `MESG:`
// circuit-id tag, and the LCP MAGICNUM. NONE of these values may ever become an
// attribute. This parser only ever reports the authentication OUTCOME (LCP:
// authorization successful); the CHAP username/challenge/response lines and the
// MESG/MAGICNUM lines are deliberately left unmodelled so nobody is tempted to lift a
// value out of them later. Do not add a `set(..., match[n])` call that touches an
// authname, a MESG value or a MAGICNUM — see TestPPPNeverEmitsAuthname.
var (
	// reBracket splits mpd's `[<name>] <rest>` framing common to every bundle/link
	// line. The name is whatever mpd named that bundle or link (deployment-specific,
	// e.g. "opt7"/"opt7_link0" in the capture) — never a closed vocabulary itself.
	reBracket = regexp.MustCompile(`^\[(\S+)\]\s+(.*)$`)

	// Link: UP/DOWN event. Captured only under the LINK bracket (opt7_link0).
	rePPPLinkUpDown = regexp.MustCompile(`^Link: (UP|DOWN) event$`)

	// IFACE: Up/Down event — note mpd's own inconsistent capitalisation (Up/Down here
	// vs UP/DOWN for Link above), preserved verbatim from the capture. Captured only
	// under the BUNDLE bracket (opt7).
	rePPPIfaceUpDown = regexp.MustCompile(`^IFACE: (Up|Down) event$`)

	// Link: reconnection attempt <n>[ in <n> seconds]. Both forms were captured;
	// the "in N seconds" tail is optional. Captured under the LINK bracket.
	rePPPReconnect = regexp.MustCompile(`^Link: reconnection attempt (\d+)(?: in (\d+) seconds)?$`)

	// Bundle: Status update: up <n> link(s), total bandwidth <n> bps. Both the
	// singular "1 link" and plural "0 links" forms were captured. Captured under the
	// BUNDLE bracket.
	rePPPBundleStatus = regexp.MustCompile(`^Bundle: Status update: up (\d+) links?, total bandwidth (\d+) bps$`)

	// <PROTOCOL>: state change <From> --> <To>. LCP was captured under the LINK
	// bracket; IPCP/IPV6CP were captured under the BUNDLE bracket.
	rePPPStateChange = regexp.MustCompile(`^(LCP|IPCP|IPV6CP): state change (\S+) --> (\S+)$`)

	// LCP: rec'd Terminate Request #<n> (<state>). Captured under the LINK bracket.
	rePPPTerminateRecv = regexp.MustCompile(`^LCP: rec'd Terminate Request #(\d+) \((\S+)\)$`)

	// IPCP|IPV6CP: SendTerminateReq #<n>. Captured under the BUNDLE bracket.
	rePPPSendTerminateReq = regexp.MustCompile(`^(IPCP|IPV6CP): SendTerminateReq #(\d+)$`)

	// PPPoE: connection successful / connection closed / can't connect ... — the
	// session-lifecycle trio. All three were captured under the LINK bracket.
	rePPPoESuccess = regexp.MustCompile(`^PPPoE: connection successful$`)
	rePPPoEClosed  = regexp.MustCompile(`^PPPoE: connection closed$`)
	rePPPoEFailed  = regexp.MustCompile(`^PPPoE: (can't connect .+)$`)

	// LCP: authorization successful. Captured under the LINK bracket. This is the
	// ONLY authentication-related line this parser matches — see the privacy note
	// above for why the CHAP lines that surround it in the capture are not modelled.
	rePPPAuthSuccess = regexp.MustCompile(`^LCP: authorization successful$`)

	// The bare "<local> -> <peer>" line inside a bundle bracket. This same shape
	// carries TWO different meanings in the capture: an assigned WAN address
	// (both sides parse as an IP) or an IPv6 interface-identifier pair (neither side
	// is a full address — 4 hex groups, no "::"). The two are told apart below by
	// attempting netip.ParseAddr on both sides, never by the bracket or by guessing
	// from shape. Captured under the BUNDLE bracket.
	rePPPAddress = regexp.MustCompile(`^(\S+) -> (\S+)$`)

	// ppp-linkup:/ppp-linkdown: executing on <iface> for <af>. These are NOT
	// bracketed — they come from the rc.d script's own logger call, not mpd itself.
	rePPPLinkupLinkdownScript = regexp.MustCompile(`^ppp-link(up|down): executing on (\S+) for (inet6?)$`)
)

func init() {
	RegisterParser(parsePPP, "ppp")
}

func parsePPP(env Envelope, _ *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	// The rc.d linkup/linkdown script lines are unbracketed and program-wide, so try
	// them before the bracket split below.
	if m := rePPPLinkupLinkdownScript.FindStringSubmatch(env.Message); m != nil {
		event := "iface_up"
		if m[1] == "down" {
			event = "iface_down"
		}
		rec, set := newRecord(env)
		set("ppp.event", event)
		set("ppp.interface", m[2])
		set("ppp.address_family", m[3])
		return rec, true
	}

	m := reBracket.FindStringSubmatch(env.Message)
	if m == nil {
		// Everything else — mpd's protocol trivia, interface renames, keepalive
		// pings, and any shape this box has never emitted — keeps shipping generic.
		return logship.Record{}, false
	}
	bracket, rest := m[1], m[2]

	if lm := rePPPLinkUpDown.FindStringSubmatch(rest); lm != nil {
		event := "link_up"
		if lm[1] == "DOWN" {
			event = "link_down"
		}
		rec, set := newRecord(env)
		set("ppp.event", event)
		set("ppp.link", bracket)
		return rec, true
	}

	if lm := rePPPIfaceUpDown.FindStringSubmatch(rest); lm != nil {
		event := "iface_up"
		if lm[1] == "Down" {
			event = "iface_down"
		}
		rec, set := newRecord(env)
		set("ppp.event", event)
		set("ppp.bundle", bracket)
		return rec, true
	}

	if lm := rePPPReconnect.FindStringSubmatch(rest); lm != nil {
		rec, set := newRecord(env)
		set("ppp.event", "reconnecting")
		set("ppp.link", bracket)
		set("ppp.retry_attempt", lm[1])
		set("ppp.retry_delay_seconds", lm[2]) // empty when the "in N seconds" tail is absent; set() drops empties
		return rec, true
	}

	if lm := rePPPBundleStatus.FindStringSubmatch(rest); lm != nil {
		rec, set := newRecord(env)
		set("ppp.event", "bundle_status")
		set("ppp.bundle", bracket)
		set("ppp.links_up", lm[1])
		set("ppp.bandwidth_bps", lm[2])
		return rec, true
	}

	if lm := rePPPStateChange.FindStringSubmatch(rest); lm != nil {
		rec, set := newRecord(env)
		set("ppp.event", "negotiation_state_change")
		set("ppp.protocol", lm[1])
		setPPPScope(set, lm[1], bracket)
		set("ppp.state.previous", lm[2])
		set("ppp.state.current", lm[3])
		return rec, true
	}

	if lm := rePPPTerminateRecv.FindStringSubmatch(rest); lm != nil {
		rec, set := newRecord(env)
		set("ppp.event", "terminate_requested")
		set("ppp.protocol", "LCP")
		set("ppp.link", bracket)
		set("ppp.state.previous", lm[2])
		return rec, true
	}

	if lm := rePPPSendTerminateReq.FindStringSubmatch(rest); lm != nil {
		rec, set := newRecord(env)
		set("ppp.event", "terminate_requested")
		set("ppp.protocol", lm[1])
		set("ppp.bundle", bracket)
		return rec, true
	}

	if rePPPoESuccess.MatchString(rest) {
		rec, set := newRecord(env)
		set("ppp.event", "session_established")
		set("ppp.link", bracket)
		return rec, true
	}

	if rePPPoEClosed.MatchString(rest) {
		rec, set := newRecord(env)
		set("ppp.event", "session_closed")
		set("ppp.link", bracket)
		return rec, true
	}

	if lm := rePPPoEFailed.FindStringSubmatch(rest); lm != nil {
		rec, set := newRecord(env)
		set("ppp.event", "session_failed")
		set("ppp.link", bracket)
		set("ppp.error", lm[1])
		return rec, true
	}

	if rePPPAuthSuccess.MatchString(rest) {
		rec, set := newRecord(env)
		set("ppp.event", "auth_success")
		set("ppp.link", bracket)
		return rec, true
	}

	if lm := rePPPAddress.FindStringSubmatch(rest); lm != nil {
		// Only an address pair where BOTH sides parse as a full IP counts as an
		// assignment. The IPv6 interface-identifier form in the capture
		// ("9ab7:85ff:fe21:aff2 -> 9e89:1eff:fe2e:0000") is 4 hex groups with no
		// "::" — not a valid address on either side — and netip.ParseAddr rejects
		// it, which is exactly the discriminator: no guessing from shape or from
		// which bracket it appeared under.
		if _, err := netip.ParseAddr(lm[1]); err == nil {
			if _, err := netip.ParseAddr(lm[2]); err == nil {
				rec, set := newRecord(env)
				set("ppp.event", "address_assigned")
				set("ppp.bundle", bracket)
				set("ppp.address.local", lm[1])
				set("ppp.address.peer", lm[2])
				return rec, true
			}
		}
	}

	// Everything else under a recognised bracket — COMPPROTO/MAGICNUM/MRU/PROTOCOMP
	// negotiation trivia, interface renames, keepalive "is OK" pings, CHAP lines
	// (deliberately unmodelled, see the privacy note above), Link: Join/Leave/Matched
	// bundle chatter, and any shape this box has never emitted — keeps shipping
	// generic.
	return logship.Record{}, false
}

// setPPPScope records which state machine produced a negotiation-state-change line.
// LCP negotiates per physical LINK; IPCP and IPV6CP negotiate per BUNDLE (mpd can
// stack multiple links under one bundle) — this split is read directly off the
// capture (see the file comment), not inferred from the bracket name's shape.
func setPPPScope(set func(k, v string), protocol, bracket string) {
	if protocol == "LCP" {
		set("ppp.link", bracket)
		return
	}
	set("ppp.bundle", bracket)
}
