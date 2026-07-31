package syslog

import (
	"regexp"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// WireGuard is the third backend of the derived `vpn` family's ATTRIBUTE contract
// (#596). Its programs sat in the subsystem map with no parser since the map was
// written, so every WireGuard line shipped generic and the dashboard's Tunnel
// lifecycle annotation layer — which filters `vpn_event=~"established|terminated"` —
// could never mark a WireGuard tunnel. Its silence on such a box read as "no tunnel
// flaps" when it meant "no parser" (#591's headline failure shape).
//
// WHAT PRODUCES app-name `wireguard`, and what does NOT. This is the whole design,
// so it is written down rather than assumed:
//
// OPNsense drives the FreeBSD IN-KERNEL driver (`ifconfig wg create`,
// src/etc/inc/plugins.inc.d/wireguard.inc) — never wireguard-go, which core
// explicitly conflicts with (Mk/version.mk CORE_CONFLICTS). There are therefore TWO
// producers, and OPNsense's own syslog-ng filter names both:
//
//	filter f_local_wireguard {
//	    program("wireguard");
//	    or (program("kernel") and message("wg[0-9]+:"));
//	};
//	-- core src/opnsense/service/templates/OPNsense/Syslog/local/wireguard.conf
//
// PRODUCER ONE, app-name `wireguard`, is OPNsense's OWN service-control script, which
// opens syslog as `openlog("wireguard", LOG_ODELAY, LOG_AUTH)` —
// core src/opnsense/scripts/wireguard/wg-service-control.php:204. Everything this file
// parses comes from there, and that script's five syslog() calls are the COMPLETE set
// of lines this app-name can carry. Verified byte-identical on core master and on
// stable/26.7, stable/26.1 and stable/25.7 (2026-07-31).
//
// PRODUCER TWO is the kernel driver, and it is out of reach here: every per-peer
// handshake, keepalive and rejection line arrives under app-name `kernel`, NOT
// `wireguard` (sources/001-local.conf gives /dev/klog program-override("kernel")), and
// every one of them is behind `#define DPRINTF(sc, ...) if (if_getflags(sc->sc_ifp) &
// IFF_DEBUG) if_printf(...)` — sys/dev/wg/if_wg.c:70 — i.e. OFF unless the operator
// ticks a per-instance "Debug Log" box that defaults to 0 (Wireguard/Server.xml). This
// parser is not registered for `kernel` and claims none of them.
//
// THE EDGE PROBLEM, AND WHY IT DOES NOT ARISE HERE. A WireGuard peer re-handshakes
// roughly every 120s while it is healthy (REKEY_AFTER_TIME, if_wg.c), so a parser
// that read `Sending handshake initiation to peer 3` as `established` would emit a
// marker every two minutes per peer and turn the annotation layer into a solid wall.
// There is also NO "handshake completed" line in either implementation — a
// successful handshake only bumps a timestamp (wg_timers_event_handshake_complete),
// so the up-edge is not expressible from handshake lines at all. What IS expressible
// is the SERVICE lifecycle: the three grammars below are logged once per transition
// by the script that performs the transition.
//
// The mapping, and why each event is what it is:
//
//	wireguard instance <name> (<dev>) started        → established (the interface now exists and carries traffic)
//	wireguard instance <name> (<dev>) stopped        → terminated  (legacy_interface_destroy; the tunnel is gone)
//	wireguard instance <name> (<dev>) switching to UP   → established (CARP promotion; the tunnel starts passing traffic)
//	wireguard instance <name> (<dev>) switching to DOWN → terminated  (CARP demotion; it stops)
//
// The unit is the INSTANCE, not a peer, and that is the honest granularity: nothing
// reaching this app-name mentions a peer at all. Unlike openvpn.go — where a daemon
// shutdown was rejected as a `terminated` because its pair is per-CLIENT-SESSION and
// a shutdown would mint a termination with no matching establishment — both sides of
// this vocabulary are instance-level, so the pair is balanced. (A `configure` action
// can still log `started` without a preceding `stopped`, so establishments may
// outnumber terminations; that asymmetry is the same one OpenVPN's has.)
//
// THREE REAL LINES UNDER THIS APP-NAME ARE DELIBERATELY LEFT GENERIC:
//
//   - `Wireguard configure event instance <name> (<dev>) vhid: <n> carp: <status>
//     interface: <up|down|->` (wg-service-control.php:265) reports the CURRENT status
//     on every CARP configure event, whether or not anything changed. It is a
//     traceability line, not a transition, and counting it would mark the graph on
//     every CARP event including the no-ops — exactly the wall of markers this
//     parser's whole shape avoids.
//   - `… can not reconfigure without stopping it first.` (:286) announces that the
//     reconfigure needs a restart. The script then calls wg_start, which logs the
//     `started` line already counted above. Counting both would double-count one
//     restart, the same rule openvpn.go applies to the ping-restart pair.
//   - A failing shell command, logged under this app-name because
//     OPNsense\Core\Shell inherits whatever ident the caller opened:
//     `<script>: The command <…> returned exit code N and the output was "…"`. It is
//     a command failure, not a stated tunnel transition; nothing in it says whether
//     the tunnel is up.
//
// PRIVACY. The lines carry the administrator's instance NAME and the tunnel device.
// This parser extracts NEITHER — the contract is the code-defined
// backend/event/result, as it is for charon and openvpn. The device is resolved to
// its friendly interface name by the generic body scan this parser opts into
// (deviceRe already matches `wg\d+`), and the name stays in the body, which ships
// verbatim exactly as it did before this parser existed. The kernel driver's peer
// identifier, for the record, is a numeric `p_id` and never a public key — so even
// the lines this file does not claim carry no key material.
var (
	// The instance name is free text an administrator typed and the device number is
	// whatever OPNsense assigned, so neither is anchored on. The `(dev)` group is
	// matched, never captured.
	wireguardInstance = `^wireguard instance .+ \(\S+\) `

	reWireGuardStarted = regexp.MustCompile(wireguardInstance + `started$`)
	reWireGuardStopped = regexp.MustCompile(wireguardInstance + `stopped$`)
	// strtoupper($carp_if_flag) over 'up'/'down', so the token is always uppercase.
	// This line is itself edge-guarded upstream: the script logs it inside
	// `} elseif ($ifstatus != $carp_if_flag) {`, i.e. only when the interface's current
	// flag differs from the one CARP wants.
	reWireGuardSwitching = regexp.MustCompile(wireguardInstance + `switching to (UP|DOWN)$`)
)

func init() {
	// WithBodyEnrichment: same as charon and openvpn — this parser extracts no address
	// of its own, so the generic body scan must keep running or these lines lose the
	// peer.* and interface.* attributes they carried while they were generic. Here the
	// interface resolution is the point: it turns `(wg1)` into the name the admin gave
	// the interface.
	RegisterParserWithBodyEnrichment(parseWireGuard, "wireguard")
}

func parseWireGuard(env Envelope, _ *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	var event string
	switch {
	case reWireGuardStarted.MatchString(env.Message):
		event = vpnEventEstablished
	case reWireGuardStopped.MatchString(env.Message):
		event = vpnEventTerminated
	default:
		m := reWireGuardSwitching.FindStringSubmatch(env.Message)
		if m == nil {
			return logship.Record{}, false
		}
		// The direction decides the event, and it is resolved from a two-value literal
		// match rather than from the token itself, so nothing on the wire can reach the
		// attribute even if the regex is later loosened.
		if m[1] == "UP" {
			event = vpnEventEstablished
		} else {
			event = vpnEventTerminated
		}
	}

	rec, set := newRecord(env)
	set(attrVPNBackend, vpnBackendWireGuard)
	set(attrVPNEvent, event)
	// Every confirmed grammar is an intended administrative or CARP transition. There
	// is no failure case to model: this app-name carries no authentication, certificate
	// or liveness verdict at all — the kernel driver owns those, behind IFF_DEBUG and
	// under app-name `kernel`.
	set(attrVPNResult, vpnResultSuccess)
	return rec, true
}
