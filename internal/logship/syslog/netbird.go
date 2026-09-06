package syslog

import (
	"strings"

	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
)

// NetBird is the fifth backend of the derived `vpn` family's ATTRIBUTE contract, and
// the one #596 refused and #601 unblocked with a live capture. Two things had to be
// settled before a line of this file could be written, and both were settled against
// the enrolled devel testbed on 2026-07-31, not against upstream source alone.
//
// ONE: THE APP-NAME ON THE WIRE IS THE FULL PATH.
//
// netbird's syslog hook passes an EMPTY tag —
// `lSyslog.NewSyslogHook("", "", syslog.LOG_INFO, "")`, util/syslog_nonwindows.go:17,
// unchanged from the packaged 0.74.4 through ports' 0.76.0 — and Go's log/syslog
// substitutes `os.Args[0]` for an empty tag ($(go env GOROOT)/src/log/syslog/syslog.go).
// The rc script starts the daemon as `%%PREFIX%%/bin/netbird`, so the app-name is
// `/usr/local/bin/netbird`. That was a PREDICTION until #601; the capture confirms it:
// 4,817 of 4,888 retained lines carry it, and 12 carry the rc script's own
// `logger -s -t netbird` app-name `netbird`.
//
// The consequence is bigger than "no parser". `subsystems` held `netbird` only, so
// subsystemFor returned EMPTY for the daemon's app-name and all 4,817 lines shipped
// with no opnsense_subsystem at all — not, as #596 assumed, "generic records with a
// subsystem label". So the Tunnel lifecycle annotation's deliberately wide
// `opnsense_subsystem=~"vpn|ipsec"` filter could not select netbird records even as a
// denominator, and the "wide regex keeps the gap observable" argument did not hold for
// this program. registry.go now carries the daemon app-name too.
//
// TWO: THE LIFECYCLE EDGE IS AT ENGINE GRANULARITY, NOT PEER.
//
// #601 asked whether any netbird line is a genuine lifecycle edge and expected the
// answer to be no, because every candidate it considered was PEER-level and the
// lazy-connection idle timer churns those. That objection is correct and the capture
// confirms it live — the box logs `lazy connection manager is enabled by management
// feature flag` and `inactivity threshold configured: 15m0s`, so on this very tenant a
// peer's connection genuinely does close and reopen on idleness — but it only rules out
// the peer-level lines. The ENGINE-level pair is untouched by lazyconn, and it is the
// same granularity wireguard.go (the tunnel instance) and tailscaled.go (the whole
// node) already settled on:
//
//	Netbird engine started, the IP is: <addr>   → established   client/internal/connect.go:418 @0.74.4 (:438 @0.76.0)
//	stopped NetBird client                      → terminated    client/internal/connect.go:444 @0.74.4 (:464 @0.76.0)
//
// WHY THE PAIR IS BALANCED, read out of the control flow rather than assumed. Both
// lines live in ONE function: the closure `operation` that connect.go hands to
// backoff.Retry. The established line sits immediately after `engine.Start(...)`
// returns nil and immediately before `state.Set(StatusConnected)`; every earlier
// failure path — no management client, login refused, relay token rejected, engine
// start error — does `return wrapErr(err)` before reaching it. The terminated line is
// the closure's LAST statement, after `<-engineCtx.Done()`, `engine.Stop()` and
// `statusRecorder.ClientTeardown()`. So a `terminated` cannot be minted without an
// `established` earlier in the same iteration, which is the objection that kept
// OpenVPN's daemon shutdown out of #406's vocabulary.
//
// The capture is the empirical half of that argument, and it is a stronger check than
// counting matches: across 18 days it holds 5 establishments and 4 terminations, the
// difference being the session still running when the log was read. It also holds six
// earlier daemon start/stop cycles from before the box was enrolled — 248
// `failed to login to Management Service` lines and not one engine start — which is a
// live demonstration that this pair tracks overlay connectivity and not the service.
//
// FIVE FAMILIES OF LINE UNDER THIS APP-NAME ARE DELIBERATELY LEFT GENERIC:
//
//   - `stopped Netbird Engine` (engine.go:355) DOUBLE-LOGS. Two call sites reach
//     Engine.Stop() on one teardown — connect.go:437 after the engine context is
//     cancelled, and the daemon server's down path at client/server/server.go:999,
//     which upstream itself flags with `// TODO: consider calling
//     connectClient.Stop() instead of engine.Stop().` Observed twice per teardown on
//     4 of 4 teardowns, same PID, same second. It is the obvious-looking teardown line
//     and it is the wrong one.
//   - `starting NetBird service` / `stopped NetBird service` are the DAEMON PROCESS,
//     not the overlay. Six such pairs in the capture bracket periods with no tunnel at
//     all. Counting them would mint six false establishments in 18 days on one box.
//     `Starting netbird.` — the rc script's line, under app-name `netbird` — is the
//     same event and is excluded for the same reason.
//   - PEER-LEVEL lines, all of them: `set ICE to active connection` (which also fires
//     on a relay→ICE upgrade mid-session, so it is not even an establishment),
//     `close peer connection`, `peer connection closed`, `first wg handshake detected
//     within`, and the lazyconn bookkeeping. Two reasons, either sufficient: the idle
//     timer above makes their meaning deployment-dependent and unknowable from the log,
//     and per-peer VPN topology is out of scope by the standing boundary this repo
//     holds for Tailscale as well.
//   - CONTROL-PLANE reachability: `connected to the Management Service stream`,
//     `reconnected to Signal or Relay server`, the relay connect/close pair, and
//     `disconnected from the Management service but will retry silently`. The tunnel
//     survives all of them — the last one says so in the line itself.
//   - `ensuring wg interface is removed, Netbird engine context cancelled` and
//     `interface wt0 has been removed` report STEPS of a teardown whose completion
//     `stopped NetBird client` already marks. Counting both would double-count one
//     event, the rule openvpn.go applies to the ping-restart pair.
//
// NO FAILURE CASE IS MODELLED. Nothing in this pair states an authentication,
// certificate or liveness verdict: a refused login produces no engine start, so the
// absence of an `established` is the signal, and the login refusal itself is a
// control-plane fact the netbird collector's poll lane reports as `daemonStatus`.
//
// NO TIMESTAMP PREFIX TO TOLERATE, unlike tailscaled.go. These lines reach syslog
// through logrus's syslog hook, which writes the formatted message only; the capture
// confirms it. (Lines netbird relays from gRPC's own logger DO carry a `2026/07/31
// 12:34:56` prefix, but none of them is in this grammar.)
//
// PRIVACY. The established line carries this node's overlay address and nothing else;
// the terminated line carries no field at all. This parser extracts NEITHER, writing
// only the code-defined backend/event/result triple, as charon, openvpn, wireguard and
// tailscaled all do. The address stays in the body, which ships verbatim exactly as it
// did while these lines were generic, and the generic body scan this parser opts into
// resolves it the same way it always has.
const (
	// netbirdDaemonProgram is argv[0] as the rc script invokes it. It is a captured
	// literal, not a guess at PREFIX: registering the wrong path would look handled and
	// fire never, which is worse than no registration at all.
	netbirdDaemonProgram = "/usr/local/bin/netbird"

	// Matched as a PREFIX: the value is `peerConfig.GetAddress()`, a management-supplied
	// string, so anchoring on today's IPv4/CIDR shape would make the parser stop working
	// the day that changes. Matched as a plain string rather than a regexp because the
	// text before the address is fixed — there is nothing to capture, and the two
	// grammars are on the hot path of every line this app-name sends.
	netbirdEngineStartedPrefix = "Netbird engine started, the IP is: "

	// Matched exactly, so `stopped NetBird clients` or a line that merely ends with this
	// text cannot reach the attribute.
	netbirdClientStopped = "stopped NetBird client"
)

func init() {
	// WithBodyEnrichment, as for charon, openvpn, wireguard and tailscaled: this parser
	// extracts no address of its own. Here it is a REGRESSION guard rather than a
	// nicety — these lines have shipped as generic records since the receiver existed,
	// so they carry peer.* and interface.name today, and a parser that opted out would
	// silently take those away from anyone already querying them.
	RegisterParserWithBodyEnrichment(parseNetbird, netbirdDaemonProgram)
}

func parseNetbird(env Envelope, _ *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	var event string
	switch {
	case strings.HasPrefix(env.Message, netbirdEngineStartedPrefix):
		event = vpnEventEstablished
	case env.Message == netbirdClientStopped:
		event = vpnEventTerminated
	default:
		return logship.Record{}, false
	}

	rec, set := newRecord(env)
	set(attrVPNBackend, vpnBackendNetBird)
	set(attrVPNEvent, event)
	set(attrVPNResult, vpnResultSuccess)
	return rec, true
}
