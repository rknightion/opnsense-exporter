package syslog

import (
	"regexp"

	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
)

// Tailscale is the fourth backend of the derived `vpn` family's ATTRIBUTE contract
// (#596), and it is deliberately NODE-LOCAL ONLY: this box's own tunnel state, never
// peer topology. That boundary is the standing one against duplicating what
// `tailscale2otel` owns, and it is also what the log can actually support at default
// verbosity — the per-peer lines are all `[v1]`, which logtail drops unless
// tailscaled was started with -verbose (it is not, by either the FreeBSD port or the
// OPNsense plugin).
//
// TWO ROUTES REACH app-name `tailscaled`, and only one of them is on by default:
//
//  1. THE rc SCRIPT'S OWN `logger` CALLS — always present. FreeBSD ports
//     security/tailscale files/tailscaled.in, tailscaled_poststop:
//     `logger -s -t tailscaled "Destroying ${tailscaled_tun_dev} adapter"` and
//     `… "Failed to destroy ${tailscaled_tun_dev} adapter"`. Facility user, priority
//     notice (logger(1)'s default). Note the prestart/poststart calls use tag
//     `tailscale` WITHOUT the d, so they are a different app-name and not ours.
//
//  2. TAILSCALED'S OWN LOG — OPT-IN. The same rc script runs the daemon as
//     `daemon -f ${tailscaled_syslog_output_flags} …`, and those flags are empty
//     unless `tailscaled_syslog_output_enable` is YES, which defaults to NO and which
//     the OPNsense plugin's generated /etc/rc.conf.d/tailscaled never sets. With `-f`
//     and no syslog flags, stdout and stderr go to /dev/null: on a stock box
//     tailscaled's own lines reach syslog nowhere. When an operator does enable it
//     (rc.conf.local survives config regeneration, since the generated file never
//     assigns the variable) the script passes `-t tailscaled -T tailscaled -s info
//     -l daemon`, so app-name `tailscaled`, facility daemon, priority info.
//     Parsing a grammar that needs a non-default logging setting is the same shape as
//     unbound.go, which only ever sees anything when `log-local-actions: yes` is set.
//
// THE LIFECYCLE EDGE. ipn/ipnlocal/local.go (v1.98.10:6070-6076, the version the
// FreeBSD port pins):
//
//	if oldState == newState {
//	        return
//	}
//
//	b.logf("Switching ipn state %v -> %v (WantRunning=%v, nm=%v)",
//	        oldState, newState, prefs.WantRunning(), netMap != nil)
//
// The early return is the EDGE GUARANTEE, read out of the source rather than assumed:
// the line cannot repeat for an unchanged state, so unlike a WireGuard handshake or a
// DERP health line it can never become a wall of markers. It is not verbose-gated.
// The states are ipn.State's closed seven (ipn/backend.go): NoState, InUseOtherUser,
// NeedsLogin, NeedsMachineAuth, Stopped, Starting, Running.
//
// The mapping:
//
//	… -> Running      → established (this node is up on the tailnet)
//	Running -> …      → terminated  (`tailscale down`, a logout, or an expired node key)
//
// `terminated` REQUIRES the previous state to have been Running. That is what stops
// this minting a termination with no possible establishment — the objection that kept
// OpenVPN's `SIGTERM[soft,delayed-exit]` out of #406's vocabulary. Every other
// transition (NoState -> NeedsLogin on a fresh box, NeedsLogin -> Starting on login,
// Stopped -> Starting on a restart) is a real transition that is neither an
// establishment nor a termination, and stays a generic record.
//
// TWO TRAPS, both from source:
//
//   - THE RATE LIMITER QUOTES OUR OWN FORMAT STRING. cmd/tailscaled wraps logf in
//     `logger.RateLimitedFn(logf, 5*time.Second, 5, 100)` and this format is not in
//     logger.go's rateFree allowlist, so under flapping the daemon emits
//     `[RATELIMIT] format("Switching ipn state %v -> %v (WantRunning=%v, nm=%v)") (3
//     dropped)`. The regex below is anchored at the start of the message (after the
//     optional Go timestamp) precisely so a suppression notice cannot be read as a
//     transition.
//   - PROCESS DEATH IS SILENT. LocalBackend.Shutdown never enters a new ipn state, so
//     `service tailscaled stop`, a SIGTERM or a crash produces NO `Switching ipn
//     state` line. That is exactly why route 1's teardown line is counted as a
//     `terminated` as well, and why the two do not double-count one event: the ipn
//     line covers `tailscale down`, the rc line covers the service stopping. They are
//     disjoint paths, not two lines for one event (contrast openvpn.go's ping-restart
//     pair, where exactly one of two lines may be counted).
//
// `Failed to destroy <dev> adapter` is deliberately NOT an event: the teardown failed,
// so the device's state is precisely what the line does not establish.
//
// PRIVACY. The parsed lines name no peer, no node key and no address: the ipn line
// carries two state words and two booleans, the rc line a device name. The parser
// extracts NONE of them and writes only the code-defined backend/event/result, the
// same contract charon.go and openvpn.go hold. A tailscale.state.* pair would be a
// second vocabulary nothing reads — observeDerived reads vpn.event — and the
// transition's endpoints are already in the body, which ships verbatim.
var (
	// tailscaledGoTimestamp is tailscaled's OWN log timestamp, which is present on the
	// daemon(8) route and absent on the logger(1) one. logpolicy sets
	// `lflags = log.LstdFlags` whenever stderr is not a terminal — which is the case
	// under daemon(8) — so the syslog body carries a second timestamp before the
	// message. TS_DEBUG_LOG_TIME adds microseconds; the native --syslog flag (which
	// does not exist in the packaged 1.98.10) sets the flags to 0 and carries none. All
	// three shapes are tolerated, and the group is matched, never captured.
	tailscaledGoTimestamp = `^(?:\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? )?`

	reTailscaledIPNState = regexp.MustCompile(tailscaledGoTimestamp +
		`Switching ipn state (\w+) -> (\w+) \(WantRunning=(?:true|false), nm=(?:true|false)\)$`)

	// The rc script's poststop teardown. The device name is configurable
	// (tailscaled_tun_dev, default tailscale0), so it is matched and never anchored on.
	reTailscaledDestroyed = regexp.MustCompile(tailscaledGoTimestamp + `Destroying \S+ adapter$`)
)

// ipnStates is ipn.State's closed vocabulary, exactly as State.String() renders it.
// Both sides of a transition are resolved through this map, so an unrecognised state
// name — a future release adding an eighth state, or a body that merely looks like
// the line — yields no event in EITHER direction rather than a guess.
var ipnStates = map[string]bool{
	"NoState":          true,
	"InUseOtherUser":   true,
	"NeedsLogin":       true,
	"NeedsMachineAuth": true,
	"Stopped":          true,
	"Starting":         true,
	"Running":          true,
}

const ipnStateRunning = "Running"

func init() {
	// WithBodyEnrichment: as for charon, openvpn and wireguard — this parser extracts no
	// address of its own, so the generic body scan must keep running rather than silently
	// dropping attributes these lines carried while they were generic.
	RegisterParserWithBodyEnrichment(parseTailscaled, "tailscaled")
}

func parseTailscaled(env Envelope, _ *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	var event string
	switch {
	case reTailscaledDestroyed.MatchString(env.Message):
		event = vpnEventTerminated
	default:
		m := reTailscaledIPNState.FindStringSubmatch(env.Message)
		if m == nil {
			return logship.Record{}, false
		}
		from, to := m[1], m[2]
		if !ipnStates[from] || !ipnStates[to] {
			return logship.Record{}, false
		}
		switch {
		case to == ipnStateRunning:
			event = vpnEventEstablished
		case from == ipnStateRunning:
			event = vpnEventTerminated
		default:
			// A real transition that is neither: it stays a generic record carrying the body
			// verbatim, rather than being forced into a vocabulary it does not belong to.
			return logship.Record{}, false
		}
	}

	rec, set := newRecord(env)
	set(attrVPNBackend, vpnBackendTailscale)
	set(attrVPNEvent, event)
	// No failure case is modelled. Nothing under this app-name states an authentication,
	// certificate or liveness verdict for the tunnel: `Running -> NeedsLogin` is an
	// expired or withdrawn node key, which is a termination whose CAUSE is already
	// covered by the poll lane's opnsense_tailscale_key_expiry_timestamp_seconds.
	set(attrVPNResult, vpnResultSuccess)
	return rec, true
}
