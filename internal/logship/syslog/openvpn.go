package syslog

import (
	"regexp"

	"github.com/rknightion/opnsense2otel/v4/internal/logship"
	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
)

// OpenVPN is the second half of the derived `vpn` family (#406).
//
// It is registered on the `openvpn` PREFIX, not an exact program name: OPNsense
// gives every configured instance its own syslog APP-NAME (openvpn_server40,
// openvpn_client2), so an exact-match registration would reach none of them. See
// RegisterParserPrefix in registry.go.
//
// The ONLY grammar parsed here is what was captured on an isolated testbed running
// OPNsense 27.1.a_40 with the OPNsense OpenVPN SERVER package 2.7.5. Four canonical
// sanitized RFC5424 templates were retained, verified byte-identical across two
// independent sanitization passes:
//
//	udp4:<addr>:<port> [<user>] Peer Connection Initiated with [AF_INET]<addr>:<port>
//	udp4:<addr>:<port> SENT CONTROL [UNDEF]: 'AUTH_FAILED' (status=1)
//	udp4:<addr>:<port> VERIFY ERROR: depth=0, error=self-signed certificate: CN=<cn>, serial=<serial>
//	<user>/udp4:<addr>:<port> SIGUSR1[soft,ping-restart] received, client-instance restarting
//
// mapping onto the closed event vocabulary:
//
//	Peer Connection Initiated with               → established           (success)
//	SENT CONTROL […]: 'AUTH_FAILED'              → authentication_failed (failure)
//	VERIFY ERROR:                                → certificate_failed    (failure)
//	SIGUSR1[soft,ping-restart] received, …       → terminated            (success)
//
// (The retained bundle labelled the capture "OpenVPN 2.6.14". That was the Debian
// test CLIENT; `pkg info openvpn` on the box reported 2.7.5, and every template
// above is a server-side line.)
//
// FIVE OTHER REAL LINES WERE CAPTURED AND ARE DELIBERATELY LEFT GENERIC:
//
//	SIGUSR1[soft,tls-error] received, client-instance restarting
//	SIGTERM[soft,delayed-exit] received, client-instance exiting
//	TLS Error: TLS handshake failed
//	TLS Error: TLS object -> incoming plaintext read error
//	Inactivity timeout (--ping-restart), restarting
//
// The reasoning, per line, because "leave it generic" is a decision and not an
// oversight:
//
//   - tls-error is NOT a peer disconnect. Only the ping-restart variant was captured
//     as a genuine one. A control-channel failure often belongs to a session that
//     never established at all, so counting it as `terminated` would mint
//     terminations with no matching `established` and make the pair unreconcilable.
//   - SIGTERM[soft,delayed-exit] is the instance being shut down by the
//     administrator, not the peer going away. #406's own capture assessment already
//     rejected service shutdowns as disconnect evidence.
//   - The two `TLS Error:` lines accompany the certificate rejection that
//     `VERIFY ERROR:` already counts. Counting them too would report three failures
//     for one rejected client.
//   - `Inactivity timeout (--ping-restart), restarting` is the FIRST of the two
//     lines OpenVPN logs for one ping-restart; the SIGUSR1 line counted above is the
//     second. Exactly one of the pair may be counted or every peer timeout counts
//     twice.
//
// PRIVACY. The captured lines carry a username (both in the `[user]` slot and as
// the `user/` peer-context prefix), a certificate CN and serial, and the peer's
// address and port. This parser extracts NONE of them — the metric contract needs
// only the code-defined backend/event/result — and the connection LABEL comes from
// the existing #255 tunnel enrichment (tunnels.go). The identities remain visible in
// the record body, which ships verbatim exactly as it did before this parser existed.
var (
	// openvpnPeerContext is OpenVPN's own multi-client line prefix: the peer context
	// (`udp4:addr:port`, or `user/udp4:addr:port` once the client is named), then an
	// optional bracketed common-name slot — the form the captured
	// `Peer Connection Initiated` template demonstrates. Both are skipped over,
	// never captured.
	openvpnPeerContext = `^\S+ (?:\[[^\]]*\] )?`

	// AF_INET6 is DERIVED FROM OPENVPN'S OWN FAMILY TAG, not captured: the testbed
	// client was IPv4. It is the same message for an IPv6 peer, and without it an
	// IPv6 roadwarrior's establishment would silently never be counted.
	reOpenVPNEstablished = regexp.MustCompile(openvpnPeerContext + `Peer Connection Initiated with \[AF_INET6?\]\S+$`)
	reOpenVPNAuthFailed  = regexp.MustCompile(openvpnPeerContext + `SENT CONTROL \[[^\]]*\]: 'AUTH_FAILED' \(status=\d+\)$`)
	// Anchored on OpenVPN's actual format string — `depth=<n>, error=<text>` — rather
	// than the bare `VERIFY ERROR:` prefix. Expired, revoked and depth-N rejections
	// are all the same event class and all match; a line that merely mentions the
	// words does not. The depth and the error text are matched, never captured: the
	// text carries the certificate subject.
	reOpenVPNCertFailed = regexp.MustCompile(openvpnPeerContext + `VERIFY ERROR: depth=\d+, error=.+$`)
	reOpenVPNTerminated = regexp.MustCompile(openvpnPeerContext + `SIGUSR1\[soft,ping-restart\] received, client-instance restarting$`)
)

func init() {
	// WithBodyEnrichment: same as charon — no address is extracted here, so the
	// generic body scan must keep running or these lines lose the peer.* attributes
	// they carried while they were generic.
	RegisterParserPrefixWithBodyEnrichment(parseOpenVPN, "openvpn")
}

func parseOpenVPN(env Envelope, _ *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	var event, result string
	switch {
	case reOpenVPNEstablished.MatchString(env.Message):
		event, result = vpnEventEstablished, vpnResultSuccess
	case reOpenVPNTerminated.MatchString(env.Message):
		event, result = vpnEventTerminated, vpnResultSuccess
	case reOpenVPNAuthFailed.MatchString(env.Message):
		event, result = vpnEventAuthenticationFailed, vpnResultFailure
	case reOpenVPNCertFailed.MatchString(env.Message):
		event, result = vpnEventCertificateFailed, vpnResultFailure
	default:
		return logship.Record{}, false
	}

	rec, set := newRecord(env)
	set(attrVPNBackend, vpnBackendOpenVPN)
	set(attrVPNEvent, event)
	set(attrVPNResult, result)
	return rec, true
}
