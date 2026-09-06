package syslog

import (
	"regexp"

	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
)

// strongSwan's charon daemon is the IPsec half of the derived `vpn` family (#406).
//
// The ONLY grammar parsed here is what was captured on an isolated testbed running
// OPNsense 27.1.a_40 with strongSwan 6.0.7. Four canonical sanitized RFC5424
// templates were retained, verified byte-identical across two independent
// sanitization passes:
//
//	00[ENC] <UUID|1> generating IKE_AUTH response 1 [ N(AUTH_FAILED) ]
//	00[IKE] <UUID|1> IKE_SA UUID[1] established between 192.0.2.1[local-id]...192.0.2.2[remote-id]
//	00[IKE] <UUID|1> giving up after 5 retransmits
//	00[IKE] <UUID|1> IKE_SA deleted
//
// mapping onto the closed event vocabulary:
//
//	N(AUTH_FAILED) in a generated IKE_AUTH response  → authentication_failed (failure)
//	IKE_SA … established between …                   → established           (success)
//	giving up after N retransmits                    → liveness_failed        (failure)
//	IKE_SA deleted                                   → terminated            (success)
//
// NOTHING ELSE IS PARSED, and nothing is inferred. CHILD_SA establishment, rekeys,
// DPD probes, individual retransmits, `deleting IKE_SA`, and every stable-release
// form (none was ever captured — the read-only 26.7.1_1 log search found zero
// lifecycle records) stay generic records carrying the body verbatim. A charon line
// this file does not recognise is still shipped and still debug-captured as
// unmodelled; it is simply not counted as a transition we did not witness.
//
// PRIVACY. The captured lines carry an IKE identity pair, both tunnel endpoint
// addresses and the raw ikeid UUID. This parser extracts NONE of them: the metric
// contract needs only the code-defined backend/event/result, and the connection
// LABEL comes from the existing #255 tunnel enrichment (tunnels.go), which resolves
// the ikeid to the name the admin configured. The identities remain visible in the
// record body, which ships verbatim exactly as it did before this parser existed.
var (
	// charonThreadPrefix is strongSwan's own line prefix: a thread number and a
	// subsystem tag. The thread number is whichever worker happened to log the line
	// and varies freely for the same event, so anchoring on a literal 00[IKE] would
	// silently stop counting as soon as the daemon is busy. The optional <name|id>
	// group that follows is the IKE_SA context; it is skipped over, never captured.
	charonThreadPrefix = `^\d+\[[A-Z]+\] (?:<[^>]*> )?`

	// AUTH_FAILED anywhere in a GENERATED IKE_AUTH response's payload list, as a
	// whole token. Requiring it to be the SOLE payload would silently drop a real
	// authentication failure that happened to carry another notify alongside it; the
	// token boundaries are what stop N(AUTH_FAILED_ANYTHING) matching.
	//
	// `generating` is load-bearing: this is RESPONDER side, the box rejecting a peer.
	// The initiator-side form — `parsed IKE_AUTH response … N(AUTH_FAILED)`, our own
	// credentials rejected by the far end — is a genuinely DIFFERENT event and was
	// never captured, so it is deliberately not counted. A future capture should add
	// it as its own case; its absence here is a decision, not an oversight.
	reCharonAuthFailed = regexp.MustCompile(charonThreadPrefix +
		`generating IKE_AUTH response \d+ \[(?: [^ \]]+)* N\(AUTH_FAILED\)(?: [^ \]]+)* \]$`)
	reCharonEstablished = regexp.MustCompile(charonThreadPrefix + `IKE_SA \S+\[\d+\] established between .+$`)
	reCharonLiveness    = regexp.MustCompile(charonThreadPrefix + `giving up after \d+ retransmits$`)
	reCharonTerminated  = regexp.MustCompile(charonThreadPrefix + `IKE_SA deleted$`)
)

func init() {
	// WithBodyEnrichment: this parser extracts no address of its own, so the generic
	// body scan must keep running — charon lines have carried peer.* since #250 and
	// must not lose it just because they are now structured.
	RegisterParserWithBodyEnrichment(parseCharon, "charon")
}

func parseCharon(env Envelope, _ *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	var event, result string
	switch {
	case reCharonEstablished.MatchString(env.Message):
		event, result = vpnEventEstablished, vpnResultSuccess
	case reCharonTerminated.MatchString(env.Message):
		event, result = vpnEventTerminated, vpnResultSuccess
	case reCharonAuthFailed.MatchString(env.Message):
		event, result = vpnEventAuthenticationFailed, vpnResultFailure
	case reCharonLiveness.MatchString(env.Message):
		event, result = vpnEventLivenessFailed, vpnResultFailure
	default:
		return logship.Record{}, false
	}

	rec, set := newRecord(env)
	set(attrVPNBackend, vpnBackendIPsec)
	set(attrVPNEvent, event)
	set(attrVPNResult, result)
	return rec, true
}
