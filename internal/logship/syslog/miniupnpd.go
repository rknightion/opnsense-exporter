package syslog

import (
	"regexp"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// miniupnpd is the UPnP IGD / NAT-PMP / PCP daemon shipped by OPNsense's os-upnp
// plugin, which installs a syslog-ng filter naming APP-NAME `miniupnpd` (#409).
//
// THE FIVE GRAMMARS BELOW ARE THE ONLY ONES PARSED, and every one of them is
// captured. Four come from a strictly read-only scan of production (OPNsense
// 26.7.1_1, miniupnpd 2.3.9_2,1, os-upnp 1.9): 1,598 real records over five days,
// severity census `<29>` daemon.notice 1,595 and `<27>` daemon.err 4. Counts:
//
//	1527  could not find nat rule to delete iport=<internal_port> addr=<token>
//	  61  remove port mapping <external_port> UDP because it has expired
//	   3  could not open lease file: /var/run/miniupnpd.leases-ipv<n>
//	   1  Unauthorized to remove PCP mapping internal port <n>, protocol UDP
//
// The fifth, the redirect-rule cleanup failure, comes from the isolated testbed
// capture (27.1.a_40, same miniupnpd version). It is the same event class as the
// production nat-rule variant and equally self-contained — miniupnpd's rdr rule is
// keyed on the external port where its nat rule is keyed on the internal one.
//
// PRODUCTION SERVES NAT-PMP/PCP, NOT IGD. Its generated /var/etc/miniupnpd.conf has
// enable_upnp=no and enable_pcp_pmp=yes, which inverted the assumption #409 started
// from: the approved isolated capture chased IGD AddPortMapping lifecycle grammar,
// while the deployment with real clients speaks NAT-PMP/PCP. The 61 expiry records
// are genuine mapping-lifecycle events from those real clients.
//
// NO SUCCESSFUL ADD AND NO SUCCESSFUL DELETE GRAMMAR EXISTS HERE, and none is
// inferred. miniupnpd logs those at a verbosity neither deployment emits, and no
// supported os-upnp 1.9 setting exposes a log level. The isolated capture is why this
// matters concretely: one real add request logged `AddPortMapping:`, then
// `redirecting port`, then `Returning UPnPError 501: Action Failed`, and live pf
// read-back showed NO rule had been created. Treating any attempt line as a success
// would have counted that failure as a mapping. See the exclusions below.
//
// AND THERE IS NO ACTIVE-MAPPING GAUGE, which #409 forbids outright. The plugin's own
// status page derives active mappings by running pfctl rather than exposing them
// through an API; an event stream cannot reconstruct authoritative state across a
// daemon restart or over pre-existing mappings; and `expired` is a decrement with no
// matching increment, so a gauge built from this family would drift negative without
// bound.
//
// DELIBERATELY NOT PARSED:
//   - `Returning UPnPError <code>: <text>` — those templates came only from the
//     isolated IGD capture, production does not enable IGD at all, and a generic error
//     response is not safely attributable to one preceding request in an interleaved
//     stream.
//   - `AddPortMapping:`, `redirecting port`, `DeletePortMapping:`, `removing redirect
//     rule port` — requests and attempts, not outcomes (see the 501 above).
//   - `shutting down MiniUPnPd`, `Listening for NAT-PMP/PCP traffic on port <n>` —
//     daemon lifecycle, not mapping lifecycle.
//
// All of those still ship as generic records carrying the body verbatim, exactly as
// they did before this parser existed. TestUPnPExcludedAndUnrelatedLinesAreNotClaimed
// is the guard.
var (
	// `remove port mapping <eport> <PROTO> because it has expired`. The one grammar
	// whose result is `ok`: a mapping reached the end of its lease and the daemon tore
	// it down, which is the mapping lifecycle working, not failing.
	//
	// The protocol group is anchored to the two literal values rather than `\w+`, so
	// the closed protocol vocabulary is enforced at the point of extraction: an
	// unknown protocol fails to match and ships generically instead of minting a new
	// label value.
	reUPnPExpired = regexp.MustCompile(`^remove port mapping (\d+) (TCP|UDP) because it has expired$`)

	// `could not find nat rule to delete iport=<iport>[ addr=<token>]`.
	//
	// The addr= token is OPTIONAL: #362's original capture recorded this shape without
	// it, while all 1,528 production occurrences carry it. Requiring it would silently
	// stop matching on whatever build omits it. The token itself is never extracted —
	// it is a fixed seven-character alphanumeric in every production occurrence, not an
	// address literal, so naming it as an attribute would assert a meaning no capture
	// proves. It still ships inside the verbatim body.
	reUPnPNATCleanupFailed = regexp.MustCompile(`^could not find nat rule to delete iport=(\d+)(?: addr=\S+)?$`)

	// `could not find redirect rule to delete eport=<eport>` — the rdr-side twin of the
	// nat-rule failure above, keyed on the EXTERNAL port.
	reUPnPRedirectCleanupFailed = regexp.MustCompile(`^could not find redirect rule to delete eport=(\d+)$`)

	// `Unauthorized to remove PCP mapping internal port <iport>, protocol <PROTO>`.
	// A PCP client asked to remove a mapping it does not own; production runs with
	// secure_mode=yes and pcp_allow_thirdparty=no, which is what refuses it.
	reUPnPUnauthorized = regexp.MustCompile(`^Unauthorized to remove PCP mapping internal port (\d+), protocol (TCP|UDP)$`)

	// `could not open lease file: <path>`. The path is not extracted: it is a fixed
	// local path (/var/run/miniupnpd.leases-ipv4 or -ipv6) that adds no queryability
	// the verbatim body does not already have.
	reUPnPLeaseFileError = regexp.MustCompile(`^could not open lease file: \S+$`)
)

// upnpProtocols is the closed, code-defined mapping from miniupnpd's upper-case
// protocol names onto the lower-case label vocabulary. A map rather than
// strings.ToLower, mirroring carpStates: the vocabulary then stays closed by
// construction even if a regex above is ever loosened.
var upnpProtocols = map[string]string{
	"TCP": upnpProtocolTCP,
	"UDP": upnpProtocolUDP,
}

func init() {
	// WithBodyEnrichment: this parser extracts no address of its own — an event, a
	// result, a protocol and a port number. Without the opt-in, the generic body scan
	// is suppressed the moment a miniupnpd line starts parsing structurally, silently
	// dropping the peer.*/interface.* attributes these lines have carried since #250.
	// Same reasoning as charon/openvpn (#406) and kernel/CARP (#405).
	RegisterParserWithBodyEnrichment(parseMiniUPnPd, "miniupnpd")
}

func parseMiniUPnPd(env Envelope, _ *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	if m := reUPnPExpired.FindStringSubmatch(env.Message); m != nil {
		proto, ok := upnpProtocols[m[2]]
		if !ok {
			return logship.Record{}, false
		}
		rec, set := newRecord(env)
		set(attrUPnPEvent, upnpEventExpired)
		set(attrUPnPResult, upnpResultOK)
		set(attrUPnPProtocol, proto)
		set(attrUPnPPortExternal, m[1])
		return rec, true
	}
	if m := reUPnPNATCleanupFailed.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set(attrUPnPEvent, upnpEventCleanupFailed)
		set(attrUPnPResult, upnpResultFailure)
		set(attrUPnPPortInternal, m[1])
		return rec, true
	}
	if m := reUPnPRedirectCleanupFailed.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set(attrUPnPEvent, upnpEventCleanupFailed)
		set(attrUPnPResult, upnpResultFailure)
		set(attrUPnPPortExternal, m[1])
		return rec, true
	}
	if m := reUPnPUnauthorized.FindStringSubmatch(env.Message); m != nil {
		proto, ok := upnpProtocols[m[2]]
		if !ok {
			return logship.Record{}, false
		}
		rec, set := newRecord(env)
		set(attrUPnPEvent, upnpEventUnauthorized)
		set(attrUPnPResult, upnpResultFailure)
		set(attrUPnPProtocol, proto)
		set(attrUPnPPortInternal, m[1])
		return rec, true
	}
	if reUPnPLeaseFileError.MatchString(env.Message) {
		rec, set := newRecord(env)
		set(attrUPnPEvent, upnpEventLeaseFileError)
		set(attrUPnPResult, upnpResultFailure)
		return rec, true
	}
	// Everything else — the excluded attempt/response/lifecycle lines and the daemon's
	// ordinary startup chatter — keeps shipping as the generic record it always was.
	return logship.Record{}, false
}
