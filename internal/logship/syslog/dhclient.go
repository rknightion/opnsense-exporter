package syslog

import (
	"regexp"
	"strconv"
	"sync"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// dhclient is the FreeBSD base DHCP CLIENT that holds this firewall's own WAN
// address (#541). Before this file existed it had ZERO matches in the registry: the
// DHCP program map claimed dnsmasq-dhcp, the kea-* family, dhcrelay and dhcp6c, but
// not dhclient, so every line arrived as an untyped generic record with a blank
// subsystem — and nothing in the exporter reported WAN lease state, time to expiry,
// or renewal failure.
//
// WHY THAT MATTERED: production ran an 11-12 hour DHCP renewal storm on 2026-07-30
// (DHCPREQUEST rate ~100x baseline, sustained) which self-resolved with zero
// telemetry and no alert. A DHCP WAN that stops renewing loses its address at lease
// expiry, and the retransmit storm is a leading indicator hours ahead of that.
//
// THE CAPTURED GRAMMARS, verbatim from the production box (OPNsense 26.7.1_1,
// WAN = ixl1). These four are the only shapes OBSERVED:
//
//	DHCPREQUEST on ixl1 to 203.0.113.233 port 67
//	DHCPACK from 203.0.113.233
//	bound to 203.0.113.148 -- renewal in 302400 seconds.
//	dhclient-script: Reason RENEW on ixl1 executing
//
// The remaining message types (DISCOVER, OFFER, NAK, DECLINE, RELEASE, INFORM) and
// the remaining script reasons are NOT captured on this box — a working WAN lease
// renews and never NAKs — and are taken from the ISC/OpenBSD dhclient source
// FreeBSD's /sbin/dhclient descends from, whose format strings are literally
// `DHCPDISCOVER on %s to %s port %d interval %ld`, `DHCPREQUEST on %s to %s port
// %d`, `DHCPACK from %s`, `DHCPNAK from %s`, `DHCPOFFER from %s` and `bound to %s --
// renewal in %ld seconds.`, and whose reason vocabulary is dhclient-script(8)'s own
// closed set. They are modelled from source rather than guessed, and every one of
// them rides the SAME two captured shapes above — an unobserved verb changes only
// which literal the alternation matches, never the surrounding grammar.
//
// DELIBERATELY NOT PARSED: `dhclient-script: New Hostname (ixl1): opnsense` and
// `dhclient-script: Creating resolv.conf`. Both are script side-effects rather than
// lease lifecycle, and the hostname line carries a value that is not ours to
// structure. They keep shipping as generic records.
var (
	// The types that name an interface: the client is SENDING, so it knows which
	// interface it is sending on. `interval <n>` is DISCOVER's backoff and is optional
	// across the family.
	//
	// The verb group is anchored to the six literal types rather than `[A-Z]+`. That is
	// the closed `type` vocabulary being enforced at the point of extraction: a future
	// or unexpected verb fails to match and ships generically instead of silently
	// minting a new label value.
	reDHCPClientSent = regexp.MustCompile(
		`^DHCP(DISCOVER|REQUEST|RELEASE|DECLINE|INFORM|LEASEQUERY) on ([0-9A-Za-z._-]+) to (\S+) port (\d+)(?: interval \d+)?$`)

	// The types that name NO interface: the client is RECEIVING, and dhclient's
	// format string carries only the server address. This is why the PID correlation
	// below exists.
	reDHCPClientReceived = regexp.MustCompile(`^DHCP(ACK|NAK|OFFER) from (\S+)$`)

	// `bound to <address> -- renewal in <n> seconds.`
	//
	// THE TRAILING FULL STOP IS REAL — it is in dhclient's format string and in all
	// three captured occurrences — and it is optional here only so a build that drops
	// it still parses. This line names no interface either.
	reDHCPClientBound = regexp.MustCompile(`^bound to (\S+) -- renewal in (\d+) seconds\.?$`)

	// `dhclient-script: Reason <REASON> on <iface> executing`
	//
	// Emitted under APP-NAME `dhclient`, NOT under a separate `dhclient-script`
	// program — verified on the production box, where the text is a prefix inside the
	// message and the app-name is plain `dhclient`. The script's own PID differs from
	// the daemon's (7351/7769/8557 against the daemon's 97927 in one captured renewal),
	// which is why these lines must not feed the PID correlation below.
	reDHCPClientScript = regexp.MustCompile(
		`^dhclient-script: Reason ([A-Z0-9]+) on ([0-9A-Za-z._-]+) executing$`)
)

// dhcpClientTypes is the closed, code-defined mapping from dhclient's upper-case
// wire verbs onto the lower-case label vocabulary. A map rather than
// strings.ToLower, mirroring carpStates and upnpProtocols: the vocabulary then stays
// closed by construction even if a regex above is ever loosened.
//
// LEASEQUERY is deliberately absent from the label vocabulary even though the regex
// accepts the verb: it is a relay-agent message a client never sends, so there is no
// honest label for it. It matches, finds no mapping, and the line ships generically.
var dhcpClientTypes = map[string]string{
	"DISCOVER": dhcpClientTypeDiscover,
	"REQUEST":  dhcpClientTypeRequest,
	"ACK":      dhcpClientTypeAck,
	"NAK":      dhcpClientTypeNak,
	"OFFER":    dhcpClientTypeOffer,
	"DECLINE":  dhcpClientTypeDecline,
	"RELEASE":  dhcpClientTypeRelease,
	"INFORM":   dhcpClientTypeInform,
}

// dhcpClientReasons is dhclient-script(8)'s own closed reason vocabulary,
// lowercased. Only RENEW is captured on production; the rest are the script's
// documented set and are modelled from it, not invented. An unlisted reason ships
// generically rather than becoming a label.
var dhcpClientReasons = map[string]string{
	"MEDIUM":   dhcpClientReasonMedium,
	"PREINIT":  dhcpClientReasonPreinit,
	"ARPCHECK": dhcpClientReasonArpcheck,
	"ARPSEND":  dhcpClientReasonArpsend,
	"BOUND":    dhcpClientReasonBound,
	"RENEW":    dhcpClientReasonRenew,
	"REBIND":   dhcpClientReasonRebind,
	"REBOOT":   dhcpClientReasonReboot,
	"EXPIRE":   dhcpClientReasonExpire,
	"FAIL":     dhcpClientReasonFail,
	"TIMEOUT":  dhcpClientReasonTimeout,
	"STOP":     dhcpClientReasonStop,
	"RELEASE":  dhcpClientReasonRelease,
	"NBI":      dhcpClientReasonNBI,
}

// maxDHCPClientPIDs bounds the PID correlation table below. dhclient runs ONE
// process per DHCP-configured interface, so the true working set is the number of
// DHCP WANs — one on production. The bound is generous because a PID changes every
// time the daemon restarts, and it exists only so a restart loop cannot grow this
// map for the life of the process.
const maxDHCPClientPIDs = 64

// dhcpClientIfaces remembers which interface each dhclient PID last named.
//
// WHY IT EXISTS: `DHCPACK from <ip>` and `bound to <ip> -- renewal in <n> seconds`
// carry NO interface, and the lease gauges are keyed by interface. Both lines come
// from the same daemon process as the `DHCPREQUEST on <iface>` that preceded them —
// verified in a captured renewal where PID 97927 emitted DHCPREQUEST, DHCPACK and
// `bound to` in sequence — so the PID resolves them.
//
// It is NOT unbounded state: one entry per live dhclient process, capped at
// maxDHCPClientPIDs with the OLDEST entry evicted on overflow (a dead PID's entry is
// the one that stops being useful). An unknown PID resolves to the empty string,
// which the metric carries honestly as "no interface known" — it never guesses.
var dhcpClientIfaces = newPIDIfaceMemory(maxDHCPClientPIDs)

// pidIfaceMemory is a tiny bounded insertion-ordered PID -> interface map. Safe for
// concurrent use: parsers run on receiver goroutines, and a box may run more than
// one listener.
type pidIfaceMemory struct {
	mu    sync.Mutex
	max   int
	byPID map[string]string
	order []string
}

func newPIDIfaceMemory(max int) *pidIfaceMemory {
	return &pidIfaceMemory{max: max, byPID: make(map[string]string, max)}
}

func (p *pidIfaceMemory) remember(pid, iface string) {
	if pid == "" || iface == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, seen := p.byPID[pid]; !seen {
		if len(p.order) >= p.max {
			oldest := p.order[0]
			p.order = p.order[1:]
			delete(p.byPID, oldest)
		}
		p.order = append(p.order, pid)
	}
	p.byPID[pid] = iface
}

func (p *pidIfaceMemory) lookup(pid string) string {
	if pid == "" {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.byPID[pid]
}

// reset clears the memory. Test-only: package-level state would otherwise make one
// test's correlation visible to the next.
func (p *pidIfaceMemory) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.byPID = make(map[string]string, p.max)
	p.order = nil
}

func init() {
	// WithBodyEnrichment: this parser emits the server and leased addresses as
	// attributes, but they are the same addresses the generic body scan already
	// resolved on these lines while they were unparsed. Suppressing the scan would drop
	// the peer.*/interface.* attributes dhclient lines have carried since #250 —
	// a regression in any existing Loki query — in exchange for removing a redundancy
	// that is already live today. Same call as kernel.go.
	RegisterParserWithBodyEnrichment(parseDHCPClient, "dhclient")
}

func parseDHCPClient(env Envelope, _ *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	if m := reDHCPClientSent.FindStringSubmatch(env.Message); m != nil {
		t, ok := dhcpClientTypes[m[1]]
		if !ok {
			return logship.Record{}, false
		}
		// This line NAMES the interface, so it is what teaches the correlation table.
		dhcpClientIfaces.remember(env.PID, m[2])
		rec, set := newRecord(env)
		set(attrDHCPClientType, t)
		set(attrDHCPClientInterface, m[2])
		set(attrDHCPClientServer, m[3])
		return rec, true
	}

	if m := reDHCPClientReceived.FindStringSubmatch(env.Message); m != nil {
		t, ok := dhcpClientTypes[m[1]]
		if !ok {
			return logship.Record{}, false
		}
		rec, set := newRecord(env)
		set(attrDHCPClientType, t)
		set(attrDHCPClientInterface, dhcpClientIfaces.lookup(env.PID))
		set(attrDHCPClientServer, m[2])
		return rec, true
	}

	if m := reDHCPClientBound.FindStringSubmatch(env.Message); m != nil {
		return dhcpClientBoundRecord(env, m[1], m[2])
	}

	if m := reDHCPClientScript.FindStringSubmatch(env.Message); m != nil {
		reason, ok := dhcpClientReasons[m[1]]
		if !ok {
			return logship.Record{}, false
		}
		// The script's PID is its OWN, not the daemon's, so this must NOT teach the
		// correlation table — doing so would file the next DHCPACK under a dead PID.
		rec, set := newRecord(env)
		set(attrDHCPClientScriptReason, reason)
		set(attrDHCPClientInterface, m[2])
		return rec, true
	}

	// Everything else — the script's hostname and resolv.conf chatter, and any shape
	// this box has never emitted — keeps shipping as the generic record it always was.
	return logship.Record{}, false
}

// dhcpClientBoundRecord builds the `bound to` record, which is the one that carries
// the two lease gauges.
//
// THE GAUGES ARE ABSOLUTE TIMESTAMPS, NOT A COUNTDOWN, and that is a deliberate
// deviation from #541's proposed `dhcp_client_lease_expiry_seconds`. A countdown
// gauge has to be recomputed against wall-clock at scrape time, and a stale one is
// indistinguishable from a fresh one — which is exactly the failure the metric is
// supposed to catch. Two `*_timestamp_seconds` gauges need no scrape-time
// arithmetic, survive a scrape gap unchanged, and make "the countdown stopped"
// directly expressible as `renewal_timestamp - time() < 0`. Precedent:
// internal/collector/flow.go's GeoIP build-time gauge.
//
// The BASE is the line's own syslog timestamp, not time.Now(): a replayed or
// buffered line must produce the deadline the firewall meant, not the deadline it
// would have had if it arrived now. A line whose envelope carried no timestamp
// (RFC5424 `-`) gets NO gauge attributes at all — an invented base would silently
// mis-date the deadline — though the record itself still ships with the leased
// address and the raw countdown.
func dhcpClientBoundRecord(env Envelope, address, renewalSeconds string) (logship.Record, bool) {
	rec, set := newRecord(env)
	set(attrDHCPClientAddress, address)
	set(attrDHCPClientRenewalSeconds, renewalSeconds)
	set(attrDHCPClientInterface, dhcpClientIfaces.lookup(env.PID))

	secs, err := strconv.ParseInt(renewalSeconds, 10, 64)
	if err != nil || env.Timestamp.IsZero() {
		return rec, true
	}
	bound := env.Timestamp.Unix()
	set(attrDHCPClientBoundTimestamp, strconv.FormatInt(bound, 10))
	set(attrDHCPClientRenewalTimestamp, strconv.FormatInt(bound+secs, 10))
	return rec, true
}
