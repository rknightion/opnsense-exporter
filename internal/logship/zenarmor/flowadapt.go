package zenarmor

import (
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/flow"
	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
)

// flowFromDoc builds a normalized flow.Record from a Zenarmor conn document.
//
// ok is false when the document does not describe a flow: a family other than
// "flow", a nil document, or endpoints that do not parse. The family guard matters
// — applied to all six families this would inflate records_total by about 64% with
// documents that carry no byte fields at all — and so does the endpoint guard, since
// a record without addresses would put a zero-address series into the rollup and a
// meaningless entry into the phase-3 correlator.
//
// This adds NO new shipped log record. The conn document continues to ship exactly
// as before; the record built here feeds the metric rollup and, from phase 3, the
// correlator.
func flowFromDoc(family string, d *zenDoc, snap *enrich.Snapshot, cache *flow.DNSCache, now time.Time) (flow.Record, bool) {
	if family != "flow" || d == nil {
		return flow.Record{}, false
	}

	src, err := netip.ParseAddr(d.SrcIP)
	if err != nil {
		return flow.Record{}, false
	}
	dst, err := netip.ParseAddr(d.DstIP)
	if err != nil {
		return flow.Record{}, false
	}
	// Unmapped here, once, so the canonical tuple, the community id and the scope
	// lookups all agree about what address this is.
	src, dst = src.Unmap(), dst.Unmap()

	txBytes, txFell := zenBytes(d.SrcNBytes, d.SrcPBytes)
	rxBytes, rxFell := zenBytes(d.DstNBytes, d.DstPBytes)

	r := flow.Record{
		Source:   flow.SourceZenarmor,
		Observed: now,
		Proto:    protoNumber(d.TransportProto),
		SrcAddr:  src,
		DstAddr:  dst,
		SrcPort:  clampPort(d.SrcPort),
		DstPort:  clampPort(d.DstPort),
		VLANID:   d.VLANID,
		// The child device, not the parent Zenarmor reports. See vlanDevice.
		In: flow.Iface{Device: vlanDevice(d.Interface, d.VLANID)},
		Zen: flow.Counters{
			TxBytes:   txBytes,
			RxBytes:   rxBytes,
			TxPackets: nonNeg(d.SrcNPackets),
			RxPackets: nonNeg(d.DstNPackets),
			Present:   true,
		},
		L7: flow.L7{
			AppName: d.AppName, AppProto: d.AppProto, AppCategory: d.AppCategory,
			// Verbatim, unmapped (#585). "Clear" and "TLS-Encrypted" are the two values
			// the live capture carried, and normalising them into a spelling of our own
			// would put a second vocabulary next to the one the conn record already
			// ships under `encryption` — the same field, two names, on two records
			// describing one flow.
			Encryption: d.Encryption,
		},
		Repairs: flow.Repairs{PayloadByteFallback: txFell || rxFell},
	}

	if d.StartTime != 0 {
		r.Start = time.UnixMilli(d.StartTime)
	}
	if d.EndTime != 0 {
		r.End = time.UnixMilli(d.EndTime)
	}
	if r.End.IsZero() {
		r.End = r.Start
	}

	// Absent is UNKNOWN, never "pass" — the same rule parse.go:95-98 already applies
	// to the shipped attribute. Claiming a disposition the document never stated
	// would corrupt the action label.
	if d.IsBlocked != nil {
		switch *d.IsBlocked {
		case 0:
			r.Verdict = flow.VerdictPass
		case 1:
			r.Verdict = flow.VerdictBlock
		}
	}

	r.CommunityID = flow.CommunityID(r.CanonicalTuple(), 0)

	// Zenarmor's own geo, carried onto the flow record verbatim (#520). This is an
	// INPUT to the precedence rules, not the answer: flow.GeoEnricher resolves which
	// database wins per field and stamps the provenance attribute. Copying it here is
	// also what lets the two databases be compared at all — before this, Zenarmor's
	// geo reached only its own log record and never met ours.
	zenGeoInto(&r.Geo.Src, d.SrcGeoIP)
	zenGeoInto(&r.Geo.Dst, d.DstGeoIP)

	// The interface description, and the ONE case where its absence is not honest
	// silence (#606). Zenarmor states a kernel device; the description comes from the
	// enrichment snapshot, which arrives on the exporter's own schedule. Until it
	// does, Iface.Label()'s device fallback would emit interface="ixl0" beside the
	// interface="LAN" the same interface gets a minute later — two series for one
	// interface, so every `sum by (interface)` under-reports both. Marking it
	// unresolved makes the label say so instead of impersonating a distinct interface.
	//
	// Holding the record instead was measured and rejected: the window runs to 300
	// seconds of process uptime and this lane carries ~96,600 records/h, so a hold
	// would buffer ~8,000 records per restart on a push lane.
	//
	// The mark is set ONLY when the interface table could not be consulted at all —
	// no snapshot, or one that names no interfaces yet. A snapshot that HAS the table
	// and simply does not name this device is a different and honest case: the box
	// really has no description for it, and the raw device is then the best true
	// label there is.
	if r.In.Device != "" && (snap == nil || len(snap.IfaceNames) == 0) {
		r.In.Unresolved = true
	}
	if snap != nil {
		if name, ok := snap.InterfaceName(r.In.Device); ok {
			r.In.Name = name
			r.In.Unresolved = false
		}
		r.Enrich.SrcScope = snap.Scope(d.SrcIP)
		r.Enrich.DstScope = snap.Scope(d.DstIP)
		r.Enrich.SrcHostname = d.SrcHostname
		r.Enrich.DstHostname = d.DstHostname
		if d.DstPort != 0 {
			if svc, ok := enrich.ServiceName(strconv.Itoa(d.DstPort), strings.ToLower(d.TransportProto)); ok {
				r.Enrich.DstService = svc
			}
		}
	}
	r.Direction = directionOf(dst, r.Enrich.SrcScope, r.Enrich.DstScope, d.Direction)

	// dst.domain from the DNS answer cache: a Zenarmor conn document carries no domain
	// of its own, so this is the only place it gets one. Keyed on the client (src) and
	// the answer (dst) the client connected to — the same pair the dns family recorded
	// under. A nil cache (domain enrichment off) simply leaves it empty.
	if cache != nil {
		if dom, ok := cache.Lookup(src, dst, now); ok {
			r.Enrich.DstDomain = dom
		}
	}

	// LAST, after the scopes are resolved: the geo metric label reads them to decide
	// which end of the flow is the remote one. Same ordering rule as the NetFlow
	// lane's enrichRecord.
	flow.GeoEnrichment.Enrich(&r)
	return r, true
}

// zenGeoInto copies Zenarmor's geo block onto a flow endpoint, taking only the fields
// #520's precedence table names.
//
// country_code2 is the ISO 3166-1 alpha-2 code, which is directly comparable with
// ours. country_code3, country_name and timezone are deliberately not carried: the
// resolved record already states the country, and three more spellings of it on every
// flow record is the per-line cost #475 removed the coordinates for.
//
// region_name is a NAME ("England"), not the ISO 3166-2 code MaxMind returns. The two
// are not normalised into each other — inventing that mapping would be fabricating
// data — which is exactly why every record carries a provenance attribute saying which
// database answered.
//
// The asn field is NOT read at all. It was the string "0" on every record of the
// capture box, "0" is Zenarmor's empty value rather than AS0, and a live check found
// no ASN database anywhere under /usr/local/zenarmor: Zenarmor structurally cannot
// supply one.
func zenGeoInto(dst *flow.GeoEndpoint, g *zenGeo) {
	if g == nil {
		return
	}
	dst.ZenCountry = g.CountryCode2
	dst.ZenContinent = g.ContinentCode
	dst.ZenCity = g.CityName
	dst.ZenRegion = g.RegionName
}

// feedDNSCache records a dns family document's answers so a later flow to one of
// those addresses can recover the domain (#353 §7). The querying client is the
// document's source; each answer token that parses as an IP is cached under
// (client, answer) -> query. Non-IP answer tokens (CNAME targets, an empty answer on
// a request-only document) are skipped, as is a document missing a client or a query.
func feedDNSCache(cache *flow.DNSCache, d *zenDoc, now time.Time) {
	if d == nil || d.Query == "" || d.Answers == "" {
		return
	}
	client, err := netip.ParseAddr(d.SrcIP)
	if err != nil {
		return
	}
	for _, tok := range strings.FieldsFunc(d.Answers, isAnswerSep) {
		if answer, err := netip.ParseAddr(tok); err == nil {
			cache.Put(client, answer, d.Query, now)
		}
	}
}

// isAnswerSep splits Zenarmor's answers field, which packs multiple resolved
// addresses into one string. The exact delimiter is not documented and has been seen
// as both comma and whitespace, so any of comma, semicolon or space separates.
func isAnswerSep(r rune) bool {
	return r == ',' || r == ';' || r == ' ' || r == '\t'
}

// addFlowAttrs stamps the normalized flow.* attributes onto a conn document's
// existing attribute map (#353 §10) — no new record. Each is set only when it
// carries information, so an unknown direction or an unresolved domain leaves no key.
func addFlowAttrs(attrs map[string]string, fr flow.Record) {
	if fr.CommunityID != "" {
		attrs["flow.community_id"] = fr.CommunityID
	}
	if d := fr.Direction.String(); d != "unknown" {
		attrs["flow.direction"] = d
	}
	if lbl := fr.InterfaceLabel(); lbl != "" {
		attrs["flow.interface"] = lbl
	}
	if fr.Enrich.DstDomain != "" {
		attrs["dst.domain"] = fr.Enrich.DstDomain
	}
}

// vlanDevice synthesises the child device name OPNsense gives a VLAN interface.
//
// Zenarmor reports the PARENT device on every conn document — verified, 20,476 of
// 20,476 carry interface="ixl0" — and puts the tag in a separate vlanid field. So
// enriching on `interface` alone makes the label single-valued and resolves every
// VLAN's traffic to the parent's name: 4,209 flows, 20.5% of the corpus, all
// reported as LAN. OPNsense names these <parent>_vlan<tag>, which is what both the
// interface table and phase 2's ifIndex map are keyed by, so synthesising it here
// also makes the interface label mean the same thing for both lanes.
func vlanDevice(dev, vlanID string) string {
	if dev == "" || vlanID == "" || vlanID == "0" {
		return dev
	}
	return dev + "_vlan" + vlanID
}

// zenBytes resolves one side's byte count, preferring wire bytes and falling back
// to payload bytes. fellBack reports whether the fallback fired, so it can be
// counted rather than being a silent repair.
//
// nbytes is wire bytes and pbytes is payload bytes, and nbytes is the right answer:
// it is the larger of the two on 26,522 of the 27,478 flow-sides where both are
// present, the gap being per-packet header overhead. But Zenarmor only starts
// accumulating nbytes once it has tracked a flow past its first packets. Across the
// 2026-07-21 capture nbytes was zero on 10,682 of 38,722 sides with packets>0
// (27.6%), exclusively UDP and UDP6 at one or two packets — DNS, STUN, SSDP. That
// is 1,756 documents, 8.6% of the corpus, that would report zero bytes while
// records_total counted them, which reads as "DNS: 311 flows, 0 bytes" on a
// dashboard: a panel that looks broken, on exactly the traffic worth watching. The
// byte impact of the fallback is negligible — these are one and two packet flows —
// so the point is not lying about zero rather than accuracy.
func zenBytes(nbytes, pbytes int64) (v uint64, fellBack bool) {
	if n := nonNeg(nbytes); n > 0 {
		return n, false
	}
	if p := nonNeg(pbytes); p > 0 {
		return p, true
	}
	return 0, false
}

// nonNeg clamps a signed JSON counter to zero. Zenarmor's byte and packet fields
// are signed, and a negative would wrap through uint64 into the rollup as an
// astronomical value that no dashboard could be read past.
func nonNeg(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// clampPort narrows Zenarmor's JSON int to the wire width, refusing to wrap an
// out-of-range value into a plausible-looking port.
func clampPort(p int) uint16 {
	if p < 0 || p > 65535 {
		return 0
	}
	return uint16(p)
}

// directionOf resolves the flow's orientation.
//
// Two sources of truth, each used for what it actually knows.
//
// Zenarmor states a direction and it is reliable for the in/out question, but it
// cannot express "internal": LAN-to-LAN traffic arrives as "out" 7,480 times and
// "in" 3,366 times in the same capture. Its is_local flag reads like it means "both
// endpoints local" and does not — 1,094 of 11,940 is_local=1 documents have a
// non-local endpoint, including 556 genuinely inbound from the internet, because
// "Local Bound" means bound TO or FROM a local host. Taking it as "internal" would
// label internet-inbound traffic as internal traffic.
//
// The firewall's own topology decides internal instead. That is the one thing this
// exporter has and Zenarmor does not, and it is strictly better information: it
// knows the LAN's IPv6 prefix, which Zenarmor's RFC1918-only local networks miss on
// 3,137 documents, every one of them a LAN host talking to the internet over IPv6.
//
// Scope returns self|local|remote|"" — never "external" — and "self" is the
// firewall itself, which is NOT remote: a LAN host querying the box's own resolver,
// web UI or NTP is internal traffic.
//
// Multicast and link-local destinations are internal by inspection. SSDP and mDNS
// never leave the L2 domain, but a group address sits in no configured subnet, so
// scope alone calls the destination remote.
//
// Anything neither source can classify stays unknown rather than being guessed.
func directionOf(dst netip.Addr, srcScope, dstScope, zenDirection string) flow.Direction {
	if dst.IsMulticast() || dst.IsLinkLocalUnicast() || dst.IsLinkLocalMulticast() || dst.IsUnspecified() {
		return flow.DirectionInternal
	}
	const remote = "remote"
	if srcScope != "" && dstScope != "" && srcScope != remote && dstScope != remote {
		return flow.DirectionInternal
	}
	switch strings.ToLower(zenDirection) {
	case "in":
		return flow.DirectionInbound
	case "out":
		return flow.DirectionOutbound
	default:
		return flow.DirectionUnknown
	}
}

// protoNumber maps Zenarmor's transport_proto text to its IANA number.
//
// The "6" suffixed spellings are not optional: TCP6 and UDP6 account for 3,336 of
// 20,476 documents (16.3%), and without them every IPv6 flow lands on
// transport="other". The suffix marks the address family, not a different protocol,
// so both fold onto the same number — the family is already visible in the
// addresses.
func protoNumber(s string) uint8 {
	switch strings.ToLower(s) {
	case "tcp", "tcp6":
		return 6
	case "udp", "udp6":
		return 17
	case "icmp":
		return 1
	case "icmp6", "icmpv6", "ipv6-icmp":
		return 58
	case "gre":
		return 47
	case "esp":
		return 50
	case "sctp":
		return 132
	default:
		return 0
	}
}
