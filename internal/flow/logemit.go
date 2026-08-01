package flow

import (
	"strconv"
	"strings"
)

// LogAttributes renders a flow record as the structured-metadata map shipped on its
// OTLP log record. Everything here is Loki structured metadata, NEVER a label: IPs,
// ports, hostnames, application names, domains and connection ids all live here, where
// they are filterable but cannot become index cardinality — the same rule the rollup
// enforces for metrics (rollup.go) and logmetrics.go enforces for the log lanes.
//
// This lives in package flow, returning a plain map, so the flow record stays the one
// source of truth for its own schema and can be tested without importing logship (which
// imports flow, so flow must not import it back). The flowlog lane wraps this into a
// logship.Record.
//
// Keys are only set when they carry information: an absent key is cheaper than an empty
// value and reads correctly in Loki, which distinguishes "no attribute" from "".
func (r Record) LogAttributes() map[string]string {
	a := make(map[string]string, 24)

	if r.SrcAddr.IsValid() {
		a["src.ip"] = r.SrcAddr.String()
	}
	if r.DstAddr.IsValid() {
		a["dst.ip"] = r.DstAddr.String()
	}
	if r.SrcPort != 0 {
		a["src.port"] = strconv.Itoa(int(r.SrcPort))
	}
	if r.DstPort != 0 {
		a["dst.port"] = strconv.Itoa(int(r.DstPort))
	}
	if t := transportName(r.Proto); t != "other" || r.Proto != 0 {
		a["net.transport"] = t
	}
	a["flow.proto"] = strconv.Itoa(int(r.Proto))
	if r.CommunityID != "" {
		a["flow.community_id"] = r.CommunityID
	}
	if d := r.Direction.String(); d != "unknown" {
		a["flow.direction"] = d
	}
	if lbl := interfaceLabel(r); lbl != "" {
		a["flow.interface"] = lbl
	}
	if r.In.Label() != "" {
		a["flow.in_interface"] = r.In.Label()
	}
	if r.Out.Label() != "" {
		a["flow.out_interface"] = r.Out.Label()
	}
	// When the label is the unresolved sentinel the kernel device is still known and
	// still useful — it is only barred from the metric LABEL, where it would invent a
	// second series for an interface that already has one (#606). Keeping it here
	// means nothing is lost, and a record from the cold window can still be joined
	// against the interface metrics by device.
	if r.In.Unresolved && r.In.Device != "" {
		a["flow.in_device"] = r.In.Device
	}
	if r.Out.Unresolved && r.Out.Device != "" {
		a["flow.out_device"] = r.Out.Device
	}
	if r.VLANID != "" {
		a["flow.vlan"] = r.VLANID
	}
	if v := r.Verdict.String(); v != "" {
		a["flow.action"] = v
	}
	// The egress correction is recorded per record, not only as a counter, so a single
	// flow can be shown to have been repaired — the counter says how often, this says
	// which one.
	if r.Out.Corrected {
		a["flow.egress_corrected"] = "true"
	}
	// Same reasoning for the VLAN-child attribution (#465): the interface on this record
	// is one the exporter deduced from the address's subnet, not one ng_netflow reported,
	// and an operator comparing it against a switch port needs to know that.
	if r.Repairs.VLANSubnetAttributed {
		a["flow.vlan_subnet_attributed"] = "true"
	}
	// And for the policy-route correction (#603): this record's egress is the one pf's
	// state table named, not the one ng_netflow's FIB lookup did. On a multi-WAN box
	// that is the difference between WAN1 and WAN2 on a single flow, which is exactly
	// the claim an operator will want to check against `pfctl -ss`.
	if r.Repairs.PolicyRouteCorrected {
		a["flow.policy_route_corrected"] = "true"
	}
	// The byte BASIS of the two sides on a merged record (#604). Without it a reader
	// comparing netflow.bytes against zenarmor.bytes on one record cannot tell wire
	// against wire from wire against payload, and on roughly half of all Zenarmor
	// records it is the latter — so the difference is IP+UDP header overhead, not
	// traffic that evaded inspection.
	if r.Repairs.ZenBytesArePayload {
		a["flow.zen_bytes_are_payload"] = "true"
	}
	// And whether the two sides are totalling the same span at all. On a window
	// partial the NetFlow side is one correlate-window of a connection the Zenarmor
	// side counts whole, so their ratio means nothing — the volume is still real.
	if r.Repairs.WindowPartial {
		a["flow.window_partial"] = "true"
	}
	if r.Fragments > 1 {
		a["flow.fragments"] = strconv.Itoa(r.Fragments)
	}
	// The peer's own answer, which nothing else on this record expresses (#585):
	// flow.action is the FIREWALL's verdict, so a burst of WAN flows currently cannot
	// be read as a port scan (SYN, no reply, no bytes back) rather than a refused
	// service (RST) or a clean short session. Namespaced under the SOURCE that supplied
	// it, not under flow.*, because it exists only where NetFlow does — a
	// Zenarmor-only record never carries one, and a reader must not have to discover
	// that from its absence.
	if r.TCPFlags != 0 {
		a["netflow.tcp_flags"] = tcpFlagsString(r.TCPFlags)
	}
	// The QoS marking the sender asked for (#630), under netflow.* for the same
	// reason tcp_flags is: only NetFlow states it. Both the number and the standard
	// name go out — the number is what a query filters on and survives a codepoint
	// with no name, the name is what makes "this is voice traffic" readable without a
	// DSCP table to hand.
	//
	// Unmarked is emitted as nothing. It is ~89% of records on the reference box, so
	// a literal "0" would be pure volume, and its absence reads correctly.
	if r.DSCP != 0 {
		a["netflow.dscp"] = strconv.Itoa(int(r.DSCP))
		if name := dscpClass(r.DSCP); name != "" {
			a["netflow.dscp_class"] = name
		}
	}
	if r.ECN != 0 {
		a["netflow.ecn"] = ecnState(r.ECN)
	}
	// The masks ride on NF.Present rather than on a non-zero test: zero is a real
	// answer here (no covering route), and it is the one that explains a next-hop
	// naming the default gateway rather than the destination's own router. Gating on
	// the NetFlow side having spoken keeps a Zenarmor-only record from carrying a
	// fabricated zero.
	if r.NF.Present {
		a["netflow.src_mask"] = strconv.Itoa(int(r.SrcMask))
		a["netflow.dst_mask"] = strconv.Itoa(int(r.DstMask))
	}

	if r.L7.AppName != "" {
		a["app.name"] = r.L7.AppName
	}
	if r.L7.AppProto != "" {
		a["app.proto"] = r.L7.AppProto
	}
	if r.L7.AppCategory != "" {
		a["app.category"] = r.L7.AppCategory
	}
	if r.L7.DomainCat != "" {
		a["app.domain_category"] = r.L7.DomainCat
	}
	// Zenarmor's transport-security verdict (#585), verbatim: "Clear" or
	// "TLS-Encrypted". Under zenarmor.* rather than app.* for the same reason
	// netflow.tcp_flags is not flow.*: only one of the two sources can state it, and a
	// NetFlow-only record legitimately has none. Cleartext-to-the-internet becomes one
	// Loki query joined against the NetFlow volume already on this record.
	if r.L7.Encryption != "" {
		a["zenarmor.encryption"] = r.L7.Encryption
	}

	if r.Enrich.SrcHostname != "" {
		a["src.hostname"] = r.Enrich.SrcHostname
	}
	if r.Enrich.DstHostname != "" {
		a["dst.hostname"] = r.Enrich.DstHostname
	}
	if r.Enrich.SrcScope != "" {
		a["src.scope"] = r.Enrich.SrcScope
	}
	if r.Enrich.DstScope != "" {
		a["dst.scope"] = r.Enrich.DstScope
	}
	if r.Enrich.DstService != "" {
		a["dst.service"] = r.Enrich.DstService
	}
	if r.Enrich.DstDomain != "" {
		a["dst.domain"] = r.Enrich.DstDomain
	}

	geoAttrs(a, "src", r.Geo.Src)
	geoAttrs(a, "dst", r.Geo.Dst)

	// Both sources' counters travel together and are NEVER summed (#346 decision 3):
	// they measure at different points and their disagreement is itself the signal.
	if r.NF.Present {
		a["flow.nf.bytes"] = strconv.FormatUint(r.NF.Bytes(), 10)
		a["flow.nf.packets"] = strconv.FormatUint(r.NF.Packets(), 10)
		// The DIRECTIONAL split, emitted only where it means something (#617). A raw
		// NetFlow record is strictly unidirectional and all of its volume is Tx, so
		// tx/rx on one would restate flow.nf.bytes and say nothing. On a MERGED record
		// the two halves have been told apart on evidence rather than arrival order
		// (#605), so Rx is the reverse half's volume — the difference between "a 2 GB
		// download" and "2 GB transmitted", which nothing else on this record expresses.
		if r.Source == SourceMerged {
			a["flow.nf.tx_bytes"] = strconv.FormatUint(r.NF.TxBytes, 10)
			a["flow.nf.rx_bytes"] = strconv.FormatUint(r.NF.RxBytes, 10)
			a["flow.nf.tx_packets"] = strconv.FormatUint(r.NF.TxPackets, 10)
			a["flow.nf.rx_packets"] = strconv.FormatUint(r.NF.RxPackets, 10)
		}
	}
	if r.Zen.Present {
		a["flow.zen.bytes"] = strconv.FormatUint(r.Zen.Bytes(), 10)
		a["flow.zen.packets"] = strconv.FormatUint(r.Zen.Packets(), 10)
	}
	return a
}

// geoAttrs renders one endpoint's geolocation under the given prefix ("src"/"dst").
//
// Everything here is a LOG ATTRIBUTE and must stay one. Per the deployment's Loki
// setup, only RESOURCE attributes are ever promoted to index labels, and country must
// not become one — it is a ~250-value dimension on a stream that already has enough.
// ASN and city are not usefully bounded at all and exist only here.
//
// The two *_source keys are the provenance attributes #520 makes mandatory. They are
// emitted whenever the field they describe is set, including when only one database
// could possibly have answered: a reader must never have to infer which one it was
// from whether Zenarmor happens to be installed.
func geoAttrs(a map[string]string, prefix string, g GeoEndpoint) {
	if g.Empty() {
		return
	}
	if g.Country != "" {
		a[prefix+".geo.country"] = g.Country
		a[prefix+".geo.country_source"] = g.CountrySource
	}
	if g.Continent != "" {
		a[prefix+".geo.continent"] = g.Continent
	}
	if g.City != "" {
		a[prefix+".geo.city"] = g.City
	}
	if g.Region != "" {
		a[prefix+".geo.region"] = g.Region
	}
	if g.City != "" || g.Region != "" {
		a[prefix+".geo.city_source"] = g.CitySource
	}
	if g.ASN != 0 {
		a[prefix+".geo.asn"] = "AS" + strconv.FormatUint(uint64(g.ASN), 10)
	}
	if g.ASOrg != "" {
		a[prefix+".geo.as_org"] = g.ASOrg
	}
	// Zenarmor's country is retained, but only where it actually says something our
	// answer does not. Re-emitting an identical value on every record would be pure
	// per-line cost for no information; a DISAGREEMENT is the interesting case, and
	// the one the disagreement counter is a rate for.
	if g.ZenCountry != "" && g.ZenCountry != g.Country {
		a[prefix+".geo.zen_country"] = g.ZenCountry
	}
}

// tcpFlagNames are the eight TCP control bits in WIRE ORDER, least significant first,
// which is also RFC 9293's own order for the flag field. Rendering always walks this
// array, so one flag combination has exactly one spelling and an operator can write
// `netflow.tcp_flags="SYN,ACK"` as an exact match. An order that varied — a map range,
// or "most interesting bit first" — would give the same flow two spellings and make
// every exact-match query silently miss a share of its records.
//
// ECE and CWR are named rather than folded into an "other" bucket: they are ECN, and a
// path that negotiates ECN is a real thing to be able to see. The names are the
// conventional tcpdump/Wireshark spellings, because those are what an operator will
// type.
var tcpFlagNames = [8]string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"}

// tcpFlagsString renders a TCP flag byte as its comma-separated set. A zero byte
// yields the empty string, which the caller reads as "emit no attribute" — see
// Record.TCPFlags for why zero is unambiguous.
func tcpFlagsString(f uint8) string {
	if f == 0 {
		return ""
	}
	var b strings.Builder
	// Longest possible value ("FIN,SYN,RST,PSH,ACK,URG,ECE,CWR") is 31 bytes; sizing
	// for it costs one allocation on a path that runs per shipped log record.
	b.Grow(31)
	for i, name := range tcpFlagNames {
		if f&(1<<uint(i)) == 0 {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(name)
	}
	return b.String()
}

// LogBody is a compact, human-readable one-line summary of the flow, used as the OTLP
// log body. The structured attributes carry the queryable detail; the body is for a
// human scanning the stream.
func (r Record) LogBody() string {
	var b strings.Builder
	b.WriteString(endpoint(r.SrcAddr.String(), r.SrcPort))
	b.WriteString(" -> ")
	b.WriteString(endpoint(r.DstAddr.String(), r.DstPort))
	b.WriteByte(' ')
	b.WriteString(transportName(r.Proto))
	if r.L7.AppName != "" {
		b.WriteByte(' ')
		b.WriteString(r.L7.AppName)
	}
	if v := r.Verdict.String(); v != "" {
		b.WriteByte(' ')
		b.WriteString(v)
	}
	return b.String()
}

// LogSeverityBlocked reports whether the flow was blocked, so the lane can raise the
// OTLP severity for a dropped flow without this package importing logship's Severity.
func (r Record) LogSeverityBlocked() bool { return r.Verdict == VerdictBlock }

func endpoint(ip string, port uint16) string {
	if port == 0 {
		return ip
	}
	return ip + ":" + strconv.Itoa(int(port))
}

// dscpStandardNames maps the differentiated-services codepoints that have a
// conventional name to it: the RFC 2474 class selectors, the RFC 2597 assured-
// forwarding classes, and RFC 3246's expedited forwarding.
//
// Deliberately NOT exhaustive over 0-63. A codepoint outside this table is a real
// value that some sender chose, so it still reports its NUMBER — dropping it would
// hide the non-standard markings that are usually the interesting ones. The table
// only decides whether a friendly name can be added alongside.
//
// DSCP 0 (CS0, "default") is absent on purpose: unmarked is emitted as no attribute
// at all, so naming it would be unreachable.
var dscpStandardNames = map[uint8]string{
	8: "CS1", 16: "CS2", 24: "CS3", 32: "CS4", 40: "CS5", 48: "CS6", 56: "CS7",
	10: "AF11", 12: "AF12", 14: "AF13",
	18: "AF21", 20: "AF22", 22: "AF23",
	26: "AF31", 28: "AF32", 30: "AF33",
	34: "AF41", 36: "AF42", 38: "AF43",
	46: "EF",
}

// dscpClass returns the conventional name for a codepoint, or "" when it has none.
func dscpClass(d uint8) string { return dscpStandardNames[d] }

// ecnStates are the four ECN codepoints of RFC 3168 in numeric order. The spellings
// are the RFC's own, because "CE" and "ECT(0)" are what an operator searches for;
// the raw numbers 0-3 convey nothing without the table.
//
// Index 0, Not-ECT, is the empty string: like an unmarked DSCP it is the default and
// is emitted as no attribute rather than as noise on every record.
var ecnStates = [4]string{"", "ECT(1)", "ECT(0)", "CE"}

// ecnState renders the two ECN bits. Values above 3 are impossible — the caller
// masks to 2 bits at decode — but the bound is checked rather than assumed, because
// this runs on data from an unauthenticated socket.
func ecnState(e uint8) string {
	if int(e) >= len(ecnStates) {
		return ""
	}
	return ecnStates[e]
}
