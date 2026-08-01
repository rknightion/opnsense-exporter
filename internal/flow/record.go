// Package flow is the exporter's normalized flow-record pipeline. Two sources feed
// it — Zenarmor's per-connection `conn` family and (phase 2) a NetFlow v5/v9
// receiver — and both produce the same Record, so one metric family and one Loki
// query cover both.
//
// The package never talks to the OPNsense API. Like the syslog and Zenarmor log
// lanes it reads an atomically-published enrich.Snapshot, so every lookup on the
// hot path is a map read with no lock and no allocation.
package flow

import (
	"net/netip"
	"time"
)

// Source names which lane produced a Record. It is a metric label, so the set is
// closed and code-defined.
type Source uint8

const (
	SourceUnknown Source = iota
	SourceNetflow
	SourceZenarmor
	SourceMerged // a correlated pair (phase 3)
)

func (s Source) String() string {
	switch s {
	case SourceNetflow:
		return "netflow"
	case SourceZenarmor:
		return "zenarmor"
	case SourceMerged:
		return "merged"
	default:
		return "unknown"
	}
}

// Direction is the flow's orientation relative to the firewall's own networks.
//
// "unknown" is a real, emitted value. NetFlow v9 from OPNsense does not export the
// DIRECTION element at all (#346), and Zenarmor's own direction field cannot
// express "internal", so inventing a value to avoid an empty label would fabricate
// data. See directionOf in the Zenarmor adapter for how the two are combined.
type Direction uint8

const (
	DirectionUnknown Direction = iota
	DirectionInbound
	DirectionOutbound
	DirectionInternal
)

func (d Direction) String() string {
	switch d {
	case DirectionInbound:
		return "inbound"
	case DirectionOutbound:
		return "outbound"
	case DirectionInternal:
		return "internal"
	default:
		return "unknown"
	}
}

// Verdict is the firewall's disposition. Only Zenarmor states one; NetFlow carries
// no verdict, so VerdictUnknown is correct there and must never be read as "pass".
type Verdict uint8

const (
	VerdictUnknown Verdict = iota
	VerdictPass
	VerdictBlock
)

// String renders the verdict as its metric label value. Unknown renders EMPTY
// rather than "unknown", matching how parse.go:95-107 leaves AttrAction unset for a
// document that stated no disposition: claiming one the source never gave would
// corrupt the very query the label exists to serve.
func (v Verdict) String() string {
	switch v {
	case VerdictPass:
		return "pass"
	case VerdictBlock:
		return "block"
	default:
		return ""
	}
}

// Counters is one source's view of a flow's volume.
//
// Present distinguishes "this source reported zero bytes" from "this source said
// nothing at all". Without it, a merged record carrying only NetFlow data is
// indistinguishable from one where Zenarmor genuinely reported a zero-byte flow,
// and the phase-3 byte-delta signal would report a 100% discrepancy on every
// NetFlow-only flow.
type Counters struct {
	TxBytes, RxBytes     uint64
	TxPackets, RxPackets uint64
	Present              bool
}

// Bytes is the flow's total volume in both directions.
func (c Counters) Bytes() uint64 { return c.TxBytes + c.RxBytes }

// Packets is the flow's total packet count in both directions.
func (c Counters) Packets() uint64 { return c.TxPackets + c.RxPackets }

// Iface is one end of the flow's interface attribution.
//
// Corrected records that the WAN-egress repair (phase 2) overrode what the exporter
// reported. ng_netflow derives OUTPUT_SNMP from a FIB lookup while OPNsense's
// multi-WAN policy routing happens in pf, so the exported egress interface is wrong
// for every policy-routed flow (#346). A repair nobody can observe is a repair
// nobody will trust, so this drives a counter.
type Iface struct {
	Device    string // kernel name, e.g. "ixl0_vlan50"
	Name      string // OPNsense description, e.g. "IOT"; empty when unmapped
	Index     uint32 // NetFlow ifIndex; 0 for Zenarmor
	Corrected bool
	// Unresolved marks an interface whose DEVICE the record's source stated but whose
	// description could not be looked up, because the enrichment snapshot had not
	// arrived yet (#606).
	//
	// It exists because Label()'s device fallback is right for a device the box
	// genuinely has no description for, and WRONG here: the box has a description, we
	// simply had not loaded it, so falling back produced a SECOND series
	// (interface="ixl0") for an interface that already had one (interface="LAN"), and
	// every `sum by (interface)` under-reported both. Measured on the reference box:
	// every byte ever attributed to a raw kernel device landed with the process less
	// than 300 seconds old, across 7 days and 51 restarts.
	//
	// The device is NOT discarded — it still travels on the record and reaches the log
	// as flow.in_device / flow.out_device. What changes is that the metric label says
	// "unresolved" instead of impersonating a distinct interface.
	Unresolved bool
}

// UnresolvedInterfaceLabel is the metric-label value for an interface whose
// description could not be resolved (see Iface.Unresolved).
//
// A named sentinel rather than "": an empty label is absent to Prometheus, so the
// bytes would vanish from `sum by (interface)` entirely rather than showing up as a
// bucket an operator can see, alert on, and watch drain after a restart.
const UnresolvedInterfaceLabel = "unresolved"

// Label returns the value to use as a metric label: the friendly name when
// enrichment resolved one, else the raw device. Never a guessed name — an unmapped
// ifIndex yields "", because a wrong interface label is worse than a missing one.
func (i Iface) Label() string {
	if i.Name != "" {
		return i.Name
	}
	if i.Unresolved && i.Device != "" {
		// The box HAS a description for this device; we just could not read it yet.
		// Returning the device here would invent a second series for an interface that
		// already has one (#606).
		return UnresolvedInterfaceLabel
	}
	return i.Device
}

// L7 is application-layer classification. Zenarmor supplies it; NetFlow cannot.
type L7 struct {
	AppName     string // high cardinality: metadata only, NEVER a metric label
	AppProto    string
	AppCategory string // bounded taxonomy (24 values observed live): safe as a label
	DomainCat   string // bounded taxonomy: safe as a label
	// Encryption is Zenarmor's transport-security verdict for the connection, verbatim
	// as sent: "Clear" or "TLS-Encrypted" across the live capture. It is a LOG
	// ATTRIBUTE only (#585) — bounded enough to be a label, but the flow label set is
	// closed at seven and this answers a query ("which internal hosts still send
	// cleartext to the internet") that wants the addresses beside it anyway.
	//
	// It lives INSIDE L7 rather than beside it because the correlator copies L7
	// wholesale onto a merged record (correlate.go finalize). A sibling field on Record
	// would need its own line there and would otherwise be silently dropped on every
	// merged record — the only kind of record that carries a Zenarmor verdict and
	// NetFlow volume together.
	Encryption string
}

// Enrichment is everything resolved from the enrich.Snapshot. All of it is
// structured metadata; only the scopes are bounded enough to be a metric label,
// and only DstScope is used as one.
type Enrichment struct {
	SrcHostname string
	DstHostname string
	// SrcScope and DstScope are enrich.Snapshot.Scope values: "self", "local",
	// "remote" or "" — never "external". "self" is the firewall itself and is NOT
	// remote, so a LAN host querying the firewall's resolver is internal traffic.
	SrcScope   string
	DstScope   string
	DstService string // IANA service name for the destination port
	DstDomain  string // from the phase-2 DNS answer cache; unbounded, metadata only
}

// Repairs records the normalisations applied on the way in, so each one is
// countable at the sink instead of being silent. A repair nobody can observe is a
// repair nobody will trust — the same reasoning behind Iface.Corrected, which
// covers the phase-2 WAN-egress correction.
type Repairs struct {
	// PayloadByteFallback is set when a side reported zero wire bytes against a
	// non-zero payload byte count, so the payload figure was used instead. Zenarmor
	// only starts accumulating wire bytes once it has tracked a flow past its first
	// packets, which leaves 27.6% of flow-sides at zero (#346).
	PayloadByteFallback bool
	// VLANSubnetAttributed is set when the repair stage moved this record from a TRUNK
	// onto the VLAN child whose configured subnet owns the relevant address (mechanism
	// A', #465). The record's In and/or Out therefore name an interface the exporter
	// deduced rather than one ng_netflow reported.
	//
	// It lives here and NOT on Iface.Corrected, which ifaceIsWAN reads as proof that an
	// interface is a WAN by construction — setting that on a VLAN child would make the
	// direction rules treat an IOT interface as an uplink.
	VLANSubnetAttributed bool
	// PolicyRouteCorrected is set when the repair stage replaced this record's egress
	// with the device pf's own state table says the traffic left by (#603). ng_netflow
	// derives OUTPUT_SNMP from a FIB lookup, and on a policy-routed multi-WAN box the
	// PRE-NAT copy — the only one that can correlate with Zenarmor — therefore names
	// the default-route WAN whatever pf actually did.
	//
	// It lives here and NOT on Iface.Corrected for the same reason
	// VLANSubnetAttributed does: ifaceIsWAN reads that flag as proof that an interface
	// is a WAN by construction, an invariant only the phase-2 repair may assert.
	PolicyRouteCorrected bool

	// ZenBytesArePayload states the BYTE BASIS of the Zenarmor side on a merged
	// record: true means the figure is Zenarmor's PAYLOAD bytes (pbytes), false that
	// it is wire bytes (nbytes).
	//
	// It exists because opnsense_flow_source_byte_delta_ratio compares that figure
	// against NetFlow's WIRE bytes, and on the reference box the fallback fires on
	// roughly HALF of all Zenarmor flow records — 2-3 packet UDP flows, where the
	// per-packet gap clusters at 28 bytes (the IPv4 IP+UDP header) and the ratio's
	// p90 reaches 1.96 on that sub-population alone (#604). Without this the metric
	// reports header overhead as source disagreement and nothing downstream can tell
	// the two apart.
	//
	// It is distinct from PayloadByteFallback, which is the ZENARMOR LANE's own
	// record-level flag. finalize() builds the merged record from a NETFLOW half, so
	// the lane's flag does not survive the merge — this is the field that does.
	ZenBytesArePayload bool

	// WindowPartial states that this record's NetFlow side covers only PART of the
	// connection its Zenarmor side counts in full.
	//
	// corrKey buckets by floor(End / window), so a connection longer than the window
	// emits one record per window carrying only that window's NetFlow bytes, while
	// the single conn document carries the whole connection's counters and merges
	// into whichever bucket its End falls in. The reference box runs
	// activeTimeout=1800, so this is routine: 3.2% of merged records overall and
	// 12.3% of the default WAN's read a ratio below 0.9, some as low as 0.013 — "the
	// firewall counted 75x fewer bytes than crossed the wire", which is impossible
	// and is a partial total against a complete one (#604).
	//
	// The delta-ratio histogram EXCLUDES these and counts the exclusions. The record
	// still ships, and still carries both sides' counters: the volume is real, only
	// the COMPARISON is meaningless.
	WindowPartial bool
}

// merge folds another fragment's repairs into these, keeping anything either one
// recorded.
//
// A conversation arrives as several NetFlow records — a mean of 3.75 on the
// reference box — and the correlator takes every non-volume dimension from ONE
// chosen orientation. A repair applied to any other fragment therefore vanished at
// the merge: the record still carried the corrected interface (that IS the chosen
// half's field when the chosen half is the corrected one) but the marker saying so
// could be dropped, which is precisely the "a repair nobody can observe" failure
// this type exists to prevent. Unioning is the same treatment TCPFlags already gets
// and for the same reason: it is a merge by design, not a loss.
//
// PayloadByteFallback is unioned too, but note the merged record's Zenarmor byte
// basis is stated by ZenBytesArePayload, which finalize sets from the conn document
// itself rather than from any NetFlow half.
func (r *Repairs) merge(o Repairs) {
	r.PayloadByteFallback = r.PayloadByteFallback || o.PayloadByteFallback
	r.VLANSubnetAttributed = r.VLANSubnetAttributed || o.VLANSubnetAttributed
	r.PolicyRouteCorrected = r.PolicyRouteCorrected || o.PolicyRouteCorrected
	r.ZenBytesArePayload = r.ZenBytesArePayload || o.ZenBytesArePayload
	r.WindowPartial = r.WindowPartial || o.WindowPartial
}

// Record is one normalized flow. Both lanes produce it; the rollup, the correlator
// and the OTLP emitter all consume it.
type Record struct {
	Source   Source
	Start    time.Time // firewall clock
	End      time.Time // firewall clock
	Observed time.Time // arrival at the exporter

	Proto   uint8
	SrcAddr netip.Addr
	DstAddr netip.Addr
	SrcPort uint16
	DstPort uint16

	// CommunityID is the Corelight community-id v1 hash of the canonical tuple,
	// computed by the exporter for BOTH sources. Zenarmor emits a field of the same
	// name, but it is NOT community-id v1 over the 5-tuple: a sweep of all 65,536
	// seeds against five real documents matched none of them, so it is neither
	// trusted nor compared against.
	CommunityID string

	// NF and Zen are never summed. They measure at different points in the stack and
	// will legitimately disagree; the disagreement is itself a signal (#346
	// decision 3).
	NF        Counters
	Zen       Counters
	Fragments int // NetFlow records folded into this record; 0 for Zenarmor-only

	// TCPFlags is the union of the TCP control bits NetFlow reported (element 6),
	// OR-ed across every fragment the correlator folded together. A single NetFlow
	// record already reports the union over its own packets, so extending it across a
	// connection-window's fragments keeps the field meaning one thing — and it has to
	// be a union, because the two directions of a conversation arrive as separate
	// records and the first fragment alone says "SYN" for practically every TCP flow.
	//
	// Zero means "nothing reported", never "a segment with no flags set": no legal TCP
	// segment carries an empty flag byte, so the two readings collapse and no separate
	// presence bit is needed. Zenarmor supplies nothing here — its own
	// src_tcp_flags/dst_tcp_flags were empty on every document of the live capture and
	// are not modelled — so this stays zero on a Zenarmor-only record.
	TCPFlags uint8

	// DSCP is the differentiated-services codepoint from NetFlow element 5, and ECN
	// the two congestion bits beside it. Both are NetFlow-only — Zenarmor supplies
	// neither — so both stay zero on a Zenarmor-only record.
	//
	// Zero means unmarked, which is the overwhelming majority (~89% of records on the
	// reference box) and is why neither reaches the emitted attributes: a
	// `netflow.dscp="0"` on nine flow logs in ten is bytes carrying no information.
	// Absent therefore reads as "unmarked, or NetFlow never described this flow", and
	// the two are deliberately not distinguished — no consumer has yet needed to, and
	// a presence bit nothing reads is the dead weight #586 removed from SRC_AS.
	//
	// Unioning is wrong here, unlike TCPFlags: a codepoint is a value, not a bit set,
	// and OR-ing EF with AF31 yields a codepoint nobody sent. The correlator takes
	// both from the chosen orientation's sample, like every other non-volume field.
	DSCP uint8
	ECN  uint8

	// SrcMask/DstMask are the FIB prefix lengths NetFlow reported for each end
	// (elements 9 and 13). Zero is a real answer — no covering route — and is emitted,
	// unlike a zero DSCP: it is uncommon enough to be worth seeing, and it is the
	// value that explains a next-hop naming the default gateway.
	SrcMask, DstMask uint8

	In        Iface
	Out       Iface
	Direction Direction
	VLANID    string

	Verdict Verdict
	L7      L7
	Enrich  Enrichment
	Repairs Repairs

	// Geo is MaxMind geolocation for the external end(s), merged with whatever
	// Zenarmor supplied (#520). It is filled by GeoEnricher AFTER Enrich, because the
	// precedence rules read Zenarmor's values and the metric label reads the scopes.
	// Absent entirely when --geoip.enabled is off.
	Geo GeoInfo
}

// Tuple is the canonical, direction-independent identity of a conversation.
type Tuple struct {
	Proto        uint8
	AAddr, BAddr netip.Addr
	APort, BPort uint16
}

// CanonicalTuple orders the two endpoints so that the same conversation observed
// from either direction yields an identical value. That is what makes it usable as
// a join key across two sources that disagree about which end is "source" — and
// across NetFlow's unidirectional halves, which report one conversation twice with
// the endpoints swapped (#346).
//
// Addresses are Unmapped first: ::ffff:192.0.2.5 and 192.0.2.5 are the same host,
// but netip compares them as different Addrs, so without this one conversation
// would canonicalise two ways and the phase-3 correlator would silently miss every
// join involving one. enrich.Snapshot.Scope Unmaps for the same reason
// (snapshot.go:97), where its comment warns a string key "would silently miss most
// of them".
func (r Record) CanonicalTuple() Tuple {
	a, ap := r.SrcAddr.Unmap(), r.SrcPort
	b, bp := r.DstAddr.Unmap(), r.DstPort
	if !endpointLess(a, ap, b, bp) {
		a, ap, b, bp = b, bp, a, ap
	}
	return Tuple{Proto: r.Proto, AAddr: a, APort: ap, BAddr: b, BPort: bp}
}

// endpointLess orders endpoints by address then port, matching the community-id
// spec's ordering rule so CanonicalTuple and CommunityID never disagree about which
// end is first. Callers pass already-Unmapped addresses.
func endpointLess(a netip.Addr, ap uint16, b netip.Addr, bp uint16) bool {
	if c := a.Compare(b); c != 0 {
		return c < 0
	}
	return ap < bp
}

// Sink receives normalized flow records. The collector's rollup store implements
// it; the receiver lanes hold one and never learn what is on the other side.
//
// Observe MUST NOT block and MUST NOT perform I/O: it is called on the receiver's
// request goroutine, where a stall backs up the socket read loop and silently drops
// data — the same contract as logship.Deps.Miss (source.go:94-97).
type Sink interface {
	Observe(Record)
}
