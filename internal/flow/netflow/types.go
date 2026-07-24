// Package netflow decodes NetFlow v5 and v9 datagrams into flat records, ready to
// be normalized into a flow.Record.
//
// Scope is deliberately narrow: OPNsense's ng_netflow, which emits v5 or v9 and
// nothing else. There is no IPFIX, no options-template interpretation, and no
// variable-length field support — see the rules on Decoder.
//
// This file is the CONTRACT the decoder, the listener and the pipeline share. The
// decoder owns decode.go and template.go; nothing else in the package may redefine
// these types.
package netflow

import (
	"errors"
	"net/netip"
	"slices"
	"time"
)

// Version is the export version from the datagram header.
type Version uint16

const (
	V5 Version = 5
	V9 Version = 9
)

// Record is one decoded flow record, before any normalization, repair or
// enrichment. Fields the export does not carry are left zero — a NetFlow record
// is strictly unidirectional and the OPNsense export declares OUT_BYTES/OUT_PKTS
// but always sends zero (#346), so Bytes/Packets are the only volume here.
type Record struct {
	Proto            uint8
	SrcAddr, DstAddr netip.Addr
	SrcPort, DstPort uint16

	Bytes   uint64
	Packets uint64

	// InIfIndex/OutIfIndex are ng_netflow's ifinfo enumeration ordinals, NOT OS or
	// SNMP indices (#346 repair 1). Resolving them is flow.IfMap's job; the decoder
	// passes them through untouched.
	InIfIndex, OutIfIndex uint32

	// First/Last are absolute times on the FIREWALL's clock, resolved by the
	// decoder from the header's unix_secs/sysUpTime and the record's
	// FIRST_SWITCHED/LAST_SWITCHED (which are sysUpTime-relative milliseconds).
	First, Last time.Time

	TCPFlags     uint8
	SrcAS, DstAS uint32 // 32-bit: this export declares len=4, not the usual 2 (#346)
	VLANID       uint16

	TemplateID uint16 // 0 for v5; the v9 template this record was decoded with
}

// Datagram is one decoded export packet.
type Datagram struct {
	Version    Version
	SourceID   uint32 // v9 source_id; 0 for v5
	Sequence   uint32
	ExportTime time.Time // the firewall's clock, from the header
	Records    []Record

	// Unidentified lists everything in this datagram the decoder stepped over
	// because it could not interpret it (#360). Stepping over is the CORRECT parse
	// behaviour and is not what this reports on; what it reports is that the export
	// carried something we do not model, so an operator can see it and a debug
	// capture can keep the bytes. Empty on a datagram the decoder fully understood,
	// which is what makes "capture only the unidentified" a bounded mode.
	Unidentified []Unidentified
}

// Unidentified names one thing the decoder did not interpret.
//
// Detail is the identifier the kind refers to — the v9 element id for
// UnidentifiedField, the flowset id for the two flowset kinds — and is deliberately
// NEVER used as a metric label: this arrives on an unauthenticated socket, so a
// sender could mint arbitrary ids. It reaches the log line and the debug capture
// only, and the metric counts by KIND, which is a closed code-defined set.
type Unidentified struct {
	Kind   string
	Detail uint16
}

// The closed kind vocabulary. The three below are the decoder's; the listener adds
// its own error-derived kinds (see capture.go).
const (
	// UnidentifiedField is a template element the decoder does not model. It is
	// reported at LEARN time, once per element, and only when the template was
	// actually stored (a new id, or a known id whose shape changed) — never on the
	// ~2-minutely re-send of a shape already held.
	UnidentifiedField = "unknown_field"
	// UnidentifiedOptions is an options-template flowset, stepped over and never
	// interpreted.
	UnidentifiedOptions = "options_template"
	// UnidentifiedFlowset is a flowset in the reserved 2-255 range that is neither a
	// template nor an options template.
	UnidentifiedFlowset = "unknown_flowset"
)

// maxUnidentifiedPerDatagram bounds the report, NOT the counters. A datagram is at
// most 65535 bytes, so a sender could pack it with ~16,000 four-byte unknown control
// flowsets and make every worker allocate a slice that large and render it into a log
// line and a capture entry. The counters stay exact — they are what an operator acts
// on — while the list stays a SAMPLE, which is all it was ever read as.
const maxUnidentifiedPerDatagram = 32

// note records one unidentified item, deduplicated and bounded. Deduplication
// matters as much as the bound: a flowset id repeated 400 times in one datagram is
// one fact, and 400 identical entries would bury the others past the cap.
func (d *Datagram) note(u Unidentified) {
	if slices.Contains(d.Unidentified, u) || len(d.Unidentified) >= maxUnidentifiedPerDatagram {
		return
	}
	d.Unidentified = append(d.Unidentified, u)
}

// Stats counts everything the decoder chose not to trust. Every field here is
// published as a metric: a decoder that silently drops input is indistinguishable
// from a quiet network.
type Stats struct {
	Datagrams uint64
	Records   uint64

	// NoTemplate counts data flowsets dropped because their template has not been
	// seen yet. Bounded at ~2 min from a cold start: ng_netflow resends templates
	// roughly every 2 minutes (#346), which is why no on-disk template cache exists.
	NoTemplate uint64

	Malformed          uint64 // truncated header, impossible lengths, short flowset
	UnsupportedVersion uint64
	VarLenRejected     uint64 // a 0xffff field length; rejected, never guessed at
	TemplatesLearned   uint64
	TemplatesReplaced  uint64 // a known template id re-sent with a DIFFERENT shape

	// UnexpectedOutBytes counts records carrying a non-zero OUT_BYTES/OUT_PKTS.
	// #346 proved these are always zero on this export, and the decoder ignores
	// them entirely rather than adding them to Bytes. Reading them as a fallback
	// would silently double a real counter the day OPNsense starts populating them,
	// so instead we assert and count: a non-zero rate here means the export shape
	// changed and this decision needs revisiting.
	UnexpectedOutBytes uint64

	// The three things the decoder used to step over in TOTAL silence (#360). Each
	// is counted per occurrence, not per record: UnknownFields at template-learn
	// time (once per unmodelled element of a stored template), the other two per
	// flowset. A non-zero UnknownFields is EXPECTED on OPNsense — the production
	// IPv4 template declares four elements this decoder does not model — so it is a
	// CHANGE in these that is the signal, not their existence.
	UnknownFields    uint64
	OptionsTemplates uint64
	UnknownFlowsets  uint64
}

// modelledFields is exactly the element set readRecord acts on. It is the decoder's
// own switch, restated as data so learnTemplates can answer "will we read this?"
// without duplicating the list by hand.
//
// FieldDirection is deliberately ABSENT: the constant exists because the element is
// worth recognising in a log line, but Record has nowhere to put it, so a template
// declaring it is carrying something we do not model and must say so.
var modelledFields = map[uint16]bool{
	FieldInBytes: true, FieldInPkts: true, FieldProtocol: true, FieldTCPFlags: true,
	FieldL4SrcPort: true, FieldL4DstPort: true,
	FieldIPv4SrcAddr: true, FieldIPv4DstAddr: true,
	FieldIPv6SrcAddr: true, FieldIPv6DstAddr: true,
	FieldInputSNMP: true, FieldOutputSNMP: true,
	FieldSrcAS: true, FieldDstAS: true,
	FieldFirstSwitched: true, FieldLastSwitched: true,
	FieldOutBytes: true, FieldOutPkts: true,
	FieldSrcVLAN: true, FieldDstVLAN: true,
}

// Decoder errors. A caller distinguishes "this datagram was not for us" from "this
// datagram was malformed" — the first is an allowlist/config problem, the second is
// a decode bug or a corrupted sender, and they warrant different operator action.
var (
	ErrShortPacket        = errors.New("netflow: datagram shorter than its header")
	ErrUnsupportedVersion = errors.New("netflow: unsupported export version")
	ErrMalformed          = errors.New("netflow: malformed flowset")
	ErrVariableLength     = errors.New("netflow: variable-length field (0xffff) is not supported")
)

// NetFlow v9 field type numbers this decoder understands. Anything else is skipped
// by its template-declared length — never by guesswork, which would desynchronise
// every subsequent record in the set.
const (
	FieldInBytes       = 1
	FieldInPkts        = 2
	FieldProtocol      = 4
	FieldTCPFlags      = 6
	FieldL4SrcPort     = 7
	FieldIPv4SrcAddr   = 8
	FieldInputSNMP     = 10
	FieldL4DstPort     = 11
	FieldIPv4DstAddr   = 12
	FieldOutputSNMP    = 14
	FieldSrcAS         = 16
	FieldDstAS         = 17
	FieldLastSwitched  = 21
	FieldFirstSwitched = 22
	FieldOutBytes      = 23
	FieldOutPkts       = 24
	FieldIPv6SrcAddr   = 27
	FieldIPv6DstAddr   = 28
	FieldSrcVLAN       = 58
	FieldDstVLAN       = 59
	FieldDirection     = 61 // NOT exported by this box (#346); handled if it appears
)
