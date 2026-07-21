package flow

import (
	"strconv"
	"sync/atomic"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/flow/netflow"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// Processor turns decoded NetFlow datagrams into normalized flow.Records and hands
// them to a Sink.
//
// Stage order is load-bearing: normalize -> repair -> enrich -> rollup.
//
//   - repair precedes enrich because the VLAN/parent de-dup must drop the parent
//     copy BEFORE it is named, scoped and counted; enriching a record that is about
//     to be discarded is not merely wasted work, it would also let the duplicate
//     reach the rollup if the ordering were ever reversed.
//   - enrich precedes rollup because the rollup's labels (interface, scope,
//     direction) are what enrichment produces.
//
// The rollup happens on arrival and never waits on anything downstream, so a slow
// or stalled consumer can delay logs but can never delay or lose a metric.
type Processor struct {
	sink Sink
	rep  *Repairer
	// cache is read per datagram rather than per record: a Snapshot is immutable and
	// atomically published, so holding one for the whole datagram gives every record
	// in it a consistent view instead of straddling a refresh.
	cache *enrich.Cache

	// ifmap is swapped wholesale when the interface table refreshes. Readers take no
	// lock; the map itself is immutable after construction.
	ifmap atomic.Pointer[IfMap]

	datagrams  atomic.Uint64
	recordsIn  atomic.Uint64
	emitted    atomic.Uint64
	dropped    atomic.Uint64
	noAddress  atomic.Uint64
	noIfaceMap atomic.Uint64
}

// ProcessorStats is a snapshot of the pipeline counters. Every one is published as
// a metric: a pipeline that discards records silently is indistinguishable from a
// network with nothing on it.
type ProcessorStats struct {
	Datagrams       uint64
	RecordsIn       uint64
	RecordsEmitted  uint64
	RecordsDropped  uint64 // VLAN/parent duplicates suppressed by the repair stage
	RecordsNoAddr   uint64 // unparseable or missing endpoints
	RecordsUnmapped uint64 // neither ifIndex resolved to a device
}

// NewProcessor builds the NetFlow pipeline. sink and rep must be non-nil; cache may
// be nil, in which case records ship unenriched rather than not at all.
func NewProcessor(sink Sink, rep *Repairer, cache *enrich.Cache) *Processor {
	return &Processor{sink: sink, rep: rep, cache: cache}
}

// SetIfMap publishes a new ifIndex map. Safe to call while records are in flight.
func (p *Processor) SetIfMap(m *IfMap) { p.ifmap.Store(m) }

// IfMap returns the current map, which may be nil before the first interface
// refresh completes.
func (p *Processor) IfMap() *IfMap { return p.ifmap.Load() }

// ObserveDatagram runs every record in a decoded datagram through the pipeline.
func (p *Processor) ObserveDatagram(dg *netflow.Datagram, now time.Time) {
	if dg == nil {
		return
	}
	p.datagrams.Add(1)

	var snap *enrich.Snapshot
	if p.cache != nil {
		snap = p.cache.Load()
	}
	m := p.ifmap.Load()

	for _, nr := range dg.Records {
		p.recordsIn.Add(1)

		rec, ok := normalizeNetflow(nr, now)
		if !ok {
			p.noAddress.Add(1)
			continue
		}
		if m != nil {
			rec.In = m.Iface(nr.InIfIndex)
			rec.Out = m.Iface(nr.OutIfIndex)
			if rec.In.Device == "" && rec.Out.Device == "" {
				p.noIfaceMap.Add(1)
			}
		}

		// Repair mutates in place and reports whether to keep the record. A false
		// return is a VLAN/parent duplicate: the same packets already counted on the
		// child interface, which is ~4% of bytes on the reference capture.
		if p.rep != nil && !p.rep.Repair(&rec, m, snap, now) {
			p.dropped.Add(1)
			continue
		}

		enrichRecord(&rec, snap)
		p.emitted.Add(1)
		if p.sink != nil {
			p.sink.Observe(rec)
		}
	}
}

// Stats returns a snapshot of the pipeline counters.
func (p *Processor) Stats() ProcessorStats {
	return ProcessorStats{
		Datagrams:       p.datagrams.Load(),
		RecordsIn:       p.recordsIn.Load(),
		RecordsEmitted:  p.emitted.Load(),
		RecordsDropped:  p.dropped.Load(),
		RecordsNoAddr:   p.noAddress.Load(),
		RecordsUnmapped: p.noIfaceMap.Load(),
	}
}

// normalizeNetflow converts a decoded NetFlow record into the shared seam.
//
// ok is false when the record carries no usable endpoints. A record without
// addresses would put a zero-address series into the rollup and a meaningless entry
// into the correlator — the same guard the Zenarmor adapter applies.
func normalizeNetflow(nr netflow.Record, now time.Time) (Record, bool) {
	if !nr.SrcAddr.IsValid() || !nr.DstAddr.IsValid() {
		return Record{}, false
	}
	// Unmapped once, here, so the canonical tuple, the community id and every scope
	// lookup agree about what address this is. The decoder already unmaps; doing it
	// again is free and keeps this function correct on its own terms.
	src, dst := nr.SrcAddr.Unmap(), nr.DstAddr.Unmap()

	r := Record{
		Source:   SourceNetflow,
		Observed: now,
		Start:    nr.First,
		End:      nr.Last,
		Proto:    nr.Proto,
		SrcAddr:  src,
		DstAddr:  dst,
		SrcPort:  nr.SrcPort,
		DstPort:  nr.DstPort,
		// Load-bearing for the VLAN/parent de-dup: a record naming a VLAN tag while
		// sitting on that tag's PARENT device is by construction the duplicate copy,
		// and that test is what makes the de-dup independent of which copy arrives
		// first. Dropping this field silently downgrades repair 1 to the arrival-order
		// backstop. (This export carries no VLAN field today, so the value is usually
		// zero — but the shape is what the repair codes against.)
		VLANID: vlanString(nr.VLANID),
		// A NetFlow record is strictly unidirectional (#346: OUT_BYTES/OUT_PKTS are
		// declared but always zero), so all volume is Tx and Rx stays zero. This is
		// NOT the same as "the reverse direction carried nothing" — the reverse
		// direction is simply a separate record.
		NF: Counters{
			TxBytes:   nr.Bytes,
			TxPackets: nr.Packets,
			Present:   true,
		},
		Fragments: 1,
	}
	if r.End.IsZero() {
		r.End = r.Start
	}
	r.CommunityID = CommunityID(r.CanonicalTuple(), 0)
	return r, true
}

// enrichRecord resolves everything the enrichment snapshot knows. It is applied
// identically to both lanes, so the same flow described by both sources lands on
// the same labels.
func enrichRecord(r *Record, snap *enrich.Snapshot) {
	if snap == nil {
		return
	}
	if r.In.Name == "" && r.In.Device != "" {
		if name, ok := snap.InterfaceName(r.In.Device); ok {
			r.In.Name = name
		}
	}
	if r.Out.Name == "" && r.Out.Device != "" {
		if name, ok := snap.InterfaceName(r.Out.Device); ok {
			r.Out.Name = name
		}
	}
	r.Enrich.SrcScope = snap.Scope(r.SrcAddr.String())
	r.Enrich.DstScope = snap.Scope(r.DstAddr.String())
	if h, ok := snap.Hostname(r.SrcAddr.String()); ok {
		r.Enrich.SrcHostname = h
	}
	if h, ok := snap.Hostname(r.DstAddr.String()); ok {
		r.Enrich.DstHostname = h
	}
	if r.DstPort != 0 {
		if svc, ok := enrich.ServiceName(strconv.Itoa(int(r.DstPort)), protoName(r.Proto)); ok {
			r.Enrich.DstService = svc
		}
	}
}

// protoName maps the IANA protocol number to the lowercase name the service table
// is keyed by. Anything else yields "", which simply misses the lookup.
func protoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 132:
		return "sctp"
	}
	return ""
}

// vlanString renders a NetFlow VLAN tag the way the Zenarmor lane already does, so
// one field means one thing across both. Tag 0 is "untagged", not "VLAN zero", and
// must stay empty — the de-dup keys off a non-empty tag.
func vlanString(tag uint16) string {
	if tag == 0 {
		return ""
	}
	return strconv.Itoa(int(tag))
}

// interfaceLabel is the rollup's view of which interface a record belongs to.
//
// A NetFlow record crosses TWO interfaces and the label can name only one, so this
// picks the WAN-FACING side: the egress for traffic going out, the ingress for
// traffic coming in. That makes per-WAN volume answerable, which is the entire point
// of the policy-routing repair — on the reference capture OUTPUT_SNMP mislabelled
// 3.36 GB of WAN2 traffic as WAN1, and a label that named the LAN side would correct
// the record while leaving the metric just as wrong.
//
// The cost, chosen deliberately: a LAN host's internet traffic is attributed to the
// WAN it left by, not to its own VLAN, so per-VLAN volume is visible for internal
// traffic only. The two lanes therefore disagree about the same flow — Zenarmor sets
// only In and keeps naming the VLAN child — and a query that does not pin `source`
// mixes the two meanings as well as double-counting the bytes.
//
// Zenarmor records are unaffected: Out is always empty there, so this returns In,
// exactly as phase 1 did.
func interfaceLabel(r Record) string {
	if r.Direction == DirectionInbound {
		if lbl := r.In.Label(); lbl != "" {
			return lbl
		}
		return r.Out.Label()
	}
	if lbl := r.Out.Label(); lbl != "" {
		return lbl
	}
	return r.In.Label()
}
