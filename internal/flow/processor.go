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

	// dnsCache resolves a bare destination IP to the domain the client looked up
	// (#353). nil when domain enrichment is off (--flow.dns-cache.size=0); a nil cache
	// is a safe no-op, so enrichRecord holds it unconditionally.
	dnsCache *DNSCache

	// ifmapCounters outlives every map SetIfMap publishes; see IfMapCounters.
	ifmapCounters IfMapCounters

	datagrams  atomic.Uint64
	recordsIn  atomic.Uint64
	emitted    atomic.Uint64
	dropped    atomic.Uint64
	noAddress  atomic.Uint64
	noIfaceMap atomic.Uint64
	// held is a GAUGE, not a counter: it goes up on a hold and back down on the
	// release, so it is the term that closes the accounting identity while records are
	// still in flight (see ProcessorStats.RecordsHeld).
	held atomic.Int64
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
	// RecordsHeld is how many records are parked in the repair stage's hold buffer
	// right now, waiting to see whether a copy on a VLAN child beats them (#357). It
	// is the fourth term of the accounting identity:
	//
	//	RecordsIn = RecordsEmitted + RecordsDropped + RecordsNoAddr + RecordsHeld
	//
	// Without it a held record reads as a lost one, which is the exact failure this
	// pipeline's counters exist to make impossible.
	RecordsHeld int64
}

// NewProcessor builds the NetFlow pipeline. sink and rep must be non-nil; cache may
// be nil, in which case records ship unenriched rather than not at all.
func NewProcessor(sink Sink, rep *Repairer, cache *enrich.Cache) *Processor {
	return &Processor{sink: sink, rep: rep, cache: cache}
}

// SetIfMap publishes a new ifIndex map. Safe to call while records are in flight.
//
// It adopts the map into the processor's OWN unmapped-lookup counter before
// publishing it. That is not bookkeeping: main rebuilds the map on a ticker, and
// a counter living on the map instance went back to zero on every rebuild, so
// the one alarm for "the enumeration moved" could never accumulate far enough to
// be visible (#361). Attaching before the atomic store is what makes the
// happens-before hold for concurrent readers.
func (p *Processor) SetIfMap(m *IfMap) {
	m.AttachCounters(&p.ifmapCounters)
	p.ifmap.Store(m)
}

// SetDNSCache installs the DNS answer cache the enrich stage reads for dst.domain.
// Late-bound like SetIfMap: the cache is built in main alongside the Zenarmor lane
// that feeds it, after the processor is constructed. Safe to call before records
// flow; not intended to be called concurrently with ObserveDatagram.
func (p *Processor) SetDNSCache(c *DNSCache) { p.dnsCache = c }

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
		// The count is OUTSIDE the nil check on purpose. It used to sit inside, which
		// meant the one window where nothing can be labelled — before the first map
		// is published — was also the window where nothing was counted. A restart on
		// a busy WAN put gigabytes into the empty-label bucket with every health
		// metric reading zero, which is indistinguishable from a quiet network (#365).
		//
		// A record still EMITS with an empty label rather than being dropped. Dropping
		// loses data and an empty label is honest; it was the silence that was wrong.
		if m != nil {
			rec.In = m.Iface(nr.InIfIndex)
			rec.Out = m.Iface(nr.OutIfIndex)
		}
		if rec.In.Device == "" && rec.Out.Device == "" {
			p.noIfaceMap.Add(1)
		}

		// Repair mutates in place and reports what to do with the record. A drop is a
		// VLAN/parent duplicate: the same packets already counted on the child
		// interface, which is ~4% of bytes on the reference capture. A hold means the
		// repair stage has parked the record because a copy on a VLAN child could still
		// arrive and beat it (#357); it comes back from the release path below.
		if p.rep != nil {
			switch p.rep.Repair(&rec, m, snap, now) {
			case RepairDrop:
				p.dropped.Add(1)
				continue
			case RepairHold:
				p.held.Add(1)
				continue
			}
		}
		p.emit(rec, snap, now)
	}

	// Draining here is what lets a busy lane need no timer at all: every datagram
	// arrival releases whatever the previous ones were holding.
	p.releaseDue(now)
}

// ReleaseDue emits every held record whose window has elapsed. It exists for the
// ticker that covers a lane which has gone quiet — ObserveDatagram already drains on
// every datagram, so on a busy lane this finds nothing to do.
func (p *Processor) ReleaseDue(now time.Time) { p.releaseDue(now) }

// Flush emits every held record regardless of its window, for a clean shutdown. A
// record parked in a buffer at exit is a record the process was told about and never
// reported.
func (p *Processor) Flush(now time.Time) {
	if p.rep == nil {
		return
	}
	p.emitReleased(p.rep.Flush(), now)
}

func (p *Processor) releaseDue(now time.Time) {
	if p.rep == nil {
		return
	}
	p.emitReleased(p.rep.Release(now), now)
}

// emitReleased ships records that came back from the hold buffer. They arrive already
// repaired, so only enrichment is left — and it uses the CURRENT snapshot rather than
// the one stored with the record, exactly as the immediate path does: the repairs
// needed the view the record arrived under, while a name or a hostname is better for
// being fresher.
func (p *Processor) emitReleased(recs []Record, now time.Time) {
	if len(recs) == 0 {
		return
	}
	var snap *enrich.Snapshot
	if p.cache != nil {
		snap = p.cache.Load()
	}
	for _, rec := range recs {
		p.held.Add(-1)
		p.emit(rec, snap, now)
	}
}

func (p *Processor) emit(rec Record, snap *enrich.Snapshot, now time.Time) {
	enrichRecord(&rec, snap, p.dnsCache, now)
	p.emitted.Add(1)
	if p.sink != nil {
		p.sink.Observe(rec)
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
		RecordsHeld:     p.held.Load(),
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
		// The decoder has read element 6 since phase 2; this is where it stops being
		// netflow-package-local (#585). Copied raw, with no protocol gate: the field's
		// meaning is "what the exporter put in element 6", and ng_netflow already zeroes
		// it for non-TCP, so a gate would only ever hide a non-zero value on a record
		// whose protocol we read wrong — which is exactly the case worth seeing.
		TCPFlags:  nr.TCPFlags,
		Fragments: 1,
	}
	if r.End.IsZero() {
		r.End = r.Start
	}
	r.CommunityID = CommunityID(r.CanonicalTuple(), 0)
	return r, true
}

// enrichRecord resolves everything the enrichment snapshot knows, plus the DNS
// answer cache's dst.domain. It is applied identically to both lanes, so the same
// flow described by both sources lands on the same labels. cache and now drive the
// domain lookup only; a nil cache or snapshot each degrade independently to "no such
// enrichment" rather than skipping the rest.
func enrichRecord(r *Record, snap *enrich.Snapshot, cache *DNSCache, now time.Time) {
	// The DNS lookup is independent of the snapshot: it needs neither interface table
	// nor local-net topology, only the client/answer pair, so it runs even on a cold
	// snapshot where every scope lookup would miss.
	if cache != nil && r.Enrich.DstDomain == "" {
		if dom, ok := cache.Lookup(r.SrcAddr, r.DstAddr, now); ok {
			r.Enrich.DstDomain = dom
		}
	}
	if snap == nil {
		// Geo is independent of the snapshot too: it needs only the addresses. A cold
		// snapshot costs the country METRIC label (MetricCountry has no scope to read)
		// but never the log attributes, which is the right trade — a flow log with no
		// country would be exactly the asymmetry #520 exists to close.
		applyGeo(r)
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
	applyGeo(r)
}

// applyGeo runs the process-wide GeoIP enrichment (#520). It is called at the END of
// each lane's enrichment, and the ordering is load-bearing: the metric-label rule
// reads Enrich.SrcScope/DstScope to decide which end is the remote one, so a record
// enriched before its scopes are resolved would land on an empty country label.
//
// A nil enricher (--geoip.enabled off, or main never wired one) is a no-op.
func applyGeo(r *Record) { GeoEnrichment.Enrich(r) }

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
// InterfaceLabel exposes interfaceLabel to other packages: the Zenarmor lane stamps
// the same normalized interface onto its conn record in place (#353 §10), so the
// conn document and a NetFlow record agree on the label for one flow.
func (r Record) InterfaceLabel() string { return interfaceLabel(r) }

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
