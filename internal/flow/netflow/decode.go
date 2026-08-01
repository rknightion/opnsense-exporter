package netflow

import (
	"container/list"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"
)

const (
	v9HeaderLen = 20
	v5HeaderLen = 24
	v5RecordLen = 48

	// flowsetTemplate and flowsetOptionsTemplate are the two control flowset ids
	// this decoder recognises. firstDataFlowsetID is the lowest id a DATA flowset
	// may carry — RFC 3954 reserves 0-255 for flowset types — so anything below it
	// is a control flowset, known or not, and is stepped over by its length.
	flowsetTemplate        = 0
	flowsetOptionsTemplate = 1
	firstDataFlowsetID     = 256

	// varLenSentinel is IPFIX's variable-length element marker. See
	// learnTemplates for why it is rejected rather than supported.
	varLenSentinel = 0xffff

	// maxIntWidth is the widest element the integer reader can represent. A
	// numeric element wider than this is skipped rather than truncated: a
	// truncated counter is a fabricated value, and no NetFlow v9 element this
	// decoder consumes is ever declared wider than 8 bytes.
	maxIntWidth = 8

	// maxCachedTemplates bounds the v9 template cache (#564). NetFlow has no
	// authentication, so the (exporter, source_id, template_id) key is entirely
	// attacker-selected by anyone who can reach the listener: a validated attack
	// inserted 20,000 distinct templates from one exporter by varying source ids
	// alone, and the pre-#564 cache had no ceiling at all.
	//
	// A real deployment's true template count is tiny — one firewall's ng_netflow
	// exports a handful of shapes (IPv4, IPv6, occasionally IPv6-with-VLAN) per
	// (exporter, source_id) pair, so even dozens of firewalls each running a
	// few ng_netflow instances stays two orders of magnitude below this. This is
	// a fixed internal budget, not an operator knob: it costs at most a few
	// hundred KB of heap (~150 bytes/template) at the ceiling, which is cheap
	// enough to not need tuning, and a CLI flag here would be attacker-facing
	// surface for no real benefit.
	maxCachedTemplates = 4096
)

// Decoder decodes NetFlow v5 and v9 datagrams and owns the v9 template cache.
//
// It is safe for concurrent use, which is not optional: the listener runs a pool
// of UDP workers and the template cache is shared mutable state that a data
// flowset reads on every record. One mutex covers the whole decode rather than
// only the cache — the alternative, a read lock plus an upgrade on the learn
// path, buys nothing measurable against a decode that is a few microseconds of
// pure byte-walking, and buys a whole class of races.
//
// The cache is in memory only and deliberately not persisted: ng_netflow
// re-sends every template roughly every 2 minutes (#346), so a cold start
// recovers on its own within that window. Stats.NoTemplate is what makes the
// window observable.
//
// The cache is bounded at maxCachedTemplates (#564) via order, an
// least-recently-used list shared across every key regardless of which
// exporter, source id or template id it belongs to. "Used" means either
// learned/refreshed (store) or looked up for a data flowset (lookup) — an
// observation domain that is actively sending data stays warm even if it
// never resends its template within the window, and one that has gone quiet
// is the first evicted when a genuinely new key needs room.
type Decoder struct {
	mu        sync.Mutex
	templates map[templateKey]*template
	order     *list.List // list.Element.Value is a templateKey; front = most recently used
	stats     Stats
}

// New returns a Decoder with an empty template cache.
func New() *Decoder {
	return &Decoder{templates: make(map[templateKey]*template), order: list.New()}
}

// Stats returns a snapshot of the decoder's counters by value.
func (d *Decoder) Stats() Stats {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stats
}

// Decode parses one datagram received from exporter at now.
//
// exporter is part of the template cache key, so it must be the real source
// address of the datagram, never a resolved or rewritten one.
//
// now is the receive instant and is used only when the sender's own clock is
// unset — see exportTimeOf. It is deliberately not stored on the Datagram: every
// timestamp the pipeline consumes is on the FIREWALL's clock, and mixing the two
// would make flow durations depend on network delay.
//
// A returned error means the datagram produced nothing: the decoder never
// returns partial records alongside an error, because a structural violation
// invalidates every offset behind it. Templates learned before the violation are
// kept — they parsed cleanly and are independently valid.
//
// The returned Datagram retains NO reference into payload — Record holds only
// scalars and netip.Addrs, both of which copy — so the caller is free to reuse
// its read buffer as soon as Decode returns.
func (d *Decoder) Decode(payload []byte, exporter netip.Addr, now time.Time) (*Datagram, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) < 2 {
		d.stats.Malformed++
		return nil, ErrShortPacket
	}
	switch Version(binary.BigEndian.Uint16(payload)) {
	case V9:
		return d.decodeV9(payload, exporter, now)
	case V5:
		return d.decodeV5(payload, now)
	default:
		d.stats.UnsupportedVersion++
		return nil, ErrUnsupportedVersion
	}
}

// decodeV9 walks a v9 datagram's flowsets. Callers hold d.mu.
func (d *Decoder) decodeV9(payload []byte, exporter netip.Addr, now time.Time) (*Datagram, error) {
	if len(payload) < v9HeaderLen {
		d.stats.Malformed++
		return nil, ErrShortPacket
	}
	sysUpTime := binary.BigEndian.Uint32(payload[4:])
	dg := &Datagram{
		Version:    V9,
		Sequence:   binary.BigEndian.Uint32(payload[12:]),
		SourceID:   binary.BigEndian.Uint32(payload[16:]),
		ExportTime: exportTimeOf(binary.BigEndian.Uint32(payload[8:]), 0, now),
	}

	// The header's count field is ADVISORY here and is never read: it counts
	// template definitions and data records together, senders are known to get it
	// wrong, and letting it steer iteration would hand a misbehaving sender
	// control of how far we walk. Flowset lengths are the only structure trusted.
	body := payload[v9HeaderLen:]
	for len(body) >= 4 {
		id := binary.BigEndian.Uint16(body)
		length := int(binary.BigEndian.Uint16(body[2:]))
		// The length counts its own 4-byte header. Below that it cannot advance the
		// cursor (an infinite loop); beyond the remaining bytes the flowset is
		// truncated and the rest of the datagram is unreadable either way.
		if length < 4 || length > len(body) {
			d.stats.Malformed++
			return nil, ErrMalformed
		}
		set := body[4:length]
		body = body[length:]

		switch {
		case id == flowsetTemplate:
			unknown, err := d.learnTemplates(set, exporter, dg.SourceID)
			if err != nil {
				if errors.Is(err, ErrVariableLength) {
					d.stats.VarLenRejected++
				} else {
					d.stats.Malformed++
				}
				return nil, err
			}
			for _, u := range unknown {
				dg.note(u)
			}
		case id == flowsetOptionsTemplate:
			// Stepped over by length and never interpreted. This export carries no
			// scoped data the pipeline consumes, and a half-understood options
			// template would desynchronise every flowset behind it. Stepping over is
			// still right; doing it SILENTLY was the defect (#360).
			d.stats.OptionsTemplates++
			dg.note(Unidentified{Kind: UnidentifiedOptions, Detail: id})
		case id < firstDataFlowsetID:
			// The rest of the reserved 2-255 range: unknown control flowsets, also
			// stepped over by length rather than taking the datagram down.
			d.stats.UnknownFlowsets++
			dg.note(Unidentified{Kind: UnidentifiedFlowset, Detail: id})
		default:
			d.readDataFlowset(dg, set, exporter, id, sysUpTime)
		}
	}
	// 0-3 bytes may remain: flowsets are padded to a 4-byte boundary, and a tail
	// shorter than a flowset header is that padding, not a truncated flowset.

	d.stats.Datagrams++
	d.stats.Records += uint64(len(dg.Records))
	return dg, nil
}

// readDataFlowset decodes every record in one data flowset. Callers hold d.mu.
func (d *Decoder) readDataFlowset(dg *Datagram, set []byte, exporter netip.Addr, id uint16, sysUpTime uint32) {
	t, ok := d.lookup(exporter, dg.SourceID, id)
	if !ok {
		// Expected for up to ~2 minutes from a cold start, and after a sender
		// restart. The whole flowset is dropped because there is no honest way to
		// read it: without the template, field widths are unknown and any guess
		// silently produces plausible-looking wrong records. Counted, never an
		// error.
		d.stats.NoTemplate++
		return
	}
	if t.recLen <= 0 {
		// Unreachable: learnTemplates rejects zero-field templates and zero-width
		// elements, and it is the cache's only writer. Kept because the loop below
		// is on an UNAUTHENTICATED, attacker-reachable path — NetFlow has no auth —
		// and a zero-width record there is not a wrong answer, it is a wedged worker
		// goroutine and eventually a wedged pool.
		d.stats.Malformed++
		return
	}
	for len(set) >= t.recLen {
		rec := d.readRecord(set[:t.recLen], t, dg.ExportTime, sysUpTime)
		rec.TemplateID = id
		dg.Records = append(dg.Records, rec)
		set = set[t.recLen:]
	}
	// What remains is shorter than one record: the flowset's alignment padding.
	// The box's IPv4 template is 57 bytes wide, so this is the common case, not a
	// corner one.
}

// readRecord decodes one fixed-width record against its template. buf is exactly
// t.recLen bytes. Callers hold d.mu (only for the stats increment).
func (d *Decoder) readRecord(buf []byte, t *template, exportTime time.Time, sysUpTime uint32) Record {
	var (
		rec                              Record
		first, last                      uint32
		haveFirst, haveLast              bool
		outUnexpected                    bool
		srcASUnexpected, dstASUnexpected bool
	)

	off := 0
	for _, f := range t.fields {
		v := buf[off : off+int(f.length)]
		off += int(f.length)

		switch f.typ {
		case FieldInBytes:
			rec.Bytes = num(v)
		case FieldInPkts:
			rec.Packets = num(v)
		case FieldProtocol:
			rec.Proto = uint8(num(v))
		case FieldTCPFlags:
			rec.TCPFlags = uint8(num(v))
		case FieldL4SrcPort:
			rec.SrcPort = uint16(num(v))
		case FieldL4DstPort:
			rec.DstPort = uint16(num(v))
		case FieldIPv4SrcAddr, FieldIPv6SrcAddr:
			if a, ok := addrOf(v); ok {
				rec.SrcAddr = a
			}
		case FieldIPv4DstAddr, FieldIPv6DstAddr:
			if a, ok := addrOf(v); ok {
				rec.DstAddr = a
			}
		case FieldInputSNMP:
			rec.InIfIndex = uint32(num(v))
		case FieldOutputSNMP:
			rec.OutIfIndex = uint32(num(v))
		case FieldSrcAS, FieldDstAS:
			// Read to assert, never to store (#586). ng_netflow hardcodes both to
			// zero on every export path it has under an explicit "not supported"
			// comment, confirmed zero across all 131 records of the reference
			// capture; a better ASN already ships via flow.Record.Geo (#549,
			// DB-IP-derived). Kept in modelledFields and read here, exactly like
			// FieldOutBytes/FieldOutPkts below, so a non-zero value still surfaces
			// as a counter rather than silently vanishing now that Record has
			// nowhere to put it.
			if num(v) != 0 {
				if f.typ == FieldSrcAS {
					srcASUnexpected = true
				} else {
					dstASUnexpected = true
				}
			}
		case FieldFirstSwitched:
			first, haveFirst = uint32(num(v)), true
		case FieldLastSwitched:
			last, haveLast = uint32(num(v)), true
		case FieldOutBytes, FieldOutPkts:
			// Read to assert, never to use. #346 verified these are zero across
			// 84,513 records; adding them to the volume as a fallback would silently
			// DOUBLE a real counter the day OPNsense starts populating them, and
			// nothing downstream could tell. A non-zero rate on this counter is the
			// signal that this decision needs revisiting.
			if num(v) != 0 {
				outUnexpected = true
			}
		case FieldSrcTOS:
			// Split at decode, not at export: the raw byte is unreadable as either
			// half, and every consumer would otherwise repeat the same shift.
			b := uint8(num(v))
			rec.DSCP, rec.ECN = b>>2, b&0x03
		case FieldSrcMask:
			rec.SrcMask = uint8(num(v))
		case FieldDstMask:
			rec.DstMask = uint8(num(v))
		case FieldIPv4NextHop, FieldIPv6NextHop:
			// An all-zero next-hop means "directly connected". addrOf yields a valid
			// zero Addr for it, so it is filtered here to keep Record.NextHop's
			// invalid-means-none contract — a consumer must not have to know that
			// 0.0.0.0 and :: are sentinels.
			if a, ok := addrOf(v); ok && !a.IsUnspecified() {
				rec.NextHop = a
			}
		case FieldSrcVLAN, FieldDstVLAN:
			// Record carries one VLAN id. Source wins: on this export the two are
			// equal for intra-VLAN traffic and only the ingress tag is meaningful for
			// attribution.
			if f.typ == FieldSrcVLAN || rec.VLANID == 0 {
				rec.VLANID = uint16(num(v))
			}
		default:
			// Every other element — including DIRECTION, which Record has nowhere to
			// put — is stepped over by its TEMPLATE-DECLARED length. Never by an
			// assumed width: one wrong width shifts every following field and
			// corrupts the record without any parse error to show for it.
		}
	}

	if outUnexpected {
		// The unit is the RECORD: a record with both OUT_BYTES and OUT_PKTS
		// non-zero is one unexpected record, not two.
		d.stats.UnexpectedOutBytes++
	}
	if srcASUnexpected {
		d.stats.UnexpectedSrcAS++
	}
	if dstASUnexpected {
		d.stats.UnexpectedDstAS++
	}
	if haveFirst {
		rec.First = switchedAt(exportTime, sysUpTime, first)
	}
	if haveLast {
		rec.Last = switchedAt(exportTime, sysUpTime, last)
	}
	// A template that omits the switched elements leaves both times ZERO. Not the
	// export instant: "the sender told us nothing" and "the flow ended exactly at
	// export" are different facts, and only the caller can decide what to do with
	// the first.
	return rec
}

// decodeV5 parses a v5 datagram. Callers hold d.mu.
//
// v5 is implemented because the receiver flag admits it, but the production box
// exports v9 only (#346). It is a fixed-layout format with no templates, so
// there is nothing to cache and nothing to desynchronise.
func (d *Decoder) decodeV5(payload []byte, now time.Time) (*Datagram, error) {
	if len(payload) < v5HeaderLen {
		d.stats.Malformed++
		return nil, ErrShortPacket
	}
	count := int(binary.BigEndian.Uint16(payload[2:]))
	sysUpTime := binary.BigEndian.Uint32(payload[4:])
	dg := &Datagram{
		Version:  V5,
		Sequence: binary.BigEndian.Uint32(payload[16:]),
		// SourceID stays 0: v5's engine_type/engine_id are a different concept and
		// folding them into a v9 field would invent an observation domain.
		ExportTime: exportTimeOf(
			binary.BigEndian.Uint32(payload[8:]),
			binary.BigEndian.Uint32(payload[12:]),
			now,
		),
	}

	body := payload[v5HeaderLen:]
	if count*v5RecordLen > len(body) {
		// v5 carries no per-flowset length, so the header count is the ONLY
		// structure available. A count that overruns the datagram cannot be
		// salvaged the way a bad v9 flowset length can be stepped over.
		d.stats.Malformed++
		return nil, ErrMalformed
	}

	dg.Records = make([]Record, 0, count)
	for i := 0; i < count; i++ {
		r := body[i*v5RecordLen : (i+1)*v5RecordLen]
		rec := Record{
			InIfIndex:  uint32(binary.BigEndian.Uint16(r[12:])),
			OutIfIndex: uint32(binary.BigEndian.Uint16(r[14:])),
			Packets:    uint64(binary.BigEndian.Uint32(r[16:])),
			Bytes:      uint64(binary.BigEndian.Uint32(r[20:])),
			SrcPort:    binary.BigEndian.Uint16(r[32:]),
			DstPort:    binary.BigEndian.Uint16(r[34:]),
			TCPFlags:   r[37],
			Proto:      r[38],
			// bytes 40-44 (SRC_AS/DST_AS) are deliberately NOT read: ng_netflow
			// hardcodes both to zero on the v5 export path too (#586, same source
			// comment as the v9 case), and a better ASN already ships via
			// flow.Record.Geo (#549). v5 is fixed-format with no template to assert
			// a width against, so — unlike the v9 case above — there is nothing
			// useful to count here either; this is pure dead-byte skip.
			First: switchedAt(dg.ExportTime, sysUpTime, binary.BigEndian.Uint32(r[24:])),
			Last:  switchedAt(dg.ExportTime, sysUpTime, binary.BigEndian.Uint32(r[28:])),
			// TemplateID stays 0: v5 has no templates, and 0 is not a valid v9
			// template id, so the two can never be confused.
		}
		if a, ok := addrOf(r[0:4]); ok {
			rec.SrcAddr = a
		}
		if a, ok := addrOf(r[4:8]); ok {
			rec.DstAddr = a
		}
		dg.Records = append(dg.Records, rec)
	}

	d.stats.Datagrams++
	d.stats.Records += uint64(len(dg.Records))
	return dg, nil
}

// num reads a big-endian unsigned integer of any width the template may declare,
// left-padding narrower values.
//
// The width comes from the template and nowhere else. This export declares
// SRC_AS/DST_AS as 4 bytes where 2 is the usual value (#346), so a decoder with
// a hardcoded width per element type reads a 32-bit ASN as its top half.
// Anything wider than maxIntWidth yields 0 — see the constant.
func num(b []byte) uint64 {
	if len(b) > maxIntWidth {
		return 0
	}
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

// addrOf decodes a 4- or 16-byte address element. Any other width is not an
// address and is reported as absent rather than padded into one.
//
// Unmap is MANDATORY. ::ffff:a.b.c.d and a.b.c.d are the same host but different
// netip.Addrs, and every downstream join compares Addrs — flow.CanonicalTuple
// Unmaps for exactly this reason (record.go:223-228), as does
// enrich.Snapshot.Scope. Without it a v4-mapped record silently misses every
// lookup and correlation it should have hit.
func addrOf(b []byte) (netip.Addr, bool) {
	a, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// switchedAt converts a sysUpTime-relative millisecond timestamp to an absolute
// instant on the exporter's clock.
//
// FIRST_SWITCHED/LAST_SWITCHED are milliseconds since the device booted, and the
// header carries both the current uptime and the wall-clock export time, so the
// flow instant is exportTime - (sysUpTime - switched).
func switchedAt(exportTime time.Time, sysUpTime, switched uint32) time.Time {
	if switched >= sysUpTime {
		// sysUpTime is a 32-bit millisecond counter: it wraps every ~49.7 days, and
		// a reboot between the flow and the export resets it. Either way the
		// subtraction would place the flow in the FUTURE, which downstream reads as
		// a clock-skew fault or drops outright. Clamping to the export instant is
		// wrong by at most one export interval and is always ordered correctly.
		return exportTime
	}
	return exportTime.Add(-time.Duration(sysUpTime-switched) * time.Millisecond)
}

// exportTimeOf resolves the header's wall clock, falling back to the receive
// instant when the sender has none.
//
// A firewall exporting before NTP settles sends unix_secs=0. Every record's
// absolute time is derived from this value, so trusting it would date the whole
// datagram to 1970 and silently poison every rollup and every Loki line built
// from it. The receive instant is wrong by the network delay — microseconds on
// the LAN this listens on — which is the far smaller error.
func exportTimeOf(secs, nsecs uint32, now time.Time) time.Time {
	if secs == 0 {
		return now
	}
	return time.Unix(int64(secs), int64(nsecs)).UTC()
}
