package flow

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// This file is the repair stage: the three normalisations that only this exporter
// can make, because only this exporter holds the OPNsense API alongside the flow
// export. Every one of them was measured against a live capture of 811,234 records
// (#346), and the numbers quoted below are from that capture rather than from
// reasoning about what ng_netflow ought to do.
//
//  1. VLAN/parent de-duplication. ng_netflow captures on a trunk AND on its VLAN
//     children, so every tagged packet is exported twice — 9,657 of 80,275 flow
//     instances, about 4% of bytes — and the parent copy additionally attributes
//     VLAN traffic to the parent's interface name.
//  2. Egress correction. OUTPUT_SNMP comes from a FIB route lookup, but OPNsense's
//     multi-WAN policy routing happens in pf, which ng_netflow never sees. It
//     mislabelled 3.36 GB of WAN2 traffic as WAN1 in a single window, leaving WAN2
//     reading 37.8 MB against ~3.4 GB actual: a 99% under-report.
//  3. Direction inference. Field 61 (DIRECTION) is not exported by this box at all,
//     so direction is deduced — by the same rules the Zenarmor lane already uses,
//     because both lanes feed one metric family and a dashboard splits on the label.

// dedupeTTL bounds how long an instance stays in the de-dup table.
//
// The two copies of one instance are produced by the SAME expiry sweep on the same
// box and differ only in which netgraph hook exported them, so they are separated by
// datagram scheduling, not by a flow timer — sub-second in the capture. Two minutes
// is three orders of magnitude of headroom for reordering and retransmission while
// still bounding the table in time as well as in size. It is deliberately not a
// flag: a knob here trades memory for a duplicate window nobody can measure, and the
// bound that actually matters (maxDedupeEntries) is already exposed.
const dedupeTTL = 2 * time.Minute

// RepairStats is the repair stage's own accounting. Every field is published as a
// self-metric: a repair nobody can observe is a repair nobody will trust, which is
// the same reasoning that put Corrected on Iface (record.go:112-124).
//
// All five are scalar counters. Nothing address-, port- or flow-identifying may ever
// be attached to them.
type RepairStats struct {
	// VLANDuplicatesDropped counts records suppressed as the second copy of an
	// instance ng_netflow exported twice.
	VLANDuplicatesDropped uint64
	// EgressCorrected counts records whose egress interface was replaced by the WAN
	// deduced from their source address.
	EgressCorrected uint64

	// DedupeEntries is the live size of the instance table.
	DedupeEntries int
	// DedupeEvicted counts entries removed because they aged past dedupeTTL. This is
	// healthy housekeeping — an instance that old cannot still have a duplicate in
	// flight.
	DedupeEvicted uint64
	// DedupeCapped counts entries forced out EARLY because the table was at
	// maxDedupeEntries. This is not housekeeping: a capped instance can no longer be
	// deduped, so a non-zero rate here means duplicates are reaching the rollup and
	// the bound wants raising. Kept apart from DedupeEvicted precisely because the two
	// call for opposite operator responses.
	DedupeCapped uint64
}

// ifTopology is the part of *IfMap the repair stage resolves against.
//
// It is deliberately narrower than IfMap's method set — Iface(idx) is the
// processor's business, not this file's — so the tests can drive the real decision
// logic against a hand-built topology without encoding an assumption about how the
// map is constructed.
type ifTopology interface {
	// WANFor reports the WAN interface holding addr, if any.
	WANFor(addr netip.Addr) (Iface, bool)
	// ParentOf maps a VLAN child device to its parent device.
	ParentOf(device string) (string, bool)
}

// wanKnower answers the one topology question rule 3 needs and WANFor cannot: is
// THIS interface a WAN, irrespective of any address on the record.
//
// It is an OPTIONAL assertion because the frozen IfMap contract does not include it.
// When the map does not implement it, ifaceIsWAN falls back to address evidence,
// which covers every NAT'd flow — but not, for example, an un-NAT'd IPv6 flow whose
// scope also failed to resolve. Exposing IsWAN on IfMap is nearly free (it is built
// from enrich.IfaceInfo, which already carries IsWAN) and would close that gap.
type wanKnower interface {
	IsWAN(device string) bool
}

// instanceKey identifies ONE export of one conversation: the canonical 5-tuple plus
// the flow's own First/Last timestamps.
//
// The timestamps are not optional. A long-lived conversation is exported repeatedly
// with an identical tuple, so keying on the tuple alone would discard every export
// after the first and collapse a busy flow to a single record. Tuple is comparable
// (netip.Addr is), so this is a map key with no allocation and no string formatting.
type instanceKey struct {
	tuple Tuple
	first int64 // UnixNano of Record.Start
	last  int64 // UnixNano of Record.End
}

// dedupeEntry remembers which interface an instance was ADMITTED on, so a later copy
// on a related interface can be recognised as the duplicate it is.
type dedupeEntry struct {
	device string
	seen   time.Time
}

// Repairer applies the three repairs. One instance is shared by the whole UDP worker
// pool, so every field is guarded by mu.
//
// One mutex covers the table and all five counters rather than splitting the
// counters into atomics: the critical sections are a map lookup and an append, the
// same shape as Rollup.Observe on an equally hot path, and a single lock keeps
// Stats() internally consistent instead of reporting a table size from one instant
// and a drop count from another.
type Repairer struct {
	mu   sync.Mutex
	seen map[instanceKey]dedupeEntry
	// order is the insertion-ordered key list backing both expiry and capacity
	// eviction. Entries are never refreshed once inserted, so insertion order IS age
	// order and the oldest entry is always at head — an O(1) answer to both "what has
	// expired" and "what goes to make room".
	order []instanceKey
	head  int

	maxEntries int

	vlanDropped     uint64
	egressCorrected uint64
	evicted         uint64
	capped          uint64
}

// NewRepairer returns a Repairer whose de-dup table holds at most maxDedupeEntries
// instances. Zero means unbounded, matching NewRollup's convention for its own caps.
//
// The table is fed by an unauthenticated UDP listener — NetFlow has no auth — so on
// any exposed deployment this bound is the memory guard, not a tuning knob.
func NewRepairer(maxDedupeEntries int) *Repairer {
	return &Repairer{
		seen:       make(map[instanceKey]dedupeEntry),
		maxEntries: maxDedupeEntries,
	}
}

// Repair mutates rec in place and reports whether the caller should KEEP it.
//
// A false return means the record is a VLAN/parent duplicate and must be dropped
// before it is enriched, counted or correlated.
//
// m may be nil (the state before the first interface refresh) and snap may be nil (a
// lane running with enrichment off). Neither panics, and neither causes a drop:
// without topology nothing can be PROVEN a duplicate, and dropping on suspicion
// would lose real traffic.
func (r *Repairer) Repair(rec *Record, m *IfMap, snap *enrich.Snapshot, now time.Time) bool {
	if m == nil {
		// Boxing a nil *IfMap yields a NON-nil interface, so the nil test has to happen
		// here rather than inside. (IfMap's own methods are nil-receiver safe, but
		// relying on that would make this file's correctness depend on another lane's.)
		return r.repairWith(rec, nil, snap, now)
	}
	return r.repairWith(rec, m, snap, now)
}

// repairWith is the real entry point, resolving against the narrow seam so the
// decision logic is testable without a constructed IfMap.
//
// The stage order is load-bearing and is asserted by a test: de-dup FIRST, so a
// record that is about to be discarded is never corrected, counted or given a
// direction; then the egress correction; then direction, which READS the corrected
// egress — a policy-routed flow is only recognisable as outbound after repair 2 has
// named the WAN it actually left by.
func (r *Repairer) repairWith(rec *Record, m ifTopology, snap *enrich.Snapshot, now time.Time) bool {
	if rec == nil {
		return false
	}
	if !r.admit(rec, m, now) {
		return false
	}
	r.correctEgress(rec, m)
	r.setDirection(rec, m, snap)
	return true
}

// Stats reports the repair stage's own accounting.
func (r *Repairer) Stats() RepairStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return RepairStats{
		VLANDuplicatesDropped: r.vlanDropped,
		EgressCorrected:       r.egressCorrected,
		DedupeEntries:         len(r.seen),
		DedupeEvicted:         r.evicted,
		DedupeCapped:          r.capped,
	}
}

// admit is repair 1. It reports whether this copy of the instance is the one to keep.
//
// THE ARRIVAL-ORDER PROBLEM. The two copies of a duplicated instance arrive in
// DIFFERENT datagrams and nothing says which lands first. Repair answers keep/drop
// synchronously, so a copy that has been kept cannot later be un-emitted; buffering
// to wait for a possible partner would mean holding EVERY record for a window, on
// the receiver goroutine, for the ~88% of instances that have no duplicate at all.
// So the winner has to be decided from the copy in hand, by topology, not by which
// datagram the network happened to deliver first. Two mechanisms, in order:
//
// A. THE TAG. On the trunk the frame is still 802.1Q-tagged — that is what a trunk
// is — while on the child interface the tag has been stripped. So a record that
// names a VLAN tag while sitting on the tag's PARENT device is, by construction, the
// parent copy, and the child copy is guaranteed to exist because ng_netflow captured
// both. It is dropped on sight, whenever it arrives, which is what makes the outcome
// identical in both orders. The check is confirmed against the interface table
// (ParentOf on the synthesised child name) rather than by string shape alone, so a
// tag naming an interface the firewall does not have never costs us a record.
//
// B. THE INSTANCE TABLE. When the export carries no usable tag, the copies are
// distinguishable only by having been seen before, so the table suppresses the
// second one and the pair is resolved by topology: the two devices are a duplicate
// pair only if one is the VLAN child of the other. Records that merely share an
// instance key on unrelated interfaces are KEPT — never drop what cannot be proven
// duplicate.
//
// The residual, stated plainly: B cannot un-emit, so if the untagged parent copy
// lands first it is the one that survives. The byte total is still right (the
// double-count is gone) but the interface attribution is not. A is what fixes that,
// and A needs Record.VLANID populated from the decoded SRC_VLAN/DST_VLAN field.
func (r *Repairer) admit(rec *Record, m ifTopology, now time.Time) bool {
	parentCopy := isVLANParentCopy(rec, m)
	key := instanceKey{
		tuple: rec.CanonicalTuple(),
		first: rec.Start.UnixNano(),
		last:  rec.End.UnixNano(),
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.expire(now)

	if parentCopy {
		r.vlanDropped++
		return false
	}
	if prev, ok := r.seen[key]; ok {
		if isVLANPair(prev.device, rec.In.Device, m) {
			r.vlanDropped++
			return false
		}
		// Same instance, unrelated interfaces: not proven a duplicate. Keep it, and
		// leave the admitted device alone — the first copy stays the reference.
		return true
	}
	r.insert(key, rec.In.Device, now)
	return true
}

// isVLANParentCopy implements mechanism A above.
func isVLANParentCopy(rec *Record, m ifTopology) bool {
	if m == nil {
		return false
	}
	tag := rec.VLANID
	dev := rec.In.Device
	if tag == "" || tag == "0" || dev == "" {
		return false
	}
	suffix := vlanInfix + tag
	if strings.HasSuffix(dev, suffix) {
		// Already the child: this is the copy we want to keep.
		return false
	}
	// OPNsense names a VLAN interface <parent>_vlan<tag>, which is what the interface
	// table and the ifIndex map are both keyed by (the Zenarmor adapter synthesises
	// the same name for the same reason, flowadapt.go:111-125). ParentOf answers only
	// for devices the interface list actually contained, so a tag naming a VLAN this
	// firewall does not have can never cost us a record.
	parent, ok := m.ParentOf(dev + suffix)
	return ok && parent == dev
}

// isVLANPair reports whether two devices are a trunk and one of its VLAN children,
// in either order. This is the topology test that decides the winner in mechanism B.
func isVLANPair(a, b string, m ifTopology) bool {
	if m == nil || a == "" || b == "" || a == b {
		return false
	}
	if p, ok := m.ParentOf(a); ok && p == b {
		return true
	}
	p, ok := m.ParentOf(b)
	return ok && p == a
}

// expire drops every entry older than dedupeTTL. Callers hold mu.
//
// order is in insertion order and entries are never refreshed, so ages are monotone
// along it and the scan stops at the first live entry.
func (r *Repairer) expire(now time.Time) {
	cutoff := now.Add(-dedupeTTL)
	for r.head < len(r.order) {
		k := r.order[r.head]
		e, ok := r.seen[k]
		if ok && e.seen.After(cutoff) {
			break
		}
		if ok {
			delete(r.seen, k)
			r.evicted++
		}
		r.head++
	}
	r.compact()
}

// insert records an admitted instance, making room first if the table is full.
// Callers hold mu.
//
// At capacity the OLDEST entry goes rather than the insert being refused: the oldest
// instance is the one least likely to still have a duplicate in flight, whereas
// refusing the insert would blind the table to the newest traffic, which is exactly
// where duplicates are still arriving. The pressure is counted as DedupeCapped
// rather than DedupeEvicted, because a capped instance can no longer be deduped and
// that is an operator problem, not housekeeping.
func (r *Repairer) insert(k instanceKey, device string, now time.Time) {
	if r.maxEntries > 0 && len(r.seen) >= r.maxEntries {
		r.dropOldest()
		r.capped++
	}
	r.seen[k] = dedupeEntry{device: device, seen: now}
	r.order = append(r.order, k)
}

// dropOldest removes the head entry. Callers hold mu.
func (r *Repairer) dropOldest() {
	for r.head < len(r.order) {
		k := r.order[r.head]
		r.head++
		if _, ok := r.seen[k]; ok {
			delete(r.seen, k)
			return
		}
	}
}

// compact reclaims the consumed prefix of order. Callers hold mu.
//
// The tail is cleared rather than left in place: instanceKey holds netip.Addrs, which
// carry an interned pointer, so stale slots beyond len would pin memory for as long
// as the slice lives.
func (r *Repairer) compact() {
	if r.head == 0 {
		return
	}
	if r.head < len(r.order)/2 && r.head < 1024 {
		return
	}
	n := copy(r.order, r.order[r.head:])
	clear(r.order[n:])
	r.order = r.order[:n]
	r.head = 0
}

// correctEgress is repair 2.
//
// A record whose SOURCE address is one the firewall holds on a WAN was NAT'd out of
// that WAN, and that is direct evidence of where it went — unlike OUTPUT_SNMP, which
// is a FIB lookup and knows nothing about the pf rule that actually routed it.
//
// The guard is as important as the repair: the rewrite fires only when the observed
// egress genuinely DIFFERS from the deduced one. Rewriting unconditionally would set
// Corrected on every WAN flow and mask the day ng_netflow starts getting this right,
// which is the one signal that would let this repair be retired.
func (r *Repairer) correctEgress(rec *Record, m ifTopology) {
	if m == nil || !rec.SrcAddr.IsValid() {
		return
	}
	wan, ok := m.WANFor(rec.SrcAddr)
	if !ok || sameIface(rec.Out, wan) {
		return
	}
	wan.Corrected = true
	rec.Out = wan

	r.mu.Lock()
	r.egressCorrected++
	r.mu.Unlock()
}

// sameIface reports whether the observed and deduced egress name the same interface.
//
// An UNMAPPED observed egress (no device, no index) does NOT agree with anything:
// replacing it with a deduced WAN is a genuine correction and is counted as one,
// because the alternative is a record labelled with no interface at all.
func sameIface(observed, deduced Iface) bool {
	if observed.Device != "" && deduced.Device != "" {
		return observed.Device == deduced.Device
	}
	return observed.Index != 0 && observed.Index == deduced.Index
}

// setDirection is repair 3.
//
// Scope is resolved HERE because the repair stage runs before enrichment
// (processor.go stage order) and the direction rules need it. It is written onto the
// record so the two stages cannot end up disagreeing about what one snapshot said.
// snap.Scope is used rather than reading SelfIPs/LocalNets directly, even though it
// costs an Addr->string->Addr round trip, because the Zenarmor lane resolves scope
// the same way and the two lanes MUST agree on this label.
func (r *Repairer) setDirection(rec *Record, m ifTopology, snap *enrich.Snapshot) {
	if snap != nil {
		if rec.Enrich.SrcScope == "" {
			rec.Enrich.SrcScope = snap.Scope(rec.SrcAddr.String())
		}
		if rec.Enrich.DstScope == "" {
			rec.Enrich.DstScope = snap.Scope(rec.DstAddr.String())
		}
	}
	rec.Direction = netflowDirection(rec, m)
}

// netflowDirection resolves the flow's orientation.
//
// Rules 1, 2 and 4 are IDENTICAL to the Zenarmor lane's directionOf
// (flowadapt.go:197-213) and must stay that way: both lanes feed one metric family
// and a query splits on this label, so a disagreement would show up as the same
// traffic appearing twice under two orientations. Only rule 3 differs, because the
// evidence differs — NetFlow knows which interfaces the packets crossed and Zenarmor
// does not, while Zenarmor states an in/out that NetFlow's field 61 would have given
// us if this box exported it.
//
//  1. A multicast, link-local or unspecified destination is internal by inspection.
//     SSDP and mDNS never leave the L2 domain, but a group address sits in no
//     configured subnet, so scope alone would call the destination remote.
//  2. Both ends resolved and neither remote: internal. "self" is the firewall itself
//     and is NOT remote — a LAN host querying the box's resolver, GUI or NTP is
//     internal traffic, and calling it outbound is the classic error here.
//  3. The evidence, strongest first.
//     (a) The interfaces. This is what NetFlow has and Zenarmor does not, and it
//     still works when the enrichment snapshot is cold and every scope lookup
//     returns "" — exactly when the scope rules cannot help.
//     (b) Which END is remote. A NetFlow record is strictly unidirectional, so a
//     record from a local address to a remote one describes packets that left, by
//     definition. This is NOT a guess and it is not a weaker form of (a) — it is
//     the same fact rule 2 already computed, read the other way.
//  4. Otherwise unknown. "unknown" is a real emitted value (record.go:40-45);
//     inventing a direction to avoid an empty label would fabricate data.
//
// (b) is not optional decoration. IfMap exposes no "is this device a WAN" predicate
// (ifmap.go), so ifaceIsWAN falls back to address evidence, which a PRE-NAT record
// does not carry: the ordinary outbound flow 10.0.0.5 -> 93.184.216.34 with
// OUTPUT_SNMP=pppoe0 resolves through (a) as nothing at all. Verified against the
// real BuildIfMap: without (b) that record reads "unknown", which is the majority of
// WAN traffic. Adding IsWAN to IfMap would make (a) answer it first and leave (b)
// covering only the records whose interfaces did not resolve.
func netflowDirection(rec *Record, m ifTopology) Direction {
	dst := rec.DstAddr
	if dst.IsMulticast() || dst.IsLinkLocalUnicast() || dst.IsLinkLocalMulticast() || dst.IsUnspecified() {
		return DirectionInternal
	}
	const remote = "remote"
	src, dstScope := rec.Enrich.SrcScope, rec.Enrich.DstScope
	if src != "" && dstScope != "" && src != remote && dstScope != remote {
		return DirectionInternal
	}
	// Egress first: an outbound record's egress interface is the one the volume metric
	// is labelled by (processor.go interfaceLabel), and it is the side repair 2 just
	// established.
	if ifaceIsWAN(m, rec.Out, rec.SrcAddr) {
		return DirectionOutbound
	}
	if ifaceIsWAN(m, rec.In, rec.DstAddr) {
		return DirectionInbound
	}
	// Rule 3b. Rule 2 already consumed the case where neither end is remote, and two
	// remote ends (transit) decide nothing, so this fires only when exactly one end is
	// remote and the other resolved.
	if src != "" && dstScope != "" {
		switch {
		case dstScope == remote && src != remote:
			return DirectionOutbound
		case src == remote && dstScope != remote:
			return DirectionInbound
		}
	}
	return DirectionUnknown
}

// ifaceIsWAN reports whether ifc is a WAN uplink, using the strongest evidence
// available.
//
// selfAddr is the address that would be the firewall's own if this side were the WAN:
// the SOURCE for an egress test (post-NAT, so it is the WAN's address) and the
// DESTINATION for an ingress test. That address echo is what makes the fallback work
// on an IfMap exposing no IsWAN, and it covers every NAT'd flow — which is nearly all
// v4 WAN traffic, though not un-NAT'd IPv6.
func ifaceIsWAN(m ifTopology, ifc Iface, selfAddr netip.Addr) bool {
	if ifc.Corrected {
		// Only repair 2 sets this, and only from the WAN table, so it is a WAN by
		// construction.
		return true
	}
	if m == nil || ifc.Device == "" {
		return false
	}
	if k, ok := m.(wanKnower); ok {
		return k.IsWAN(ifc.Device)
	}
	if !selfAddr.IsValid() {
		return false
	}
	w, ok := m.WANFor(selfAddr)
	return ok && w.Device != "" && w.Device == ifc.Device
}
