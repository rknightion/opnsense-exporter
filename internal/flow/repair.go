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
//     VLAN traffic to the parent's interface name. WHICH copy survives is as much
//     of the repair as how many do: the box flushes the trunk copy first, so
//     keeping the earlier arrival keeps the wrong one every time (#357).
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

// vlanHoldWindow is how long a record that could still be beaten by a more specific
// copy waits before it is emitted (#357).
//
// It exists because the winner cannot always be decided from the copy in hand. On the
// reference box the trunk hook's flows and the child hook's flows leave in SEPARATE
// CONSECUTIVE DATAGRAMS of one expiry sweep — measured on the golden fixture, the
// parent copy arrives first in 12 of 12 genuine pairs — so a first-seen-wins rule does
// not merely risk keeping the trunk copy, it keeps it every time. Waiting out the rest
// of the sweep is what makes the outcome independent of datagram scheduling.
//
// Two seconds is roughly three orders of magnitude beyond the observed sub-second gap
// between the two datagrams, and sits well inside the correlator's own window, so a
// held record costs no flow-log latency that was not already there. It is deliberately
// not a flag, matching dedupeTTL and the de-dup bound: the value that would actually
// want tuning is the memory bound, and that is already a constant an operator can see.
const vlanHoldWindow = 2 * time.Second

// RepairStats is the repair stage's own accounting. Every field is published as a
// self-metric: a repair nobody can observe is a repair nobody will trust, which is
// the same reasoning that put Corrected on Iface (record.go:112-124).
//
// Every field is a scalar counter or gauge. Nothing address-, port- or
// flow-identifying may ever be attached to them.
type RepairStats struct {
	// VLANDuplicatesDropped counts records suppressed as the second copy of an
	// instance ng_netflow exported twice.
	VLANDuplicatesDropped uint64
	// EgressCorrected counts records whose egress interface was replaced by the WAN
	// deduced from their source address.
	EgressCorrected uint64
	// VLANChildPreferred counts the duplicates resolved IN FAVOUR OF THE VLAN CHILD
	// after the parent copy had already been held — the repair #357 added. It is kept
	// apart from VLANDuplicatesDropped (which counts both copies' worth of drops
	// regardless of which won) because it is the only number that answers "is the
	// attribution fix doing anything on this box"; a de-dup that drops the right
	// COUNT while keeping the wrong COPY is exactly the failure that went unnoticed.
	VLANChildPreferred uint64

	// HeldEntries is how many records are parked in the hold buffer right now,
	// waiting out vlanHoldWindow. It is a gauge of the latency this repair costs and
	// of the memory it holds.
	HeldEntries int
	// HoldOverflow counts records RELEASED EARLY because the hold buffer was full.
	// They are emitted, never dropped — early release degrades to first-seen-wins for
	// that record, which is the behaviour that predates #357, rather than losing it.
	// A non-zero rate means the bound wants raising.
	HoldOverflow uint64

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
	// HasVLANChildren reports whether a device is a trunk, i.e. whether a more
	// specific copy of a record naming it could still exist.
	HasVLANChildren(device string) bool
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

// instanceKey identifies ONE export of one flow: the DIRECTIONAL 5-tuple, the flow's
// own First/Last timestamps, and its volume. Everything an ng_netflow record states
// except the interfaces it crossed — which is precisely what the two copies differ in.
//
// Every component is load-bearing, and two of them were added by #357 after the
// original key destroyed real traffic:
//
//   - DIRECTIONAL, not canonical. A NetFlow record is strictly unidirectional, so the
//     two halves of a conversation are two separate exports. Canonicalising them
//     folded both halves onto one key, and on the golden fixture that is exactly what
//     happened: a 4,907-byte record on a VLAN child and the 558-byte reverse record on
//     its trunk collided, the reverse record was declared a "VLAN duplicate", and 558
//     bytes of real traffic was destroyed.
//   - The timestamps. A long-lived conversation is exported repeatedly with an
//     identical tuple, so without them a busy flow would collapse to a single record.
//   - The VOLUME. Two copies of one export are byte-identical — measured across every
//     duplicate pair in the fixture (1008/1008, 716/716, 149/149, 64/64, 1471/1471) —
//     while two different exports that happen to share a tuple and a timestamp pair do
//     not. This is the file's own rule applied to the key itself: never drop what is
//     not PROVEN a duplicate. If some exporter ever counted the 802.1Q header on the
//     trunk but not on the child, the two copies would stop matching and the de-dup
//     would stop firing — an over-count, which is visible, rather than a silent loss,
//     which is not. That is the direction to fail in.
//
// netip.Addr is comparable, so this is a map key with no allocation and no string
// formatting.
type instanceKey struct {
	proto        uint8
	src, dst     netip.Addr
	sport, dport uint16
	first, last  int64 // UnixNano of Record.Start / Record.End
	bytes        uint64
	packets      uint64
}

func keyOf(rec *Record) instanceKey {
	bytes, packets := volumeOf(*rec)
	return instanceKey{
		proto:   rec.Proto,
		src:     rec.SrcAddr.Unmap(),
		dst:     rec.DstAddr.Unmap(),
		sport:   rec.SrcPort,
		dport:   rec.DstPort,
		first:   rec.Start.UnixNano(),
		last:    rec.End.UnixNano(),
		bytes:   bytes,
		packets: packets,
	}
}

// dedupeEntry remembers which interfaces an instance was ADMITTED on, so a later copy
// on related interfaces can be recognised as the duplicate it is. Both sides are
// remembered: the ingress-side pair is what a trunk-captured OUTBOUND duplicate
// differs in, and the egress-side pair is what its INBOUND half differs in — keying on
// the ingress alone left every inbound VLAN duplicate undetected.
type dedupeEntry struct {
	in, out string
	seen    time.Time
}

// heldRecord is a record parked in the hold buffer: a copy that is admissible but
// could still be beaten by a more specific one within vlanHoldWindow.
//
// It carries the topology and enrichment snapshot CURRENT WHEN IT ARRIVED, because
// repairs 2 and 3 are deferred to release (a copy that loses must never be corrected
// or counted) and must still resolve against the view the record arrived under. Both
// are immutable and atomically published, so this is two pointers, not a copy.
type heldRecord struct {
	rec  Record
	m    ifTopology
	snap *enrich.Snapshot
	// arrived is when the FIRST copy of this instance landed, not when the copy
	// currently stored did. It sets both the release deadline and, once released, the
	// instance's age in the de-dup table — the pair's window opens when the pair is
	// first seen, and the TTL must not be inflated by however long we held it.
	arrived time.Time
}

func (h *heldRecord) deadline() time.Time { return h.arrived.Add(vlanHoldWindow) }

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

	// held is the hold buffer, kept DELIBERATELY SEPARATE from seen: the two have
	// different lifetimes (vlanHoldWindow against dedupeTTL, three orders of magnitude
	// apart) and only one of them owns a record that has not been emitted yet. Sharing
	// one table would put the TTL sweep in a position to delete a record nobody has
	// seen — a silent loss — for no gain.
	held      map[instanceKey]*heldRecord
	holdOrder []instanceKey
	holdHead  int
	// dueEarly holds records forced out of the buffer before their deadline because it
	// was full. The next Release emits them.
	dueEarly []*heldRecord

	maxEntries int
	maxHeld    int

	vlanDropped     uint64
	egressCorrected uint64
	evicted         uint64
	capped          uint64
	childPreferred  uint64
	holdOverflow    uint64
}

// RepairVerdict is what the repair stage decided about one record. It is NOT
// Verdict, which is the firewall's own disposition on a flow (record.go:68-77) and
// says nothing about the pipeline.
type RepairVerdict int

const (
	// RepairEmit means the record is the copy to keep and is fully repaired. The
	// caller enriches and ships it.
	RepairEmit RepairVerdict = iota
	// RepairDrop means the record is a duplicate of one the stage already holds or
	// has emitted. The caller discards it and does no further work on it.
	//
	// It is ALSO what a copy that WINS a contest against a held record reports: the
	// winner takes the loser's place in the hold buffer rather than being emitted
	// now, so from the caller's side exactly one record leaves the pair either way and
	// the accounting is identical. Which copy that is shows up in VLANChildPreferred.
	RepairDrop
	// RepairHold means the record is admissible but a more specific copy could still
	// arrive, so the stage has parked it. The caller does nothing; the record comes
	// back from Release once its window elapses.
	RepairHold
)

// NewRepairer returns a Repairer whose de-dup table holds at most maxDedupeEntries
// instances and whose hold buffer holds at most maxHeld records. Zero means unbounded
// for either, matching NewRollup's convention for its own caps.
//
// Both tables are fed by an unauthenticated UDP listener — NetFlow has no auth — so on
// any exposed deployment these bounds are the memory guard, not tuning knobs. The hold
// buffer's bound is the tighter concern of the two: it holds whole Records rather than
// keys, and it holds them on behalf of records nobody downstream has seen yet.
func NewRepairer(maxDedupeEntries, maxHeld int) *Repairer {
	return &Repairer{
		seen:       make(map[instanceKey]dedupeEntry),
		held:       make(map[instanceKey]*heldRecord),
		maxEntries: maxDedupeEntries,
		maxHeld:    maxHeld,
	}
}

// Repair mutates rec in place and reports what the caller should do with it: emit it,
// drop it as a duplicate, or nothing at all because the stage is holding it (see
// RepairVerdict). A held record comes back from Release, fully repaired.
//
// m may be nil (the state before the first interface refresh) and snap may be nil (a
// lane running with enrichment off). Neither panics, and neither causes a drop OR a
// hold: without topology nothing can be PROVEN a duplicate, nothing can be known to
// have a more specific copy, and dropping or delaying on suspicion would lose or stall
// real traffic.
func (r *Repairer) Repair(rec *Record, m *IfMap, snap *enrich.Snapshot, now time.Time) RepairVerdict {
	if m == nil {
		// Boxing a nil *IfMap yields a NON-nil interface, so the nil test has to happen
		// here rather than inside. (IfMap's own methods are nil-receiver safe, but
		// relying on that would make this file's correctness depend on another lane's.)
		return r.repairWith(rec, nil, snap, now)
	}
	return r.repairWith(rec, m, snap, now)
}

// Release returns every held record whose window has elapsed, plus anything the hold
// buffer had to let go early, each with repairs 2 and 3 applied. The caller enriches
// and ships them exactly as it would a RepairEmit record.
//
// It is cheap to call and safe to call often: the common case is a bounded scan that
// stops at the first record not yet due. The caller should drive it from both the
// receive path (so a busy lane needs no timer at all) and a ticker (so a lane that has
// gone quiet still flushes what it is holding).
func (r *Repairer) Release(now time.Time) []Record {
	return r.release(now, false)
}

// Flush returns every held record regardless of its deadline, for a clean shutdown.
// After it returns the hold buffer is empty. Its counterpart is Correlator.Flush, and
// it exists for the same reason: a record parked in a buffer at exit is a record the
// process was told about and never reported.
func (r *Repairer) Flush() []Record {
	return r.release(time.Time{}, true)
}

// release pops the due (or, when all is set, every) held record and finishes it.
//
// The two repairs run OUTSIDE the lock, both because correctEgress takes it itself and
// because there is no reason to hold the hot path's mutex across work that touches
// nothing shared.
func (r *Repairer) release(now time.Time, all bool) []Record {
	r.mu.Lock()
	due := r.dueEarly
	r.dueEarly = nil
	for r.holdHead < len(r.holdOrder) {
		k := r.holdOrder[r.holdHead]
		h, ok := r.held[k]
		if ok && !all && now.Before(h.deadline()) {
			// Deadlines are assigned from a constant window at insertion, so hold order
			// IS deadline order and the first record not yet due ends the scan.
			break
		}
		r.holdHead++
		if !ok {
			continue
		}
		delete(r.held, k)
		// The instance moves into the de-dup table as it leaves the buffer: a later copy
		// must still be recognised as a duplicate even though nothing is holding a
		// record for it any more.
		r.insert(k, h.rec.In.Device, h.rec.Out.Device, h.arrived)
		due = append(due, h)
	}
	r.compactHold()
	r.mu.Unlock()

	if len(due) == 0 {
		return nil
	}
	out := make([]Record, 0, len(due))
	for _, h := range due {
		r.correctEgress(&h.rec, h.m)
		r.setDirection(&h.rec, h.m, h.snap)
		out = append(out, h.rec)
	}
	return out
}

// repairWith is the real entry point, resolving against the narrow seam so the
// decision logic is testable without a constructed IfMap.
//
// The stage order is load-bearing and is asserted by a test: de-dup FIRST, so a
// record that is about to be discarded is never corrected, counted or given a
// direction; then the egress correction; then direction, which READS the corrected
// egress — a policy-routed flow is only recognisable as outbound after repair 2 has
// named the WAN it actually left by.
func (r *Repairer) repairWith(rec *Record, m ifTopology, snap *enrich.Snapshot, now time.Time) RepairVerdict {
	if rec == nil {
		return RepairDrop
	}
	switch v := r.admit(rec, m, snap, now); v {
	case RepairDrop, RepairHold:
		// A held record's repairs are deferred to Release for the same reason a dropped
		// record gets none at all: it may yet lose to a more specific copy, and work
		// spent on a copy that loses is at best wasted and at worst reaches a counter.
		return v
	}
	r.correctEgress(rec, m)
	r.setDirection(rec, m, snap)
	return RepairEmit
}

// Stats reports the repair stage's own accounting.
func (r *Repairer) Stats() RepairStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return RepairStats{
		VLANDuplicatesDropped: r.vlanDropped,
		EgressCorrected:       r.egressCorrected,
		VLANChildPreferred:    r.childPreferred,
		// dueEarly counts as held: those records have left the buffer but not yet the
		// stage, and a gauge that dropped them would make the accounting look short for
		// as long as they sat there.
		HeldEntries:   len(r.held) + len(r.dueEarly),
		HoldOverflow:  r.holdOverflow,
		DedupeEntries: len(r.seen),
		DedupeEvicted: r.evicted,
		DedupeCapped:  r.capped,
	}
}

// admit is repair 1. It decides which copy of an instance is the one to keep.
//
// THE ARRIVAL-ORDER PROBLEM. The two copies of a duplicated instance arrive in
// DIFFERENT datagrams and nothing on the wire says which lands first, so a rule that
// keeps whichever copy arrived first does not keep the copy we want — it keeps
// whichever one the exporter happened to flush first. On the reference box that is
// always the trunk copy: the trunk hook's flows and the child hook's flows leave in
// separate consecutive datagrams of one expiry sweep, so first-seen-wins kept the
// parent copy in 12 of 12 genuine pairs and attributed every VLAN's traffic to the
// trunk (#357). Three mechanisms, in order:
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
// A IS DEAD AGAINST THE REFERENCE BOX and is kept anyway: 0 of the 131 records in the
// golden capture carry SRC_VLAN/DST_VLAN, so this branch never fires there. It is
// still correct for an exporter that does send field 58, and it is the only mechanism
// that costs nothing at all, so removing it would trade real coverage for tidiness.
//
// B. THE HOLD. When the export carries no usable tag, the copies are distinguishable
// only by having been seen — which is the arrival-order trap above. So a record that
// COULD still be beaten (one of its interfaces is a trunk with VLAN children, so a
// more specific copy may exist) is parked for vlanHoldWindow instead of being emitted.
// A better copy arriving inside that window takes its place. Nothing else is delayed:
// a box with no VLANs, or a record naming no trunk, holds nothing.
//
// C. THE INSTANCE TABLE. Whatever the hold did not resolve, the table still catches:
// a second copy of an instance already decided is suppressed, and the pair is resolved
// by topology on BOTH interfaces — ingress and egress, because the ingress-side pair
// is what an outbound duplicate differs in and the egress-side pair is what its
// inbound half differs in. Records that merely share an instance key on unrelated
// interfaces are KEPT: never drop what cannot be proven duplicate.
//
// The residual, stated plainly: a copy whose partner arrives more than vlanHoldWindow
// later, or after the hold buffer had to release it early, is resolved by C alone and
// therefore by arrival order. HoldOverflow counts the second case; the first cannot
// happen for two copies of one expiry sweep.
func (r *Repairer) admit(rec *Record, m ifTopology, snap *enrich.Snapshot, now time.Time) RepairVerdict {
	parentCopy := isVLANParentCopy(rec, m)
	key := keyOf(rec)
	in, out := rec.In.Device, rec.Out.Device

	r.mu.Lock()
	defer r.mu.Unlock()
	r.expire(now)

	if parentCopy {
		r.vlanDropped++
		return RepairDrop
	}

	// Mechanism B's contest. A held copy has not been emitted, so unlike everything
	// below it can still be replaced rather than merely defended.
	if h, ok := r.held[key]; ok {
		if !isDuplicateOf(h.rec.In.Device, h.rec.Out.Device, in, out, m) {
			// Same instance key on unrelated interfaces: not proven a duplicate.
			return RepairEmit
		}
		r.vlanDropped++
		if moreSpecific(in, out, h.rec.In.Device, h.rec.Out.Device, m) {
			// The incoming copy names a VLAN child where the held one names that child's
			// parent. It takes the held record's place, keeping its deadline and its slot
			// in hold order: the pair's window opened when the FIRST copy arrived, and
			// restarting it would let a stream of copies hold a record indefinitely.
			h.rec, h.m, h.snap = *rec, m, snap
			r.childPreferred++
		}
		return RepairDrop
	}

	if prev, ok := r.seen[key]; ok {
		if isDuplicateOf(prev.in, prev.out, in, out, m) {
			r.vlanDropped++
			return RepairDrop
		}
		// Same instance, unrelated interfaces: not proven a duplicate. Keep it, and
		// leave the admitted devices alone — the first copy stays the reference.
		return RepairEmit
	}

	if canBeBeaten(m, in, out) {
		r.hold(key, rec, m, snap, now)
		return RepairHold
	}
	r.insert(key, in, out, now)
	return RepairEmit
}

// canBeBeaten reports whether a more specific copy of this record could still exist —
// i.e. whether either interface it names is a trunk with VLAN children.
//
// This is what keeps the hold buffer small and the added latency narrow: on a box with
// no VLANs it is false for every record, and on one with VLANs it is false for
// everything that never touched the trunk.
func canBeBeaten(m ifTopology, in, out string) bool {
	if m == nil {
		return false
	}
	return m.HasVLANChildren(in) || m.HasVLANChildren(out)
}

// isDuplicateOf reports whether two records under the same instance key are two copies
// of ONE export rather than two different exports that happen to collide.
//
// They are, iff each side names either the same device or a trunk/child pair. The
// interfaces are all that ng_netflow's two hooks disagree about; the key has already
// established that everything else — tuple, direction, timestamps, volume — is
// identical, so anything that also agrees on topology is the same packets twice.
//
// The both-sides-identical case is a real one and is deliberately included: when the
// ingress and egress ifIndex are the same on both hooks (an inter-VLAN flow, where the
// pair reads in=trunk out=child for both copies) the two are indistinguishable by
// interface, and refusing to call that a duplicate double-counted it.
func isDuplicateOf(aIn, aOut, bIn, bOut string, m ifTopology) bool {
	return sideMatches(aIn, bIn, m) && sideMatches(aOut, bOut, m)
}

// sideMatches reports whether one side of two copies names the same device or a
// trunk/child pair.
func sideMatches(a, b string, m ifTopology) bool {
	return a == b || isVLANPair(a, b, m)
}

// moreSpecific reports whether the copy naming (aIn, aOut) attributes the flow better
// than the one naming (bIn, bOut): it names a VLAN CHILD on at least one side where
// the other names that child's parent, and names a parent on no side.
//
// The one-sided requirement is what makes this a strict improvement rather than a
// swap. A copy that is more specific on the ingress and less specific on the egress
// states no clear preference, and in that case the incumbent stands — arbitrary, but
// arbitrary in favour of doing nothing, and the shape does not occur on a box whose
// two hooks report one ifIndex pair.
func moreSpecific(aIn, aOut, bIn, bOut string, m ifTopology) bool {
	better := isChildOf(aIn, bIn, m) || isChildOf(aOut, bOut, m)
	worse := isChildOf(bIn, aIn, m) || isChildOf(bOut, aOut, m)
	return better && !worse
}

// isChildOf reports whether child is a VLAN child of parent, per the interface table.
func isChildOf(child, parent string, m ifTopology) bool {
	if m == nil || child == "" || parent == "" || child == parent {
		return false
	}
	p, ok := m.ParentOf(child)
	return ok && p == parent
}

// isVLANParentCopy implements mechanism A above.
//
// It tests the INGRESS side only. The egress-side equivalent — a tagged record whose
// egress names the tag's parent — is left unwritten deliberately: no export we can
// observe sends field 58 at all (see the note on A in admit), so the shape it would
// have to match is unverifiable, and mechanisms B and C already cover that side by
// topology. Mechanism C's isDuplicateOf is where the egress side IS handled.
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
//
// ALMOST monotone, since #357: a released record enters the table stamped with when it
// ARRIVED, not when it was released, so it can land behind an entry inserted while it
// was still held. The disorder is bounded by vlanHoldWindow — two seconds against a
// two-minute TTL — so the worst case is an entry lingering a couple of seconds past its
// TTL, and paying for a full scan to avoid that would be the wrong trade. Stamping the
// release time instead is NOT the fix: Flush releases with no clock at all, so the
// arrival time is the only one always available.
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
func (r *Repairer) insert(k instanceKey, in, out string, now time.Time) {
	if r.maxEntries > 0 && len(r.seen) >= r.maxEntries {
		r.dropOldest()
		r.capped++
	}
	r.seen[k] = dedupeEntry{in: in, out: out, seen: now}
	r.order = append(r.order, k)
}

// hold parks a record that could still be beaten by a more specific copy. Callers
// hold mu.
//
// At capacity the OLDEST held record is RELEASED EARLY, never dropped. That is the
// whole difference between this bound and the de-dup table's: an entry in that table
// is a memory of a decision already taken, while a record in here has not been emitted
// yet, so discarding it would be silent data loss. Early release degrades that one
// record to first-seen-wins — the behaviour that predates #357 — and is counted apart
// from everything else so the pressure is visible for what it is.
func (r *Repairer) hold(k instanceKey, rec *Record, m ifTopology, snap *enrich.Snapshot, now time.Time) {
	if r.maxHeld > 0 && len(r.held) >= r.maxHeld {
		r.releaseOldestHeld()
	}
	r.held[k] = &heldRecord{rec: *rec, m: m, snap: snap, arrived: now}
	r.holdOrder = append(r.holdOrder, k)
}

// releaseOldestHeld moves the oldest held record onto the early-release list, so the
// next Release emits it. Callers hold mu.
func (r *Repairer) releaseOldestHeld() {
	for r.holdHead < len(r.holdOrder) {
		k := r.holdOrder[r.holdHead]
		r.holdHead++
		h, ok := r.held[k]
		if !ok {
			continue
		}
		delete(r.held, k)
		r.insert(k, h.rec.In.Device, h.rec.Out.Device, h.arrived)
		r.dueEarly = append(r.dueEarly, h)
		r.holdOverflow++
		return
	}
}

// compactHold reclaims the consumed prefix of holdOrder, on the same terms and for the
// same interned-pointer reason as compact.
func (r *Repairer) compactHold() {
	if r.holdHead == 0 {
		return
	}
	if r.holdHead < len(r.holdOrder)/2 && r.holdHead < 1024 {
		return
	}
	n := copy(r.holdOrder, r.holdOrder[r.holdHead:])
	clear(r.holdOrder[n:])
	r.holdOrder = r.holdOrder[:n]
	r.holdHead = 0
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
