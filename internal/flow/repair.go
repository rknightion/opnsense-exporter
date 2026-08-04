package flow

import (
	"maps"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
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
//  4. Policy-route egress correction (#603). Repair 2 can only fix the POST-NAT copy,
//     because it keys on the source address and a pre-NAT record's source is a private
//     LAN address. The pre-NAT copy is the only one that can ever correlate with a
//     Zenarmor conn document, and on the reference box every byte Zenarmor inspected
//     that actually left by WAN2 was reported as WAN1. This repair resolves it from
//     pf's own state table, which carries the routing decision verbatim; see
//     routetable.go for why that beats every inferential join.
//  5. NAT-pair de-duplication (#623). A conversation crossing a captured LAN
//     interface AND a captured ethernet WAN is exported TWICE — pre-NAT on one node,
//     post-NAT on the other — and nothing in either record says so, because the
//     whole point of NAT is that the tuples differ. Both were counted, and the
//     reference box's policy-routed WAN read 62.40 GB against 45.05 GB actual.
//     pf's own nat_addr/nat_port pairs them exactly; see nattable.go.

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
	// VLANSubnetAttributed counts trunk-named records moved onto the VLAN child that
	// owns the address's subnet — mechanism A' (#465). It is the number that says
	// whether subnet evidence is doing the work: unlike VLANChildPreferred it also
	// counts records with NO second copy at all, which #403 measured at 247,105 over
	// 18h35m and which no hold window of any size could ever have attributed.
	VLANSubnetAttributed uint64
	// VLANLateChildCopies counts the RESIDUAL: a proven duplicate that arrived MORE
	// SPECIFIC than the copy already emitted, and therefore too late to correct
	// anything. It is the one case the stage still resolves by arrival order.
	//
	// It exists because the alternative is silence. An emitted record has been counted
	// in the rollup and shipped, so it cannot be taken back, and re-emitting the better
	// copy would double-count real bytes. Counting the case instead makes the residual
	// observable: it was ~29% of pairs before #465 (108,678 of 372,109, every one of
	// them trunk-first), and it should now be near zero, moving only for the ambiguous
	// addresses subnet evidence legitimately refuses.
	VLANLateChildCopies uint64

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
	// PolicyRouteCorrected counts records whose egress was replaced by the device
	// pf's own state table says the traffic left by (#603). A zero rate on a
	// single-WAN box is expected; a zero rate on a policy-routed multi-WAN box means
	// the mechanism is not firing and per-WAN volume on the correlatable copy is
	// wrong.
	PolicyRouteCorrected uint64
	// PolicyRouteNoState counts pre-NAT egress records for which NO pf state exists.
	// This is the mechanism's genuine miss window: a short flow whose state expired
	// before its NetFlow record arrived (the reference box runs inactiveTimeout=15).
	// It is kept apart from PolicyRouteCorrected because the two call for opposite
	// responses — corrections rising is the repair working, misses rising is
	// attribution that cannot be recovered at all, and NO poll interval fixes it.
	PolicyRouteNoState uint64
	// PolicyRouteNoStateByInterface splits PolicyRouteNoState by the interface
	// ng_netflow REPORTED for the record — i.e. where the bytes are currently being
	// attributed, not where they actually went (#620 follow-up).
	//
	// Which is the only interface a refused record HAS. The whole reason it was
	// refused is that pf could not tell us the real egress, so this cannot say
	// "these misses belong to WAN2". What it can say is whether the misses pile up
	// on ONE interface or spread across every WAN, and that is the question worth
	// answering: refusals concentrated on the default-route WAN are consistent with
	// policy-routed traffic hiding inside it, while refusals spread evenly are
	// structural and mean the mechanism has nothing left to recover.
	//
	// Cardinality is one series per WAN, on an exporter using ~4.6k of a 100k budget.
	PolicyRouteNoStateByInterface map[string]uint64
	// PolicyRouteSkipped* count the four ways repair 4 declines to act WITHOUT it
	// being a miss (#624). Before they existed, three of the four moved no counter,
	// so "the repair is finding nothing to do" and "the repair is never running"
	// produced identical telemetry — which is how a 9x gap between the code and a
	// deployment went unexplained.
	//
	// NotWANEgress is the record not leaving by a WAN at all. It is the majority of
	// records on any box and healthy, but it is ALSO what a wrong interface map looks
	// like: if the map stops reporting a device as a WAN, every record on it moves
	// here and the repair silently ceases to exist. Watch it as a SHARE of decoded
	// records, not as a rate.
	//
	// PostNAT is repair 2's population, already resolved from the source address.
	// FIBAgreed is a state found carrying no route-to, i.e. pf used the FIB and
	// OUTPUT_SNMP was already right. AlreadyOnWAN is a policy-routed state whose
	// device ng_netflow had ALSO named, so the correction would be a no-op — kept
	// apart from FIBAgreed because the two say different things about whether the
	// mechanism is earning its keep.
	PolicyRouteSkippedNotWANEgress uint64
	PolicyRouteSkippedPostNAT      uint64
	PolicyRouteSkippedFIBAgreed    uint64
	PolicyRouteSkippedAlreadyOnWAN uint64
	// PolicyRouteUnresolvedDevice counts states whose route-to named a device the
	// interface map does not know. Kept apart again: the fix is the interface
	// enumeration, not the poll cadence. The record is left alone rather than
	// labelled with a raw kernel device, which would split one interface across two
	// series exactly as #606 describes.
	PolicyRouteUnresolvedDevice uint64
	// PolicyRouteUnresolvedDeviceByInterface splits it the same way.
	PolicyRouteUnresolvedDeviceByInterface map[string]uint64

	// RouteTableEntries, RouteTablePolicyRouted and RouteTableAge describe the pf
	// state snapshot the repair resolves against. A lookup table nobody can size or
	// age is one nobody will trust the day it starts answering "no".
	RouteTableEntries      int
	RouteTablePolicyRouted int
	RouteTableSkipped      int
	RouteTableConflicts    int
	// RouteTableCarried is the subset of RouteTableEntries answered from an EARLIER
	// snapshot rather than the current one (#620) — expired states still inside the
	// retention window. Persistently zero means the rolling union is contributing
	// nothing; a value that dwarfs the fresh count means states are dying much faster
	// than we poll and most answers describe a table that no longer exists.
	RouteTableCarried int
	RouteTableAge     time.Duration

	// NATDuplicatesDropped counts POST-NAT copies suppressed because the pre-NAT
	// copy of the same conversation had already been emitted (#623). On a box whose
	// WAN is captured alongside its LAN this is the difference between per-WAN byte
	// totals that agree with the kernel's interface counters and totals that do not;
	// the reference box read +38.5% before it existed. Zero on a box with no
	// captured WAN, or one whose WAN is PPPoE and therefore exports nothing.
	NATDuplicatesDropped uint64
	// NATLatePreNATCopies counts the RESIDUAL: the pre-NAT copy arrived AFTER its
	// post-NAT twin had already been emitted, so the double count could not be
	// prevented without discarding the only correlatable copy of that conversation.
	// Measured at 10.8% of pairs (43 of 399). It is a fraction of
	// NATDuplicatesDropped, not a fault, and the two should move together.
	NATLatePreNATCopies uint64
	// NATConversationDuplicates counts POST-NAT copies suppressed on the SECOND
	// proof (#636): the exact export twin was not in the identity table, but this
	// conversation's LAN side is demonstrably being captured, so its bytes reach the
	// rollup by the pre-NAT copy regardless.
	//
	// It is the number that carries the fix on a quiet WAN, where the WAN-side
	// ng_netflow node batches its exports minutes behind the LAN node's and the exact
	// window can never close. A box whose WAN node is busy pairs almost everything
	// exactly and leaves this near zero; the split between the two is the diagnostic.
	NATConversationDuplicates uint64
	// NATUnpaired counts post-NAT copies EMITTED because neither proof was available.
	//
	// This is the guard. #636 was a mechanism that fell silent while every other
	// number stayed plausible: the translation index was populated, the identity
	// table was populated, conflicts were in band, and the two de-dup counters simply
	// read zero — which is indistinguishable from a box that has nothing to
	// de-duplicate. This one is not: it moves only when a record pf CALLS a
	// translation is emitted anyway, so
	//
	//	NATUnpaired / (NATUnpaired + NATDuplicatesDropped + NATConversationDuplicates)
	//
	// is the share of proven-translated post-NAT copies the stage failed to pair, and
	// it reads ~1 when the mechanism is broken rather than reading nothing at all.
	// A small non-zero value is normal: a post-NAT copy that legitimately arrives
	// first is unpaired at that instant and is counted again as NATLatePreNATCopies
	// when its twin lands.
	NATUnpaired uint64
	// NATSeenEntries is the live size of the canonical-identity table, and
	// NATSeenCapped counts entries forced out early because it was full. A non-zero
	// cap rate means NAT duplicates are reaching the rollup.
	NATSeenEntries int
	NATSeenCapped  uint64
	// NATConversationEntries is the live size of the conversation table, and
	// NATConversationCapped counts conversations NOT recorded because it was full.
	// Both carry the same reading as their NATSeen* counterparts: a non-zero cap rate
	// means NAT duplicates are reaching the rollup.
	NATConversationEntries int
	NATConversationCapped  uint64
	// NATTableEntries, NATTableCarried, NATTableConflicts and NATTableSkipped
	// describe the pf translation index itself, on the same terms as the
	// RouteTable* fields above. Entries counts BOTH directional forms of each
	// translation, so it is roughly twice the number of translated states.
	NATTableEntries   int
	NATTableCarried   int
	NATTableConflicts int
	NATTableSkipped   int

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
	// VLANChildFor resolves an address to the VLAN child of parent whose configured
	// subnet contains it, and answers ONLY when exactly one child owns it. This is the
	// evidence mechanism A' acts on; see IfMap.VLANChildFor for the three refusals.
	VLANChildFor(parent string, addr netip.Addr) (Iface, bool)
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

// deviceResolver turns a kernel device name back into the whole interface.
//
// Repair 4's evidence is pf's `route-to`, which names a DEVICE and nothing else,
// while the metric label wants the description. It is an OPTIONAL assertion for the
// same reason wanKnower is: the frozen ifTopology contract does not include it, and
// a map that cannot answer must leave the record alone rather than label it with a
// raw kernel name.
type deviceResolver interface {
	IfaceForDevice(device string) (Iface, bool)
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

	// routes is the pf state snapshot repair 4 resolves against, swapped wholesale by
	// the cold-tier poller. Readers take no lock; the table is immutable after build.
	routes atomic.Pointer[RouteTable]
	// nats is the NAT translation index repair 5 resolves against, built from the
	// SAME snapshot on the same poll and swapped on the same terms (#623).
	nats atomic.Pointer[NATTable]

	// natSeen remembers the CANONICAL identity of every record that has been
	// emitted, so the post-NAT copy of the same conversation can be recognised when
	// it lands — on the reference box a median of 20 seconds later, p99 60 seconds.
	//
	// It is kept apart from seen for the same reason held is: a different key (no
	// timestamps — the two copies' first/last disagree in 39% of real pairs) and a
	// different question. Sharing one table would need one of the two questions to
	// be answered with the wrong key.
	natSeen   map[natKey]natSeenEntry
	natOrder  []natKey
	natHead   int
	natCapped uint64

	// natConv is the SECOND, weaker proof (#636): the set of canonical (pre-NAT)
	// tuples for which a pre-NAT record has actually been observed, i.e. the
	// conversations whose LAN side is demonstrably being captured.
	//
	// It answers a different question from natSeen and on a different timescale.
	// natSeen asks "have I already emitted THIS EXACT export?", which needs the
	// volume and is only answerable while both copies are in flight. natConv asks
	// "is this conversation captured on both sides?", which is a property of the
	// conversation rather than of one export, so it survives an arrival gap of any
	// size. See natAdmit for why the second is needed.
	//
	// Keyed on the tuple alone and gated on NATTable.IsTranslatedPre, so it holds one
	// entry per TRANSLATED conversation rather than one per record. That gate is what
	// makes it scale with how much the box NATs rather than with its record rate — it
	// does NOT make the table smaller: measured on the reference box 40 minutes after
	// a restart, 4,039 conversations against natSeen's 3,026, because the TTL is 7.5x
	// longer. Both sit against the same maxEntries bound.
	natConv       map[routeKey]time.Time
	natConvSwept  time.Time
	natConvCapped uint64

	maxEntries int
	maxHeld    int

	vlanDropped     uint64
	egressCorrected uint64
	evicted         uint64
	capped          uint64
	childPreferred  uint64
	holdOverflow    uint64
	subnetAttrib    uint64
	lateChildCopies uint64

	policyRouteCorrected  uint64
	policyRouteNoState    uint64
	policyRouteUnresolved uint64
	// Keyed by the interface ng_netflow reported. Lazily allocated: a single-WAN box
	// never refuses anything and should carry no map at all.
	policyRouteNoStateBy    map[string]uint64
	policyRouteUnresolvedBy map[string]uint64

	natDuplicates     uint64
	natConvDuplicates uint64
	natUnpaired       uint64
	natLatePreCopies  uint64

	// Repair 4's SILENT EXITS, made countable (#624). Three of the four ways
	// correctPolicyRoute can decline to act moved no counter at all, so a box where
	// the repair was doing nothing looked identical to a box where it had nothing to
	// do. They are atomics rather than mutex-guarded fields because notWANEgress
	// fires on the majority of records and the existing early return deliberately
	// does not take the lock.
	prNotWANEgress atomic.Uint64
	prPostNAT      atomic.Uint64
	prFIBAgreed    atomic.Uint64
	prAlreadyOnWAN atomic.Uint64
}

// bumpByInterface increments the per-interface tally for a record's REPORTED
// egress, allocating the map on first use so a box that never refuses carries none.
//
// An unnamed interface is filed under "unresolved" rather than under the empty
// string: a blank label renders as a gap in a legend and reads as a bug in the
// dashboard, and it is the same word the ifIndex lane already uses for the cold-start
// case, so the two agree.
func bumpByInterface(counts map[string]uint64, iface Iface) map[string]uint64 {
	name := iface.Name
	if name == "" {
		name = "unresolved"
	}
	if counts == nil {
		counts = make(map[string]uint64, 4)
	}
	counts[name]++
	return counts
}

// copyCounts snapshots a tally so the caller cannot race the record path by holding
// the live map. Nil in, nil out — an empty map and no map mean the same thing here
// and neither should invent a zero-valued series.
func copyCounts(counts map[string]uint64) map[string]uint64 {
	if len(counts) == 0 {
		return nil
	}
	out := make(map[string]uint64, len(counts))
	maps.Copy(out, counts)
	return out
}

// SetRouteTable publishes a new pf state snapshot. Safe to call while records are
// in flight; a nil table (the window before the first poll) makes repair 4 inert
// rather than failing, and counts nothing — the mechanism is absent, not missing.
func (r *Repairer) SetRouteTable(t *RouteTable) { r.routes.Store(t) }

// RouteTable returns the current pf state snapshot, which may be nil.
func (r *Repairer) RouteTable() *RouteTable { return r.routes.Load() }

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
		natSeen:    make(map[natKey]natSeenEntry),
		natConv:    make(map[routeKey]time.Time),
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
		// Repair 5 runs at RELEASE for a held record, not at arrival: the copy that
		// wins the VLAN contest is the one whose identity belongs in the NAT table.
		if !r.natAdmit(&h.rec, now) {
			continue
		}
		r.correctEgress(&h.rec, h.m)
		r.correctPolicyRoute(&h.rec, h.m)
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
	if !r.natAdmit(rec, now) {
		// Repair 5: the pre-NAT copy of this conversation is already through the
		// rollup. Emitting this one would count the same bytes twice (#623).
		return RepairDrop
	}
	r.correctEgress(rec, m)
	r.correctPolicyRoute(rec, m)
	r.setDirection(rec, m, snap)
	return RepairEmit
}

// Stats reports the repair stage's own accounting.
func (r *Repairer) Stats() RepairStats { return r.StatsAt(time.Now()) }

// StatsAt is Stats with the clock injected, so the table-age gauge is testable
// without sleeping.
func (r *Repairer) StatsAt(now time.Time) RepairStats {
	rt := r.routes.Load().Stats()
	nt := r.nats.Load().Stats()
	r.mu.Lock()
	defer r.mu.Unlock()
	return RepairStats{
		VLANDuplicatesDropped: r.vlanDropped,
		EgressCorrected:       r.egressCorrected,
		VLANChildPreferred:    r.childPreferred,
		VLANSubnetAttributed:  r.subnetAttrib,
		VLANLateChildCopies:   r.lateChildCopies,

		PolicyRouteCorrected:        r.policyRouteCorrected,
		PolicyRouteNoState:          r.policyRouteNoState,
		PolicyRouteUnresolvedDevice: r.policyRouteUnresolved,

		PolicyRouteSkippedNotWANEgress: r.prNotWANEgress.Load(),
		PolicyRouteSkippedPostNAT:      r.prPostNAT.Load(),
		PolicyRouteSkippedFIBAgreed:    r.prFIBAgreed.Load(),
		PolicyRouteSkippedAlreadyOnWAN: r.prAlreadyOnWAN.Load(),

		PolicyRouteNoStateByInterface:          copyCounts(r.policyRouteNoStateBy),
		PolicyRouteUnresolvedDeviceByInterface: copyCounts(r.policyRouteUnresolvedBy),

		RouteTableEntries:      rt.Entries,
		RouteTablePolicyRouted: rt.PolicyRouted,
		RouteTableSkipped:      rt.Skipped,
		RouteTableConflicts:    rt.Conflicts,
		RouteTableCarried:      rt.Carried,
		RouteTableAge:          r.routes.Load().Age(now),

		NATDuplicatesDropped:      r.natDuplicates,
		NATConversationDuplicates: r.natConvDuplicates,
		NATUnpaired:               r.natUnpaired,
		NATLatePreNATCopies:       r.natLatePreCopies,
		NATSeenEntries:            len(r.natSeen),
		NATSeenCapped:             r.natCapped,
		NATConversationEntries:    len(r.natConv),
		NATConversationCapped:     r.natConvCapped,
		NATTableEntries:           nt.Entries,
		NATTableCarried:           nt.Carried,
		NATTableConflicts:         nt.Conflicts,
		NATTableSkipped:           nt.Skipped,
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
	attributed := false
	if !parentCopy {
		// A' runs BEFORE the tables are consulted, so the record is compared and stored
		// under the interfaces it should have named all along. That is what makes the
		// outcome identical in both arrival orders: whichever copy lands first, the one
		// the de-dup table remembers names the child.
		//
		// After A, because A is strictly better where it applies: a tagged parent copy is
		// PROOF that a child copy exists, so dropping it costs nothing, while relabelling
		// it would leave two identical records to be deduped.
		attributed = attributeBySubnet(rec, m)
	}
	key := keyOf(rec)
	in, out := rec.In.Device, rec.Out.Device

	r.mu.Lock()
	defer r.mu.Unlock()
	r.expire(now)

	if parentCopy {
		r.vlanDropped++
		return RepairDrop
	}
	if attributed {
		r.subnetAttrib++
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
			if moreSpecific(in, out, prev.in, prev.out, m) {
				// THE RESIDUAL, AND WHY IT IS COUNTED RATHER THAN FIXED HERE. This copy
				// attributes the flow better than the one already in the table — but that one
				// has been EMITTED: it is through the rollup, counted, and shipped. Taking it
				// back is not possible, and emitting this copy as well would double-count real
				// bytes, which is a worse failure than a misattributed one because it is
				// invisible in the totals.
				//
				// So the honest fix is upstream, in A' above, which makes the incumbent
				// already-correct on first sight. This counter is what proves that: it was
				// ~29% of pairs before A' existed and should now move only for the addresses
				// subnet evidence legitimately refuses to resolve.
				r.lateChildCopies++
			}
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

// attributeBySubnet is mechanism A' (#465): when a record names a TRUNK on a side, and
// the address belonging to that side falls inside exactly one of the trunk's VLAN
// children's subnets, the record is relabelled onto that child immediately.
//
// WHY THIS EXISTS AT ALL. The hold contest (B) can only prefer the better copy when both
// copies are in flight inside vlanHoldWindow. #403's production measurement says that is
// true for 70.8% of real pairs: p50 gap 953.7ms, but p95 5.7s, p99 31.2s and a maximum
// of 108.5s. For the other 29.2% the trunk copy had already been released and the child
// copy was dropped as a duplicate — all 108,678 of them trunk-first, so the
// misattribution was systematic rather than a coin flip. Enlarging the window is not the
// lever: covering p99 needs ~31s, whose projected hold occupancy is far past maxHeld
// (measured peak was 2,115 of 10,000 at 2s), and past the cap the buffer degrades to
// first-seen-wins anyway; the observed max gap is also 90% of dedupeTTL, so a window
// pushed into the tail starts double-counting instead. Subnet evidence resolves on FIRST
// SIGHT, which removes the dependency on arrival order rather than improving the odds of
// beating it — 362,678 agreements with the hold contest's winner and ZERO disagreements
// across the whole unambiguous population.
//
// THE SIDE PAIRING IS PHYSICAL, not a choice. A record whose INGRESS is the trunk
// entered from the VLAN, so its SOURCE address is the VLAN host's; one whose EGRESS is
// the trunk is leaving toward the VLAN, so its DESTINATION is. Resolving a side from the
// other end's address would attribute the flow to whichever VLAN the far end sat on.
//
// A plain function, not a method: it touches only the record and the immutable topology,
// so it runs BEFORE admit takes the mutex and cannot contend with a concurrent copy. The
// counter it feeds is incremented inside the lock, with the rest of the accounting.
//
// It never drops, never guesses, and leaves the record untouched unless the evidence is
// unambiguous — VLANChildFor refuses anything matching zero or several children, and
// #403's scope is explicit that uncertain records are never dropped. What it cannot
// place keeps flowing into B exactly as before.
func attributeBySubnet(rec *Record, m ifTopology) bool {
	if m == nil {
		return false
	}
	// Both sides are attempted, and both may fire on one record: an inter-VLAN flow
	// reads in=trunk out=trunk, and its two ends belong to two different children.
	ingress := attributeSide(rec, &rec.In, rec.SrcAddr, m)
	egress := attributeSide(rec, &rec.Out, rec.DstAddr, m)
	return ingress || egress
}

// attributeSide relabels one side of the record, if the evidence names a child of the
// device that side currently claims.
//
// The HasVLANChildren gate is what stops this touching anything else: a side already
// naming a VLAN child is left alone (the child copy is ground truth, and re-resolving
// could only move it to a different child), and so is a WAN, a loopback, or any device
// on a box with no VLANs at all.
func attributeSide(rec *Record, side *Iface, addr netip.Addr, m ifTopology) bool {
	if side.Device == "" || !addr.IsValid() || !m.HasVLANChildren(side.Device) {
		return false
	}
	child, ok := m.VLANChildFor(side.Device, addr)
	if !ok || child.Device == side.Device {
		return false
	}
	// Corrected is deliberately NOT set. ifaceIsWAN reads it as proof that an interface
	// IS a WAN ("only repair 2 sets this, and only from the WAN table"), so setting it
	// on a VLAN child would make the direction rules treat an IOT interface as an
	// uplink. The relabel is recorded on the RECORD instead, which is a log attribute
	// and cannot be mistaken for topology.
	*side = child
	rec.Repairs.VLANSubnetAttributed = true
	return true
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

// correctPolicyRoute is repair 4 (#603).
//
// It runs AFTER repair 2 and BEFORE repair 3, and both halves of that order are
// load-bearing. After repair 2, because a post-NAT record repair 2 has already
// resolved from its source address needs nothing from pf and must not be looked up.
// Before repair 3, because direction inference reads the corrected egress.
//
// THE CANDIDATE SET is deliberately narrow, and narrowing it is what makes the miss
// counter mean anything. A record is a candidate only when:
//
//   - ng_netflow named a WAN as its egress — the population where OUTPUT_SNMP's FIB
//     answer can be wrong at all; and
//   - its SOURCE is not one of the firewall's own WAN addresses — i.e. it is the
//     PRE-NAT copy. The post-NAT copy's tuple appears in no direction="in" state, so
//     consulting the table for it would turn every WAN record into a phantom "no
//     state" and bury the real miss window.
//
// THE THREE OUTCOMES are counted apart because they have three different fixes: a
// correction (working as intended), no state at all (the expiry miss window, which
// no poll interval closes), and a route-to naming a device the interface map does
// not know (the enumeration is wrong). Nothing is ever guessed: a record whose
// answer is not exact is emitted exactly as ng_netflow reported it.
//
// Iface.Corrected is deliberately NOT set. ifaceIsWAN reads that flag as proof that
// an interface is a WAN BY CONSTRUCTION, an invariant repair 2 owns and direction
// inference depends on; a route-to device is a WAN in practice, but widening the flag
// here would silently widen that invariant. The marker lives on Repairs instead, and
// the direction rules learn the device through IfMap.IsWAN like any other WAN.
func (r *Repairer) correctPolicyRoute(rec *Record, m ifTopology) {
	table := r.routes.Load()
	if table == nil || m == nil || !rec.SrcAddr.IsValid() {
		return
	}
	if !ifaceIsWAN(m, rec.Out, rec.SrcAddr) {
		// Not leaving by a WAN; the FIB answer cannot be the multi-WAN bug. This is
		// the majority of records on any box and a healthy number, but it is also the
		// one place a WRONG interface map silently removes the whole repair, so it is
		// counted rather than merely returned from.
		r.prNotWANEgress.Add(1)
		return
	}
	if _, isPostNAT := m.WANFor(rec.SrcAddr); isPostNAT {
		r.prPostNAT.Add(1)
		return // repair 2's population, resolved from the source address already
	}

	device, ok := table.Egress(rec.Proto, rec.SrcAddr, rec.SrcPort, rec.DstAddr, rec.DstPort)
	if !ok {
		r.mu.Lock()
		r.policyRouteNoState++
		r.policyRouteNoStateBy = bumpByInterface(r.policyRouteNoStateBy, rec.Out)
		r.mu.Unlock()
		return
	}
	if device == "" {
		// pf used the FIB, which is precisely when OUTPUT_SNMP is already right. On a
		// mostly-single-WAN box this is the bulk of resolved lookups.
		r.prFIBAgreed.Add(1)
		return
	}
	if device == rec.Out.Device {
		// pf policy-routed it and ng_netflow already named the same device, so there
		// is nothing to correct. Distinguished from the FIB case because the two say
		// different things about whether the mechanism is earning its keep.
		r.prAlreadyOnWAN.Add(1)
		return
	}

	resolver, canResolve := m.(deviceResolver)
	if !canResolve {
		return
	}
	iface, known := resolver.IfaceForDevice(device)
	if !known {
		r.mu.Lock()
		r.policyRouteUnresolved++
		r.policyRouteUnresolvedBy = bumpByInterface(r.policyRouteUnresolvedBy, rec.Out)
		r.mu.Unlock()
		return
	}

	rec.Out = iface
	rec.Repairs.PolicyRouteCorrected = true
	r.mu.Lock()
	r.policyRouteCorrected++
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

// ---------------------------------------------------------------------------
// Repair 5: NAT-pair de-duplication (#623).
//
// The mechanism and every number behind it are documented in nattable.go. What
// lives here is the decision: WHICH copy is suppressed, and what happens in the
// order this cannot fix.
//
// ONLY THE POST-NAT COPY IS EVER SUPPRESSED. That is not arbitrary. The pre-NAT
// copy carries the LAN host's own 5-tuple, which is the only tuple Zenarmor ever
// saw, so it is the only copy that can reach a merged record. Suppressing it to
// keep the post-NAT one would trade a double count for a hole in correlation
// coverage, which is the worse of the two because it is invisible in the totals.
//
// THE RESIDUAL, COUNTED RATHER THAN HIDDEN. The pre-NAT copy arrives first in
// 89.2% of real pairs (356/399 measured). In the other 10.8% the post-NAT copy is
// already emitted — through the rollup, counted, shipped — by the time its twin
// lands, and it cannot be taken back. Suppressing the pre-NAT copy at that point
// would fix the byte total at the cost of the correlatable record, so the pair is
// emitted and counted as NATLatePreNATCopies instead. This is the same trade, for
// the same reason, as VLANLateChildCopies above.
//
// TWO PROOFS, NOT ONE (#636). A post-NAT copy is suppressed on either of:
//
//  1. EXACT EXPORT. The pre-NAT copy of this very export — same canonical tuple,
//     same bytes, same packets — is in natSeen. The strongest evidence there is, and
//     the only one #623 shipped.
//  2. CAPTURED CONVERSATION. A pre-NAT record for this canonical tuple has been seen
//     within natConversationTTL, so the LAN side of the conversation is
//     demonstrably being captured and its bytes reach the rollup by that copy.
//
// The second exists because the first cannot be sized. It assumes both copies are in
// flight together, and that held on the capture #623 measured — but that capture was
// taken with a 100 Mbit/s backup running over the policy-routed WAN, and the backup
// is what put enough flows on the WAN-side ng_netflow node to keep its export
// datagrams filling. Off that load the WAN node carries a handful of flows, its
// datagram does not fill, and it holds records until its own flush: measured at the
// socket on the production box, the LAN node exported every 324 s while the WAN node
// exported in batches ~609 s apart, giving pre->post arrival gaps of 266 s and 591 s
// against a 120 s window. Every pair missed. VIRGIN read 1.79x the kernel's own byte
// counter for three days while all five of repair 5's numbers looked healthy.
//
// The batching interval is set by the WAN node's flow RATE, which nothing here
// controls and which RISES as the box gets quieter — so no fixed window is safe, and
// widening the exact one only moves the failure. The second proof is not
// time-bounded in the same way: it asks a question about the conversation rather
// than about one export, and a live conversation refreshes its own entry.
//
// WHAT THE SECOND PROOF GIVES UP. #623's rule was "never drop what is not PROVEN a
// duplicate", where proof meant "I have already emitted these exact bytes". Proof 2
// is weaker: it infers that THIS export's twin exists from the fact that the
// conversation's other copies do. It is wrong only if the pre-NAT copy of this
// particular window never arrives — a lost datagram — in which case that window's
// bytes are under-counted instead of double-counted. That is the better failure of
// the two, and it is rarer than the one it replaces.

// natKey is the CANONICAL identity of one export: the pre-NAT directional tuple
// plus the volume, and DELIBERATELY NOT the timestamps.
//
// instanceKey next door includes First/Last because the two copies it compares are
// produced by ONE expiry sweep and agree on them exactly. These two are produced by
// two INDEPENDENT ng_netflow nodes with their own timers, and measured against a
// live box only 244 of 399 real pairs (61%) agreed on both. Keying on them would
// silently miss two pairs in five.
//
// The volume stays, and does the work the timestamps used to: NAT does not change
// the size of a packet, so bytes and packets are conserved across the translation —
// 399 of 399 pairs matched both EXACTLY. It is what stops two different exports of
// one long-lived conversation, which share a tuple, from being folded together.
type natKey struct {
	canon       routeKey
	bytes, pkts uint64
}

// natRole records which side of a pair an entry was.
type natRole uint8

const (
	// natRolePre is a record emitted under its own (pre-NAT) tuple. A post-NAT copy
	// finding one of these is a proven duplicate.
	natRolePre natRole = iota
	// natRolePost is a post-NAT copy emitted because its twin had not arrived. It
	// exists ONLY so the late twin is countable; it never suppresses anything.
	natRolePost
)

type natSeenEntry struct {
	role natRole
	seen time.Time
}

// SetNATTable publishes a new NAT translation index. Safe to call while records are
// in flight; a nil table makes repair 5 inert rather than failing.
func (r *Repairer) SetNATTable(t *NATTable) { r.nats.Store(t) }

// NATTable returns the current NAT translation index, which may be nil.
func (r *Repairer) NATTable() *NATTable { return r.nats.Load() }

// natAdmit reports whether a record should be emitted, suppressing it when it is the
// post-NAT copy of a conversation already emitted from its pre-NAT side.
//
// It runs at the point a record is decided to be EMITTED — after repair 1 has
// resolved the VLAN contest — so a held record is considered when it is released
// rather than when it arrived, and a copy that loses the VLAN contest is never
// entered here at all.
func (r *Repairer) natAdmit(rec *Record, now time.Time) bool {
	t := r.nats.Load()
	if t == nil {
		// No snapshot yet, or a box whose pf table records no translations. Nothing
		// can be identified as a post-NAT copy, so remembering anything would be pure
		// cost. The mechanism is absent, not failing.
		return true
	}
	own, ok := tupleOfRecord(rec)
	if !ok {
		return true
	}
	bytes, packets := volumeOf(*rec)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.natExpire(now)
	r.natConvExpire(now)

	if canon, isPost := t.Canonical(own); isPost {
		k := natKey{canon: canon, bytes: bytes, pkts: packets}
		if e, seen := r.natSeen[k]; seen && e.role == natRolePre {
			// The pre-NAT copy of this EXACT export has already been emitted. These are
			// the same bytes; counting them again is the whole bug.
			delete(r.natSeen, k)
			r.natDuplicates++
			return false
		}
		if _, captured := r.natConv[canon]; captured {
			// The exact twin is gone — expired, or split differently by the two nodes —
			// but this conversation's LAN side is demonstrably being captured, so its
			// bytes reach the rollup by the pre-NAT copy whether or not that copy is
			// still in natSeen. Emitting this one counts them twice.
			r.natConvDuplicates++
			return false
		}
		// Not proven a duplicate by either test. Emit — never drop what is not proven —
		// and leave a marker so that if the twin does arrive the residual is visible.
		r.natRemember(k, natRolePost, now)
		r.natUnpaired++
		return true
	}

	if !couldBeTranslated(rec) {
		// Both ends private, or neither: this record can have no post-NAT twin, so
		// remembering it would only fill the table. Internal traffic is the bulk of
		// most boxes' records and none of it is ever translated.
		return true
	}
	// Whatever happens below, this record is evidence that the LAN side of its
	// conversation is being captured — but only worth keeping if pf says the
	// conversation is translated at all, which is what bounds the table.
	if t.IsTranslatedPre(own) {
		r.natConvRemember(own, now)
	}
	k := natKey{canon: own, bytes: bytes, pkts: packets}
	if e, seen := r.natSeen[k]; seen && e.role == natRolePost {
		// The post-NAT copy went out first and is already shipped. Emitting this one
		// double-counts, suppressing it loses the only correlatable copy; the residual
		// is counted instead. See the block comment above.
		delete(r.natSeen, k)
		r.natLatePreCopies++
		return true
	}
	r.natRemember(k, natRolePre, now)
	return true
}

// natConversationTTL bounds how long a conversation stays answerable as "captured
// on its LAN side".
//
// It is NOT dedupeTTL and must not be folded into it. dedupeTTL bounds a window in
// which two copies of ONE EXPORT are both in flight, and its two minutes were sized
// against copies separated by datagram scheduling. This bounds a window in which a
// CONVERSATION is still live, and the thing it has to outlast is the WAN-side
// ng_netflow node's export batching.
//
// Fifteen minutes, from measurement (#636). On the production box the LAN node
// exported every 324 s, promptly at each window's close, while the WAN node — which
// carries a handful of flows, so its datagram does not fill — exported in batches
// ~609 s apart, two windows at a time. Observed pre->post arrival gaps were 266 s
// and 591 s. Fifteen minutes is 1.5x the worst measured gap, and the gap grows as
// the WAN gets quieter, which is why the exact-export path alone could never be
// sized safely: nothing here controls the WAN node's flow rate.
const natConversationTTL = 15 * time.Minute

// natConvSweepInterval bounds how often the conversation table is swept.
//
// It has no order slice to scan, because entries are REFRESHED on every pre-NAT
// record of the conversation — that refresh is what keeps a long-lived conversation
// answerable, and it is exactly what would break insertion-order-is-age-order. So
// expiry is a full walk, and a walk on every record would put an O(entries) scan on
// the hot path. Once a second against a table of a few thousand is negligible, and
// the cost of a stale entry lingering up to a second past its TTL is nil.
const natConvSweepInterval = time.Second

// natConvRemember records that a conversation's pre-NAT side has been seen, or
// refreshes it. Callers hold mu.
//
// At capacity it declines to add rather than evicting: a missing entry costs a
// missed de-duplication, which shows up as an over-count against the interface
// counter, while evicting somebody else's live conversation would cost the same
// thing plus the entry. Refreshing an EXISTING entry is always allowed — it takes no
// new space, and it is the case that matters most.
func (r *Repairer) natConvRemember(canon routeKey, now time.Time) {
	if _, exists := r.natConv[canon]; !exists {
		if r.maxEntries > 0 && len(r.natConv) >= r.maxEntries {
			r.natConvCapped++
			return
		}
	}
	r.natConv[canon] = now
}

// natConvExpire drops conversations untouched for natConversationTTL. Callers hold
// mu.
func (r *Repairer) natConvExpire(now time.Time) {
	if len(r.natConv) == 0 {
		return
	}
	if !r.natConvSwept.IsZero() && now.Sub(r.natConvSwept) < natConvSweepInterval {
		return
	}
	r.natConvSwept = now
	cutoff := now.Add(-natConversationTTL)
	for k, seen := range r.natConv {
		if !seen.After(cutoff) {
			delete(r.natConv, k)
		}
	}
}

// couldBeTranslated reports whether a record has the shape of one side of a NAT'd
// conversation: exactly one endpoint on a private address.
//
// A cheap address test rather than a table lookup, so it cannot go stale. It is
// deliberately conservative — a box translating a public range is not recognised, and
// the cost of that is a double count, which shows up against the interface counter,
// rather than a suppressed record, which would not.
func couldBeTranslated(rec *Record) bool {
	return rec.SrcAddr.Unmap().IsPrivate() != rec.DstAddr.Unmap().IsPrivate()
}

// tupleOfRecord is the record's own directional 5-tuple in the shape the pf tables
// key by.
func tupleOfRecord(rec *Record) (routeKey, bool) {
	src, dst := rec.SrcAddr.Unmap(), rec.DstAddr.Unmap()
	if !src.IsValid() || !dst.IsValid() {
		return routeKey{}, false
	}
	return routeKey{proto: rec.Proto, src: src, dst: dst, sport: rec.SrcPort, dport: rec.DstPort}, true
}

// natRemember records a canonical identity, making room first if the table is full.
// Callers hold mu.
//
// An existing entry is left ALONE rather than refreshed, exactly as insert does, so
// insertion order stays age order and the expiry scan can stop at the first live
// entry.
func (r *Repairer) natRemember(k natKey, role natRole, now time.Time) {
	if _, exists := r.natSeen[k]; exists {
		return
	}
	if r.maxEntries > 0 && len(r.natSeen) >= r.maxEntries {
		r.natDropOldest()
		r.natCapped++
	}
	r.natSeen[k] = natSeenEntry{role: role, seen: now}
	r.natOrder = append(r.natOrder, k)
}

// natExpire drops entries past dedupeTTL. Callers hold mu.
//
// It shares the instance table's TTL rather than defining its own, and that is a
// measurement, not a convenience: the arrival gap between the two copies of a NAT
// pair is p50 20s, p90 49s, p99 60s on the reference box, so two minutes pairs 99.7%
// of them. The one pair in the sample that exceeded it was 7m11s apart, and buying it
// would mean holding every record's identity for eight minutes.
func (r *Repairer) natExpire(now time.Time) {
	cutoff := now.Add(-dedupeTTL)
	for r.natHead < len(r.natOrder) {
		k := r.natOrder[r.natHead]
		e, ok := r.natSeen[k]
		if ok && e.seen.After(cutoff) {
			break
		}
		if ok {
			delete(r.natSeen, k)
		}
		r.natHead++
	}
	r.natCompact()
}

// natDropOldest evicts the oldest entry to make room. Callers hold mu.
func (r *Repairer) natDropOldest() {
	for r.natHead < len(r.natOrder) {
		k := r.natOrder[r.natHead]
		r.natHead++
		if _, ok := r.natSeen[k]; ok {
			delete(r.natSeen, k)
			return
		}
	}
}

// natCompact reclaims the consumed prefix of natOrder, on the same terms as compact.
func (r *Repairer) natCompact() {
	if r.natHead == 0 {
		return
	}
	if r.natHead < len(r.natOrder)/2 {
		return
	}
	r.natOrder = append(r.natOrder[:0], r.natOrder[r.natHead:]...)
	r.natHead = 0
}
