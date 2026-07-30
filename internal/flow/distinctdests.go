package flow

import (
	"net/netip"
	"sync"
)

// distinctDestsPerIfaceCap bounds the distinct-destination set PER interface. A LAN
// interface whose host is scanning or running a busy P2P client legitimately reaches
// thousands of destinations, so the cap is generous; past it the gauge pins at the
// cap rather than growing without bound, and a pinned value is itself the signal that
// the true count is at least this high. Ten interfaces at this cap is a few MB of
// addresses worst case — the memory ceiling that keeps an unauthenticated NetFlow
// flood from growing the set forever.
const distinctDestsPerIfaceCap = 10000

// distinctDestsMaxInterfaces bounds the OUTER interface-key set, i.e. how many
// distinct interface cells this counter will ever hold at once (#563).
//
// Zenarmor controls the `interface` and `vlanid` strings that key this map (they
// flow in from internal/logship/zenarmor/parse.go and flowadapt.go), and the
// per-interface cap above only bounds destinations INSIDE a cell — nothing
// previously bounded the number of cells. An admitted or compromised sender could
// therefore mint one process-lifetime map entry and one extra
// opnsense_flow_distinct_destinations series per novel interface/VLAN combination it
// chose to send; a validation run against clean main produced exactly 20,000
// interface cells from a single destination.
//
// Sized generously above any real deployment, not down toward cardinality scarcity
// (the exporter runs ~4.6k of a 100k global series budget): even a heavily VLANed
// box — a few dozen physical interfaces times a few dozen VLAN children each — lands
// in the low hundreds of distinct labels. 512 comfortably covers that while still
// giving an attacker a fixed, small ceiling instead of an open one.
const distinctDestsMaxInterfaces = 512

// DistinctDests counts the distinct destination addresses seen per interface — the
// bounded stand-in for a per-destination series (§9): one gauge per interface, never
// one per destination, so the cardinality stays with the interface set instead of
// tracking the open internet.
//
// A set, not a sum, so it is immune to the cross-source double-count that the byte
// counters carry: the same destination reported by both the NetFlow and Zenarmor
// lanes collapses to one set entry, where summing its bytes would count it twice.
type DistinctDests struct {
	mu     sync.Mutex
	cells  map[string]map[netip.Addr]struct{}
	capped uint64 // observations folded into OtherLabel because a novel interface arrived at the ceiling
}

// NewDistinctDests returns an empty counter.
func NewDistinctDests() *DistinctDests {
	return &DistinctDests{cells: make(map[string]map[netip.Addr]struct{})}
}

// Observe records this record's destination against its interface. At the per-
// interface cap it stops inserting rather than evicting, so an established set is
// never thrashed by a burst of novel destinations. Safe for concurrent callers.
//
// Once distinctDestsMaxInterfaces distinct interface cells already exist, a genuinely
// novel interface label folds into the fixed OtherLabel bucket (the same convention
// rollup.go uses for its own overflow) rather than minting another
// process-lifetime cell keyed by a sender-controlled string. The fold is counted in
// capped, never the rejected label itself — the label that pushed a sender over the
// ceiling is exactly the value this bound exists to stop trusting.
func (d *DistinctDests) Observe(r Record) {
	if !r.DstAddr.IsValid() {
		return
	}
	iface := interfaceLabel(r)
	if iface == "" {
		return
	}
	dst := r.DstAddr.Unmap()

	d.mu.Lock()
	defer d.mu.Unlock()

	set, ok := d.cells[iface]
	if !ok {
		if iface != OtherLabel && len(d.cells) >= distinctDestsMaxInterfaces {
			d.capped++
			iface = OtherLabel
			set, ok = d.cells[iface]
		}
		if !ok {
			set = make(map[netip.Addr]struct{})
			d.cells[iface] = set
		}
	}
	if _, ok := set[dst]; ok {
		return
	}
	if len(set) >= distinctDestsPerIfaceCap {
		return
	}
	set[dst] = struct{}{}
}

// Snapshot returns the current distinct-destination count per interface. Beyond the
// interface budget, everything folds into the OtherLabel key rather than growing the
// map further.
func (d *DistinctDests) Snapshot() map[string]int {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := make(map[string]int, len(d.cells))
	for iface, set := range d.cells {
		out[iface] = len(set)
	}
	return out
}

// DistinctDestsStats is the counter's own health, mirroring RollupStats: how many
// interface cells are live against the configured budget, and how many observations
// have been folded into OtherLabel because a novel interface arrived at the ceiling.
// Without this an operator cannot distinguish "every real interface fits comfortably"
// from "the budget saturated and new interfaces have been invisible since".
type DistinctDestsStats struct {
	Interfaces    int
	MaxInterfaces int
	Capped        uint64
}

// Stats returns the counter's current health.
func (d *DistinctDests) Stats() DistinctDestsStats {
	d.mu.Lock()
	defer d.mu.Unlock()

	return DistinctDestsStats{
		Interfaces:    len(d.cells),
		MaxInterfaces: distinctDestsMaxInterfaces,
		Capped:        d.capped,
	}
}
