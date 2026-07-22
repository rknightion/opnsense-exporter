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

// DistinctDests counts the distinct destination addresses seen per interface — the
// bounded stand-in for a per-destination series (§9): one gauge per interface, never
// one per destination, so the cardinality stays with the interface set instead of
// tracking the open internet.
//
// A set, not a sum, so it is immune to the cross-source double-count that the byte
// counters carry: the same destination reported by both the NetFlow and Zenarmor
// lanes collapses to one set entry, where summing its bytes would count it twice.
type DistinctDests struct {
	mu    sync.Mutex
	cells map[string]map[netip.Addr]struct{}
}

// NewDistinctDests returns an empty counter.
func NewDistinctDests() *DistinctDests {
	return &DistinctDests{cells: make(map[string]map[netip.Addr]struct{})}
}

// Observe records this record's destination against its interface. At the per-
// interface cap it stops inserting rather than evicting, so an established set is
// never thrashed by a burst of novel destinations. Safe for concurrent callers.
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

	set := d.cells[iface]
	if set == nil {
		set = make(map[netip.Addr]struct{})
		d.cells[iface] = set
	}
	if _, ok := set[dst]; ok {
		return
	}
	if len(set) >= distinctDestsPerIfaceCap {
		return
	}
	set[dst] = struct{}{}
}

// Snapshot returns the current distinct-destination count per interface.
func (d *DistinctDests) Snapshot() map[string]int {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := make(map[string]int, len(d.cells))
	for iface, set := range d.cells {
		out[iface] = len(set)
	}
	return out
}
