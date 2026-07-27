package collector

import (
	"cmp"
	"slices"
	"time"
)

// boundedInventory is a set of currently-known entities with an insert-time key
// budget AND a last-seen expiry. It backs `*_info` metrics — one series per live
// entity, value 1 — where cappedCounter cannot be used.
//
// The difference from cappedCounter is expiry, and it is the whole reason this type
// exists. A counter is cumulative: a key that stops being observed must keep its
// total, so the map never shrinks and a budget alone is a permanent one-way ratchet.
// An inventory answers "what is here NOW", so a key that stops being observed should
// leave — and once it leaves, its budget slot must come back. Without that, a single
// burst of churn wedges the inventory for the life of the process and a genuinely new
// entity never appears again. TestBoundedInventory_ExpiryFreesBudget pins it.
//
// Both bounds are load-bearing on their own:
//
//   - The CAP bounds memory and series against a novel key that arrives faster than
//     the TTL retires one. Refusals are counted, never silent, for the same reason
//     cappedCounter folds into an overflow total: a quietly truncated inventory looks
//     exactly like a small network.
//   - The TTL bounds a key that arrives once and never again. Prometheus would
//     otherwise carry it as a live series forever, which for a device inventory means
//     a laptop that visited once still reads as present.
//
// Not safe for concurrent use on its own: every caller in this package runs on
// LogEventStore's map-owning goroutine, and taking a lock here would buy nothing.
type boundedInventory[K comparable] struct {
	m   map[K]time.Time // key -> last seen
	max int
	ttl time.Duration
	// order gives live() a deterministic sequence. It is a parameter rather than a
	// cmp.Ordered constraint because the real key is a struct tuple, which no
	// ordering constraint in the standard library covers.
	order func(a, b K) int
	// refusals counts novel keys turned away by the budget. Emitted as a counter, so
	// a float64 for the same reason cappedCounter's overflow is.
	refusals float64
}

func newBoundedInventory[K comparable](max int, ttl time.Duration, order func(a, b K) int) *boundedInventory[K] {
	return &boundedInventory[K]{m: map[K]time.Time{}, max: max, ttl: ttl, order: order}
}

// seen records a sighting of k. A key already tracked is always refreshed, even at
// the cap: steady-state traffic must not be starved by a burst of novelty. max <= 0
// disables the budget, matching cappedCounter.
func (b *boundedInventory[K]) seen(k K, now time.Time) {
	if _, ok := b.m[k]; !ok && b.max > 0 && len(b.m) >= b.max {
		b.refusals++
		return
	}
	b.m[k] = now
}

// live prunes everything not seen within the TTL and returns what remains, sorted.
//
// It PRUNES rather than filters — the expired entries are deleted from the map, not
// merely skipped — because that is what returns their budget slots and what keeps the
// map from growing forever. Sorted output keeps a scrape's series order stable, so a
// diff of two scrapes shows real changes only.
func (b *boundedInventory[K]) live(now time.Time) []K {
	out := make([]K, 0, len(b.m))
	for k, last := range b.m {
		if now.Sub(last) >= b.ttl {
			delete(b.m, k)
			continue
		}
		out = append(out, k)
	}
	slices.SortFunc(out, b.order)
	return out
}

// refused reports the running count of novel keys the budget turned away.
func (b *boundedInventory[K]) refused() float64 { return b.refusals }

// len reports the tracked key count, INCLUDING any not yet pruned by a live() call.
func (b *boundedInventory[K]) len() int { return len(b.m) }

// compareZenDeviceKey orders the device inventory by name, then category, then
// interface — the order a reader of the emitted series would expect.
func compareZenDeviceKey(a, b zenDeviceKey) int {
	if c := cmp.Compare(a.name, b.name); c != 0 {
		return c
	}
	if c := cmp.Compare(a.category, b.category); c != 0 {
		return c
	}
	return cmp.Compare(a.iface, b.iface)
}
