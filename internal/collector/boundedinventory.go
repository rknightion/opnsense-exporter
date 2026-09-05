package collector

import (
	"cmp"
	"slices"
	"time"
)

// inventoryEntry is one live entity as returned to a caller: its identity and its
// current attributes.
type inventoryEntry[K comparable, V any] struct {
	key K
	val V
}

// inventoryRecord is what the map stores: the entity's current attributes plus when
// it was last seen.
type inventoryRecord[V any] struct {
	val  V
	last time.Time
	cost int
}

// boundedInventory is a set of currently-known entities with an insert-time key
// budget AND a last-seen expiry. It backs `*_info` metrics — one series per live
// entity, value 1, labels as the payload — where cappedCounter cannot be used.
//
// The difference from cappedCounter is expiry, and it is the whole reason this type
// exists. A counter is cumulative: a key that stops being observed must keep its
// total, so the map never shrinks and a budget alone is a permanent one-way ratchet.
// An inventory answers "what is here NOW", so a key that stops being observed should
// leave — and once it leaves, its budget slot must come back. Without that, a single
// burst of churn wedges the inventory for the life of the process and a genuinely new
// entity never appears again. TestBoundedInventory_ExpiryFreesBudget pins it.
//
// IDENTITY IS THE KEY; EVERYTHING ELSE OBSERVED ABOUT THE ENTITY IS THE VALUE (#476).
// That split is not cosmetic. The first version made every observed attribute part of
// the key, so an attribute that changed over time forked the entity into two rows
// rather than updating one: a Zenarmor device seen once before the enrichment snapshot
// had loaded and again afterwards appeared twice, as `ixl0` and as `LAN`, and the
// stale row sat out its full 24h TTL. Anything that can legitimately change while the
// entity remains the same entity belongs in V.
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
type boundedInventory[K comparable, V any] struct {
	m   map[K]inventoryRecord[V]
	max int
	ttl time.Duration
	// order gives live() a deterministic sequence over the KEY. It is a parameter
	// rather than a cmp.Ordered constraint because a key may be a struct tuple, which
	// no ordering constraint in the standard library covers.
	order func(a, b K) int
	// refusals counts novel keys turned away by the budget. Emitted as a counter, so
	// a float64 for the same reason cappedCounter's overflow is.
	refusals float64
	bytes    int
	// Conservative earliest expiry avoids scanning a full, entirely live map
	// on every rejected sighting. Refreshes may leave this earlier than reality.
	nextExpiry time.Time
}

func newBoundedInventory[K comparable, V any](max int, ttl time.Duration, order func(a, b K) int) *boundedInventory[K, V] {
	return &boundedInventory[K, V]{m: map[K]inventoryRecord[V]{}, max: max, ttl: ttl, order: order}
}

// seen records a sighting of k carrying attributes v, LAST WRITE WINS. A key already
// tracked is always refreshed — both its attributes and its clock — even at the cap:
// steady-state traffic must not be starved by a burst of novelty, and an entity whose
// attributes keep changing must not expire on its first sighting's timestamp.
// max <= 0 disables the budget, matching cappedCounter.
func (b *boundedInventory[K, V]) seen(k K, v V, now time.Time) {
	old, exists := b.m[k]
	cost, valid := retainedStringBytes(k, v)
	if !valid {
		b.refusals++
		return
	}
	if b.bytes-old.cost+cost > maxRetainedFamilyBytes || (!exists && b.max > 0 && len(b.m) >= b.max) {
		if !now.Before(b.nextExpiry) {
			b.prune(now)
			old, exists = b.m[k]
		}
	}
	if b.bytes-old.cost+cost > maxRetainedFamilyBytes || (!exists && b.max > 0 && len(b.m) >= b.max) {
		b.refusals++
		return
	}
	b.bytes = b.bytes - old.cost + cost
	b.m[k] = inventoryRecord[V]{val: v, last: now, cost: cost}
	expiry := now.Add(b.ttl)
	if b.nextExpiry.IsZero() || expiry.Before(b.nextExpiry) {
		b.nextExpiry = expiry
	}
}

func (b *boundedInventory[K, V]) prune(now time.Time) {
	b.nextExpiry = time.Time{}
	for k, rec := range b.m {
		if now.Sub(rec.last) >= b.ttl {
			b.bytes -= rec.cost
			delete(b.m, k)
			continue
		}
		expiry := rec.last.Add(b.ttl)
		if b.nextExpiry.IsZero() || expiry.Before(b.nextExpiry) {
			b.nextExpiry = expiry
		}
	}
}

// live prunes everything not seen within the TTL and returns what remains, ordered by
// key.
//
// It PRUNES rather than filters — expired entries are deleted from the map, not merely
// skipped — because that is what returns their budget slots and what keeps the map
// from growing forever. Ordered output keeps a scrape's series order stable, so a diff
// of two scrapes shows real changes only.
func (b *boundedInventory[K, V]) live(now time.Time) []inventoryEntry[K, V] {
	b.prune(now)
	out := make([]inventoryEntry[K, V], 0, len(b.m))
	for k, rec := range b.m {
		out = append(out, inventoryEntry[K, V]{key: k, val: rec.val})
	}
	slices.SortFunc(out, func(x, y inventoryEntry[K, V]) int { return b.order(x.key, y.key) })
	return out
}

// refused reports the running count of novel keys the budget turned away.
func (b *boundedInventory[K, V]) refused() float64 { return b.refusals }

// len reports the tracked key count, INCLUDING any not yet pruned by a live() call.
func (b *boundedInventory[K, V]) len() int { return len(b.m) }

// zenDeviceAttrs are the observed properties of a Zenarmor device. They are the
// inventory's VALUE, never part of its key: both can change while the device stays the
// same device — interface when it moves segment or when enrichment resolves it late,
// category when Zenarmor reclassifies it — and keying on them forked one device into
// two series (#476). See the type comment above.
type zenDeviceAttrs struct{ category, iface string }

// compareZenDeviceName orders the device inventory by name, which is its identity.
func compareZenDeviceName(a, b string) int { return cmp.Compare(a, b) }
