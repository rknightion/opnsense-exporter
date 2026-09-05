package collector

import (
	"cmp"
	"slices"
	"testing"
	"time"
)

func at(sec int) time.Time { return time.Unix(int64(sec), 0).UTC() }

// The everyday case: repeated sightings of the same entity are one entry, and the
// entry stays live for as long as it keeps being seen.
func TestBoundedInventory_RefreshKeepsAnEntryLive(t *testing.T) {
	inv := newBoundedInventory[string, struct{}](8, 100*time.Second, cmp.Compare[string])

	inv.seen("a", struct{}{}, at(0))
	inv.seen("a", struct{}{}, at(90))
	if got := keysOf(inv.live(at(150))); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("live = %v, want [a] — a refreshed entry must not expire on its FIRST sighting's clock", got)
	}
	// ...and it does expire once it genuinely goes quiet.
	if got := keysOf(inv.live(at(200))); len(got) != 0 {
		t.Fatalf("live = %v, want empty — the entry went quiet more than one TTL ago", got)
	}
}

func TestBoundedInventory_ExpiresIndependently(t *testing.T) {
	inv := newBoundedInventory[string, struct{}](8, 100*time.Second, cmp.Compare[string])
	inv.seen("stale", struct{}{}, at(0))
	inv.seen("fresh", struct{}{}, at(80))

	got := keysOf(inv.live(at(120)))
	if !slices.Equal(got, []string{"fresh"}) {
		t.Fatalf("live = %v, want [fresh] only", got)
	}
	if n := inv.len(); n != 1 {
		t.Errorf("len = %d after expiry, want 1 — live() must PRUNE, not merely filter, or the map grows forever", n)
	}
}

// The cap is the guard against a churning DNS-derived name — the exact failure mode
// #474 exists to prevent. A novel key past the budget is refused and COUNTED, never
// silently dropped.
func TestBoundedInventory_CapRefusesNovelKeysAndCountsThem(t *testing.T) {
	inv := newBoundedInventory[string, struct{}](2, 100*time.Second, cmp.Compare[string])
	inv.seen("a", struct{}{}, at(0))
	inv.seen("b", struct{}{}, at(0))
	inv.seen("c", struct{}{}, at(0))
	inv.seen("d", struct{}{}, at(0))

	if got := keysOf(inv.live(at(1))); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("live = %v, want [a b] — the budget admits the first arrivals", got)
	}
	if got := inv.refused(); got != 2 {
		t.Errorf("refused = %v, want 2 — saturation must be visible, not silent", got)
	}
	// An entry already tracked keeps being refreshed even at the cap: steady-state
	// traffic must not be starved by a burst of novelty.
	inv.seen("a", struct{}{}, at(50))
	if got := keysOf(inv.live(at(120))); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("live = %v, want [a] — a tracked key must still refresh while the budget is met", got)
	}
}

// Expiry must free budget, or a single burst of churn wedges the inventory for the
// life of the process and a genuinely new device never appears again.
func TestBoundedInventory_ExpiryFreesBudget(t *testing.T) {
	inv := newBoundedInventory[string, struct{}](2, 100*time.Second, cmp.Compare[string])
	inv.seen("a", struct{}{}, at(0))
	inv.seen("b", struct{}{}, at(0))
	inv.seen("late", struct{}{}, at(0)) // refused, budget met

	// Both originals go quiet and are pruned...
	if got := keysOf(inv.live(at(200))); len(got) != 0 {
		t.Fatalf("live = %v, want empty", got)
	}
	// ...so the slot is available again.
	inv.seen("late", struct{}{}, at(210))
	if got := keysOf(inv.live(at(220))); !slices.Equal(got, []string{"late"}) {
		t.Fatalf("live = %v, want [late] — expiry must return budget", got)
	}
}

// A device may be seen only once between snapshots. Expired entries must not
// consume the admission budget until a later live() call discards them.
func TestBoundedInventory_AdmissionReclaimsExpiredEntries(t *testing.T) {
	inv := newBoundedInventory[string, string](2, 100*time.Second, cmp.Compare[string])
	inv.seen("expired", "old", at(0))
	inv.seen("current", "kept", at(80))
	inv.seen("visitor", "new", at(100))
	if got := keysOf(inv.live(at(100))); !slices.Equal(got, []string{"current", "visitor"}) {
		t.Fatalf("live = %v, want [current visitor]; expired state must not reject a one-time sighting", got)
	}
	if inv.refused() != 0 {
		t.Fatalf("refused = %v, want 0", inv.refused())
	}
	wantBytes, _ := retainedStringBytes("current", "kept", "visitor", "new")
	if inv.bytes != wantBytes {
		t.Fatalf("retained bytes = %d, want %d", inv.bytes, wantBytes)
	}
}

// live() is emitted straight into Prometheus metrics, and a scrape that reorders its
// series for no reason is noise in every diff.
func TestBoundedInventory_LiveIsSorted(t *testing.T) {
	inv := newBoundedInventory[string, struct{}](8, 100*time.Second, cmp.Compare[string])
	for _, k := range []string{"delta", "alpha", "charlie", "bravo"} {
		inv.seen(k, struct{}{}, at(0))
	}
	got := keysOf(inv.live(at(1)))
	if !slices.Equal(got, []string{"alpha", "bravo", "charlie", "delta"}) {
		t.Fatalf("live = %v, want sorted", got)
	}
}

// A zero cap disables the budget, matching cappedCounter's max <= 0 contract.
func TestBoundedInventory_ZeroCapDisablesTheBudget(t *testing.T) {
	inv := newBoundedInventory[int, struct{}](0, 100*time.Second, cmp.Compare[int])
	for i := range 1000 {
		inv.seen(i, struct{}{}, at(0))
	}
	if n := inv.len(); n != 1000 {
		t.Fatalf("len = %d, want 1000 — max <= 0 must disable the cap", n)
	}
	if got := inv.refused(); got != 0 {
		t.Errorf("refused = %v, want 0", got)
	}
}

// keysOf reduces entries to their keys, for the tests above that only care about
// membership and ordering.
func keysOf[K comparable, V any](entries []inventoryEntry[K, V]) []K {
	out := make([]K, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.key)
	}
	return out
}

// The #476 defect, at the primitive level: an attribute that changes over time must
// UPDATE the entity's entry, not fork a second one. Before this, interface was part
// of the key, so one device seen before and after the enrichment snapshot loaded
// produced two rows — one saying ixl0, one saying LAN — and the stale one sat out the
// full TTL.
func TestBoundedInventory_ValueIsLastWriteWinsNotASecondEntry(t *testing.T) {
	inv := newBoundedInventory[string, string](8, 100*time.Second, cmp.Compare[string])

	inv.seen("jules", "ixl0", at(0)) // seen before enrichment resolved
	inv.seen("jules", "LAN", at(10)) // ...and again once it had

	got := inv.live(at(20))
	if len(got) != 1 {
		t.Fatalf("live = %v, want exactly one entry — a changed attribute must not fork the entity", got)
	}
	if got[0].key != "jules" || got[0].val != "LAN" {
		t.Fatalf("entry = %+v, want jules/LAN — the most recent sighting wins", got[0])
	}
}

// Refreshing the value must also refresh the clock, or a device whose interface keeps
// changing would expire on its first sighting's timestamp.
func TestBoundedInventory_ValueUpdateRefreshesTheClock(t *testing.T) {
	inv := newBoundedInventory[string, string](8, 100*time.Second, cmp.Compare[string])
	inv.seen("dev", "LAN", at(0))
	inv.seen("dev", "IOT", at(90))
	if got := inv.live(at(150)); len(got) != 1 {
		t.Fatalf("live = %v, want the entry still alive 60s after its latest sighting", got)
	}
}
