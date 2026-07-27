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
	inv := newBoundedInventory(8, 100*time.Second, cmp.Compare[string])

	inv.seen("a", at(0))
	inv.seen("a", at(90))
	if got := inv.live(at(150)); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("live = %v, want [a] — a refreshed entry must not expire on its FIRST sighting's clock", got)
	}
	// ...and it does expire once it genuinely goes quiet.
	if got := inv.live(at(200)); len(got) != 0 {
		t.Fatalf("live = %v, want empty — the entry went quiet more than one TTL ago", got)
	}
}

func TestBoundedInventory_ExpiresIndependently(t *testing.T) {
	inv := newBoundedInventory(8, 100*time.Second, cmp.Compare[string])
	inv.seen("stale", at(0))
	inv.seen("fresh", at(80))

	got := inv.live(at(120))
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
	inv := newBoundedInventory(2, 100*time.Second, cmp.Compare[string])
	inv.seen("a", at(0))
	inv.seen("b", at(0))
	inv.seen("c", at(0))
	inv.seen("d", at(0))

	if got := inv.live(at(1)); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("live = %v, want [a b] — the budget admits the first arrivals", got)
	}
	if got := inv.refused(); got != 2 {
		t.Errorf("refused = %v, want 2 — saturation must be visible, not silent", got)
	}
	// An entry already tracked keeps being refreshed even at the cap: steady-state
	// traffic must not be starved by a burst of novelty.
	inv.seen("a", at(50))
	if got := inv.live(at(120)); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("live = %v, want [a] — a tracked key must still refresh while the budget is met", got)
	}
}

// Expiry must free budget, or a single burst of churn wedges the inventory for the
// life of the process and a genuinely new device never appears again.
func TestBoundedInventory_ExpiryFreesBudget(t *testing.T) {
	inv := newBoundedInventory(2, 100*time.Second, cmp.Compare[string])
	inv.seen("a", at(0))
	inv.seen("b", at(0))
	inv.seen("late", at(0)) // refused, budget met

	// Both originals go quiet and are pruned...
	if got := inv.live(at(200)); len(got) != 0 {
		t.Fatalf("live = %v, want empty", got)
	}
	// ...so the slot is available again.
	inv.seen("late", at(210))
	if got := inv.live(at(220)); !slices.Equal(got, []string{"late"}) {
		t.Fatalf("live = %v, want [late] — expiry must return budget", got)
	}
}

// live() is emitted straight into Prometheus metrics, and a scrape that reorders its
// series for no reason is noise in every diff.
func TestBoundedInventory_LiveIsSorted(t *testing.T) {
	inv := newBoundedInventory(8, 100*time.Second, cmp.Compare[string])
	for _, k := range []string{"delta", "alpha", "charlie", "bravo"} {
		inv.seen(k, at(0))
	}
	got := inv.live(at(1))
	if !slices.Equal(got, []string{"alpha", "bravo", "charlie", "delta"}) {
		t.Fatalf("live = %v, want sorted", got)
	}
}

// A zero cap disables the budget, matching cappedCounter's max <= 0 contract.
func TestBoundedInventory_ZeroCapDisablesTheBudget(t *testing.T) {
	inv := newBoundedInventory(0, 100*time.Second, cmp.Compare[int])
	for i := range 1000 {
		inv.seen(i, at(0))
	}
	if n := inv.len(); n != 1000 {
		t.Fatalf("len = %d, want 1000 — max <= 0 must disable the cap", n)
	}
	if got := inv.refused(); got != 0 {
		t.Errorf("refused = %v, want 0", got)
	}
}
