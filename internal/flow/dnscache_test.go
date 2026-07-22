package flow

import (
	"net/netip"
	"testing"
	"time"
)

var (
	dcClient = netip.MustParseAddr("192.0.2.10")
	dcAnswer = netip.MustParseAddr("142.250.1.1")
)

// Control 1: a Put within TTL is returned by Lookup, and counts as a hit.
// Breaks if Lookup always misses, or if Stats never increments Hits.
func TestDNSCache_PutThenLookupHitsWithinTTL(t *testing.T) {
	d := NewDNSCache(10, time.Minute)
	t0 := time.Unix(1000, 0)
	d.Put(dcClient, dcAnswer, "example.com", t0)

	got, ok := d.Lookup(dcClient, dcAnswer, t0.Add(30*time.Second))
	if !ok || got != "example.com" {
		t.Fatalf("Lookup = (%q, %v), want (\"example.com\", true)", got, ok)
	}
	if st := d.Stats(); st.Hits != 1 || st.Misses != 0 {
		t.Fatalf("Stats() = %+v, want Hits=1 Misses=0", st)
	}
}

// Control 2: an entry older than TTL must NOT be returned — a stale domain is
// worse than none. Breaks if Lookup returns the value regardless of age, or if
// the expiry path forgets to count a miss.
func TestDNSCache_ExpiredEntryMissesNotStale(t *testing.T) {
	d := NewDNSCache(10, time.Minute)
	t0 := time.Unix(2000, 0)
	d.Put(dcClient, dcAnswer, "example.com", t0)

	got, ok := d.Lookup(dcClient, dcAnswer, t0.Add(90*time.Second))
	if ok || got != "" {
		t.Fatalf("Lookup after TTL = (%q, %v), want (\"\", false)", got, ok)
	}
	if st := d.Stats(); st.Misses != 1 {
		t.Fatalf("Stats().Misses = %d, want 1 (expiry must count as a miss)", st.Misses)
	}
	// The expired slot must also be dropped, freeing capacity for a new key.
	if st := d.Stats(); st.Entries != 0 {
		t.Fatalf("Stats().Entries = %d, want 0 (expired entry must be evicted on access)", st.Entries)
	}
}

// Control 3: at the entry cap, a brand-new key is refused and counted, while an
// existing key keeps working — the ktranslate stop-insert behaviour, not LRU
// eviction. Breaks if the cache evicts an existing entry to make room (an LRU
// implementation would pass this differently), or if it silently drops the new
// key without incrementing Rejected.
func TestDNSCache_AtCapRejectsNewKeepsExisting(t *testing.T) {
	d := NewDNSCache(2, time.Hour)
	t0 := time.Unix(3000, 0)

	c1, a1 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1")
	c2, a2 := netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("198.51.100.2")
	c3, a3 := netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("198.51.100.3")

	d.Put(c1, a1, "one.example", t0)
	d.Put(c2, a2, "two.example", t0)
	if st := d.Stats(); st.Entries != 2 || st.Rejected != 0 {
		t.Fatalf("after filling to cap: Stats() = %+v, want Entries=2 Rejected=0", st)
	}

	// A third, novel key must be refused.
	d.Put(c3, a3, "three.example", t0)
	if st := d.Stats(); st.Entries != 2 || st.Rejected != 1 {
		t.Fatalf("after over-cap Put: Stats() = %+v, want Entries=2 Rejected=1", st)
	}
	if _, ok := d.Lookup(c3, a3, t0); ok {
		t.Fatalf("Lookup(c3,a3) = true, want false: the rejected key must not have been stored")
	}

	// An EXISTING key must still update and still be found — the cap only
	// blocks growth, it never blocks a key already holding a slot.
	d.Put(c1, a1, "one-updated.example", t0)
	if st := d.Stats(); st.Entries != 2 || st.Rejected != 1 {
		t.Fatalf("re-Put of existing key changed cap accounting: Stats() = %+v", st)
	}
	got, ok := d.Lookup(c1, a1, t0)
	if !ok || got != "one-updated.example" {
		t.Fatalf("Lookup(c1,a1) = (%q,%v), want (\"one-updated.example\", true)", got, ok)
	}
}

// Control 4: size<=0 disables the cache outright — every Put is a no-op and
// every Lookup reports absent. Breaks if a zero or negative size is treated as
// "unbounded" instead of "off".
func TestDNSCache_ZeroSizeDisablesCache(t *testing.T) {
	for _, size := range []int{0, -1} {
		d := NewDNSCache(size, time.Minute)
		t0 := time.Unix(4000, 0)
		d.Put(dcClient, dcAnswer, "example.com", t0)

		got, ok := d.Lookup(dcClient, dcAnswer, t0)
		if ok || got != "" {
			t.Fatalf("size=%d: Lookup = (%q,%v), want (\"\",false)", size, got, ok)
		}
		if st := d.Stats(); st.Entries != 0 || st.Hits != 0 || st.Misses != 0 || st.Rejected != 0 {
			t.Fatalf("size=%d: Stats() = %+v, want all-zero (disabled cache must be a total no-op)", size, st)
		}
	}
}

// Control 5: a v4-mapped IPv6 address and its plain IPv4 form must key
// identically, exactly like CanonicalTuple (record.go) requires for the same
// reason. Breaks if Put/Lookup key on the raw netip.Addr without calling
// Unmap(), since netip compares ::ffff:142.250.1.1 and 142.250.1.1 as distinct
// values.
func TestDNSCache_V4MappedAndPlainV4ShareEntry(t *testing.T) {
	d := NewDNSCache(10, time.Minute)
	t0 := time.Unix(5000, 0)

	plainClient := netip.MustParseAddr("192.0.2.10")
	mappedClient := netip.MustParseAddr("::ffff:192.0.2.10")
	plainAnswer := netip.MustParseAddr("142.250.1.1")
	mappedAnswer := netip.MustParseAddr("::ffff:142.250.1.1")

	d.Put(mappedClient, plainAnswer, "example.com", t0)

	got, ok := d.Lookup(plainClient, mappedAnswer, t0)
	if !ok || got != "example.com" {
		t.Fatalf("Lookup with swapped v4/v4-mapped forms = (%q,%v), want (\"example.com\",true): Unmap must fold them to one key", got, ok)
	}
	if st := d.Stats(); st.Entries != 1 {
		t.Fatalf("Stats().Entries = %d, want 1 (v4 and v4-mapped forms must be ONE entry, not two)", st.Entries)
	}
}

// Control 6: a Lookup on a key that was never Put counts as a miss and returns
// absent. Breaks if a plain not-found path forgets to increment Misses.
func TestDNSCache_MissOnAbsentKeyCounts(t *testing.T) {
	d := NewDNSCache(10, time.Minute)
	t0 := time.Unix(6000, 0)

	got, ok := d.Lookup(dcClient, dcAnswer, t0)
	if ok || got != "" {
		t.Fatalf("Lookup on absent key = (%q,%v), want (\"\",false)", got, ok)
	}
	if st := d.Stats(); st.Misses != 1 || st.Hits != 0 {
		t.Fatalf("Stats() = %+v, want Misses=1 Hits=0", st)
	}
}
