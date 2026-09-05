package flow

import (
	"net/netip"
	"sync"
	"time"
)

// dnsKey is the cache's join key: which client asked, and which address the
// answer resolved to. Both are Unmapped before keying — see the comment on
// CanonicalTuple (record.go) for why ::ffff:a.b.c.d and a.b.c.d must key
// identically: a NetFlow record and the DNS answer that explains it can arrive
// wearing different address forms for the same host.
type dnsKey struct {
	client netip.Addr
	answer netip.Addr
}

// dnsEntry is one cached answer. added is the firewall/receiver clock at Put
// time, not time.Now() — see DNSCache's doc comment on why the clock is always
// passed in.
type dnsEntry struct {
	qname string
	added time.Time
}

// DNSCacheStats is the cache's own health, published as self-metrics. Without
// these an operator cannot tell "the cache is quietly empty" from "the cache is
// thrashing at its cap" — both look like "no domains resolved" from outside.
type DNSCacheStats struct {
	Entries  int // live tracked entries
	Size     int // configured insert cap; <=0 means the cache is disabled
	Hits     uint64
	Misses   uint64
	Rejected uint64 // inserts refused because the cache remained at Size
}

// DNSCache maps (client, answer) -> the qname that produced the answer, so a
// bare NetFlow flow to 142.250.1.1 can recover a dst.domain, and a Zenarmor
// conn record — which carries no domain of its own — gets one anyway (#346
// phase 3, spec §7).
//
// Bounded two ways, deliberately NOT the same way Rollup is bounded:
//
//   - size is a hard entry cap enforced at INSERT time. Over the cap, Put
//     STOPS INSERTING new keys rather than evicting an existing one — this is
//     ktranslate's resolver-ceiling behaviour, chosen so a burst of novel
//     lookups cannot evict the hot entries a busy client is actually about to
//     match against. There is no LRU here on purpose.
//   - ttl bounds entries by AGE, checked lazily on Lookup and when a new key
//     needs room at a full cache. An entry older than ttl is treated as absent
//     (and counted as a miss on Lookup) rather than returned stale: a DNS
//     answer's address can be reused by an unrelated site well within a flow's
//     own lifetime, so an unbounded cache would eventually hand out someone
//     else's domain.
//
// Put and Lookup are called from receiver goroutines (the syslog/DNS lane) and
// must never block or perform I/O — same contract as Sink.Observe
// (record.go:251-253). now is always passed in rather than read from
// time.Now(), so tests can drive the TTL deterministically without a hidden
// clock, matching Rollup and the rest of this package's accumulators.
type DNSCache struct {
	mu      sync.Mutex
	entries map[dnsKey]dnsEntry
	size    int
	ttl     time.Duration
	// nextExpiry is a conservative earliest expiry. Refreshing or looking up
	// an entry may leave it early, but never late: a full scan is only needed
	// once caller time has passed a possible expiry, not on every refused Put.
	nextExpiry time.Time
	hits       uint64
	misses     uint64
	rejected   uint64
}

// NewDNSCache returns a cache bounded by size entries and ttl age. size<=0
// disables the cache entirely: every Put is a no-op and every Lookup returns
// ("", false) without touching the mutex or counting a miss, so a deployment
// that turns the feature off pays nothing for it.
func NewDNSCache(size int, ttl time.Duration) *DNSCache {
	d := &DNSCache{size: size, ttl: ttl}
	if size > 0 {
		d.entries = make(map[dnsKey]dnsEntry, size)
	}
	return d
}

// Put records that answer resolved from a query client made, naming qname.
// Unmaps both addresses first (see dnsKey's comment). At capacity, expired
// entries are reclaimed before a brand-new key is rejected and counted. A key
// already present keeps updating regardless of the cap, since it costs no
// additional map slot.
func (d *DNSCache) Put(client, answer netip.Addr, qname string, now time.Time) {
	if d.size <= 0 {
		return
	}
	key := dnsKey{client: client.Unmap(), answer: answer.Unmap()}

	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.entries[key]; !ok && len(d.entries) >= d.size {
		if now.After(d.nextExpiry) {
			d.nextExpiry = time.Time{}
			for existingKey, entry := range d.entries {
				if now.Sub(entry.added) > d.ttl {
					delete(d.entries, existingKey)
					continue
				}
				expires := entry.added.Add(d.ttl)
				if d.nextExpiry.IsZero() || expires.Before(d.nextExpiry) {
					d.nextExpiry = expires
				}
			}
		}
		if len(d.entries) >= d.size {
			d.rejected++
			return
		}
	}
	d.entries[key] = dnsEntry{qname: qname, added: now}
	expires := now.Add(d.ttl)
	if d.nextExpiry.IsZero() || expires.Before(d.nextExpiry) {
		d.nextExpiry = expires
	}
}

// Lookup returns the qname cached for (client, answer), or ("", false) if
// absent or if the entry aged out past ttl. An expired entry counts as a miss
// — not a stale hit — and is dropped so its slot frees up for a future Put.
func (d *DNSCache) Lookup(client, answer netip.Addr, now time.Time) (string, bool) {
	if d.size <= 0 {
		return "", false
	}
	key := dnsKey{client: client.Unmap(), answer: answer.Unmap()}

	d.mu.Lock()
	defer d.mu.Unlock()

	e, ok := d.entries[key]
	if !ok {
		d.misses++
		return "", false
	}
	if now.Sub(e.added) > d.ttl {
		delete(d.entries, key)
		d.misses++
		return "", false
	}
	d.hits++
	return e.qname, true
}

// Stats reports the cache's own health.
func (d *DNSCache) Stats() DNSCacheStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	return DNSCacheStats{
		Entries:  len(d.entries),
		Size:     d.size,
		Hits:     d.hits,
		Misses:   d.misses,
		Rejected: d.rejected,
	}
}
