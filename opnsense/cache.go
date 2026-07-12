package opnsense

import (
	"sync"
	"time"
)

// responseCache memoizes raw successful GET response bodies per endpoint, each
// under its own TTL. It exists because several OPNsense endpoints are backed by
// data the box itself only refreshes on a slow cadence (e.g. the firmware status
// GET reads /tmp/pkg_upgrade.json, written by the box's own daily update check),
// yet every Prometheus scrape re-fetches them — and each fetch spawns a configd
// action and a PHP script on the firewall.
//
// Endpoints with no TTL are never cached, so caching is strictly opt-in per
// endpoint. Bodies are cached rather than decoded structs so the cache stays
// generic over every Fetch* method: the (cheap) JSON unmarshal still runs per
// scrape, giving each caller its own copy of the data to own.
//
// A nil *responseCache is a valid, permanently-empty cache — every method below
// is nil-safe — so a Client built without one simply never caches.
type responseCache struct {
	now     func() time.Time
	ttls    map[EndpointPath]time.Duration
	entries map[EndpointPath]cacheEntry
	mu      sync.Mutex
}

type cacheEntry struct {
	expiresAt time.Time
	body      []byte
}

func newResponseCache() *responseCache {
	return &responseCache{
		now:     time.Now,
		ttls:    make(map[EndpointPath]time.Duration),
		entries: make(map[EndpointPath]cacheEntry),
	}
}

// setTTL caches successful responses for path for ttl. A ttl <= 0 disables
// caching for path and drops any entry already held for it.
func (rc *responseCache) setTTL(path EndpointPath, ttl time.Duration) {
	if rc == nil {
		return
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if ttl <= 0 {
		delete(rc.ttls, path)
		delete(rc.entries, path)
		return
	}
	rc.ttls[path] = ttl
}

// get returns the cached body for path when one is held and unexpired.
func (rc *responseCache) get(path EndpointPath) ([]byte, bool) {
	if rc == nil {
		return nil, false
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()

	entry, ok := rc.entries[path]
	if !ok || !rc.now().Before(entry.expiresAt) {
		return nil, false
	}
	return entry.body, true
}

// put stores body as the cached response for path, if path has a TTL. body must
// not be mutated afterwards; callers hand over a freshly read response body.
func (rc *responseCache) put(path EndpointPath, body []byte) {
	if rc == nil {
		return
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()

	ttl, ok := rc.ttls[path]
	if !ok {
		return
	}
	rc.entries[path] = cacheEntry{body: body, expiresAt: rc.now().Add(ttl)}
}

// SetEndpointCacheTTL serves successful GET responses from the named endpoint
// out of an in-memory cache for ttl, instead of re-fetching them on every
// scrape. A ttl <= 0 (the default for every endpoint) disables caching for it.
// Unknown endpoint names are ignored.
//
// Only use this for endpoints whose payload is wholly slow-moving. Anything
// carrying a counter, rate or live status must stay uncached, and a POST
// endpoint is never cached regardless of its TTL.
//
// Metrics are still emitted from the cached body on every scrape, so cached
// series have no gaps; what drops is the API call (and with it the per-endpoint
// request-count self-metric, which is how you can see the cache working).
//
// Call this during setup, before the client is cloned per scrape via
// WithContext: clones share the cache, but only if it already exists.
func (c *Client) SetEndpointCacheTTL(name EndpointName, ttl time.Duration) {
	path, ok := c.endpoints[name]
	if !ok {
		return
	}
	if c.cache == nil {
		c.cache = newResponseCache()
	}
	c.cache.setTTL(path, ttl)
}
