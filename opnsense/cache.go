package opnsense

import (
	"net/http"
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
	now func() time.Time
	// ttls holds positive TTLs: how long a successful body may be replayed.
	ttls map[EndpointPath]time.Duration
	// absentTTLs holds negative TTLs: how long a 404 ("plugin absent") may be
	// replayed. Kept separate from ttls because the two are not interchangeable —
	// a *ServiceStatus endpoint's 200 body is live state that must never be cached,
	// while its 404 is a routing fact that changes only when an admin installs the
	// plugin. Most endpoints on the negative list have no positive TTL at all.
	absentTTLs map[EndpointPath]time.Duration
	entries    map[EndpointPath]cacheEntry
	mu         sync.Mutex
}

type cacheEntry struct {
	expiresAt  time.Time
	body       []byte
	statusCode int
}

func newResponseCache() *responseCache {
	return &responseCache{
		now:        time.Now,
		ttls:       make(map[EndpointPath]time.Duration),
		absentTTLs: make(map[EndpointPath]time.Duration),
		entries:    make(map[EndpointPath]cacheEntry),
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

// setAbsentTTL caches a 404 from path for ttl. A ttl <= 0 disables negative
// caching for path and drops any entry already held for it.
func (rc *responseCache) setAbsentTTL(path EndpointPath, ttl time.Duration) {
	if rc == nil {
		return
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if ttl <= 0 {
		delete(rc.absentTTLs, path)
		delete(rc.entries, path)
		return
	}
	rc.absentTTLs[path] = ttl
}

// get returns the cached entry for path when one is held and unexpired.
func (rc *responseCache) get(path EndpointPath) (cacheEntry, bool) {
	if rc == nil {
		return cacheEntry{}, false
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()

	entry, ok := rc.entries[path]
	if !ok || !rc.now().Before(entry.expiresAt) {
		return cacheEntry{}, false
	}
	return entry, true
}

// put stores a response for path under whichever TTL applies to its status code:
// the positive TTL for a success, the absent TTL for a 404. Anything else (a 5xx,
// an auth failure) is never cached — those are faults, and replaying one would
// suppress a real error for the length of the TTL. body must not be mutated
// afterwards; callers hand over a freshly read response body.
//
// It reports whether the response was actually stored, which is also what makes a
// request a cache MISS in the self-metrics: a miss is a call that populated the
// cache (cold cache or expired TTL). A call whose response was never cacheable in
// the first place is not a miss — notably a 200 from an endpoint that only has an
// absent TTL, i.e. a plugin-gated endpoint whose plugin IS installed. Its live
// payload is fetched every scrape by design, so counting it as a miss every time
// would bury the real signal and make the hit rate meaningless.
func (rc *responseCache) put(path EndpointPath, statusCode int, body []byte) bool {
	if rc == nil {
		return false
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()

	var ttl time.Duration
	var ok bool
	switch {
	case statusCode >= 200 && statusCode < 300:
		ttl, ok = rc.ttls[path]
	case statusCode == http.StatusNotFound:
		ttl, ok = rc.absentTTLs[path]
	}
	if !ok {
		return false
	}
	rc.entries[path] = cacheEntry{body: body, statusCode: statusCode, expiresAt: rc.now().Add(ttl)}
	return true
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

// SetEndpointAbsentTTL caches a 404 from the named endpoint for ttl, so a
// plugin-gated endpoint on a box without the plugin is asked once per ttl rather
// than on every scrape. A ttl <= 0 (the default) disables it. Unknown endpoint
// names are ignored.
//
// The cached 404 is replayed as the same APICallError a live 404 produces, so the
// Fetch* methods that treat 404 as "feature absent" behave identically and their
// collectors stay silent. Only 404 is cached this way: a 5xx is a fault, not a
// routing fact.
//
// The cost is staleness in one direction only: for up to ttl after an admin
// installs a plugin, the exporter still reports it absent. Use only for
// plugin-gated endpoints (see PluginGatedEndpoints) — never for a core endpoint
// like the health check, where a cached 404 would keep reporting a recovered
// firewall as down.
func (c *Client) SetEndpointAbsentTTL(name EndpointName, ttl time.Duration) {
	path, ok := c.endpoints[name]
	if !ok {
		return
	}
	if c.cache == nil {
		c.cache = newResponseCache()
	}
	c.cache.setAbsentTTL(path, ttl)
}

// PluginGatedEndpoints lists the GET endpoints that answer 404 on a firewall
// without the corresponding plugin installed, and whose Fetch* method therefore
// treats a 404 as "feature absent" rather than an error. These are the endpoints
// it is safe to negative-cache: a 404 here reflects an uninstalled plugin, which
// changes only by admin action.
//
// It deliberately excludes core endpoints (healthCheck, services, systemResources,
// firmware …): a cached 404 on those would misreport a broken or recovering box.
// TestPluginGatedEndpoints enforces that.
//
// POST endpoints DO belong here. Only their 404 is ever cached, and a 404 is a
// property of the route, not of the request body — verified against a live OPNsense
// 26.1, where an absent plugin's endpoint answers 404 {"errorMessage":"Endpoint not
// found"} to any POST, while a POST carrying a bad resource (smartInfo with a
// nonexistent device) answers 200 {"message":"Invalid device name"}, not 404. So the
// body-collision problem that rules out caching a POST's successful body does not
// apply to caching its absence.
//
// When adding a plugin-gated collector whose Fetch treats 404 as feature-absent,
// add its endpoint(s) here so boxes without the plugin stop paying for it on every
// scrape.
func PluginGatedEndpoints() []EndpointName {
	return []EndpointName{
		// Per-plugin service status. The 200 body ({"status":"running"}) is live
		// state and is never cached — only the 404 is.
		"apcupsdServiceStatus", "captivePortalServiceStatus", "chronyServiceStatus",
		"crowdsecServiceStatus", "dnsmasqServiceStatus", "dyndnsServiceStatus",
		"haproxyServiceStatus", "ipsecServiceStatus", "keaServiceStatus",
		"monitServiceStatus", "nginxServiceStatus", "nutServiceStatus",
		"quaggaServiceStatus", "syslogServiceStatus", "tailscaleServiceStatus",
		"unboundServiceStatus", "wireguardServiceStatus", "netbirdServiceStatus",

		// Plugin data endpoints (GET).
		"acmeCertificates", "apcupsdUpsStatus", "bpfStatistics", "captivePortalZones",
		"chronySources", "chronySourceStats", "chronyTracking", "clamavVersion", "dhcpv4",
		"dhcpv6Leases", "dhcpv6Prefixes", "dyndnsAccounts", "haproxyCounters",
		"haproxyInfo", "haproxyTables", "ipsecPhase1", "ipsecPools", "monitStatus", "nginxVts",
		"nutUpsStatus", "qfeedsStats", "quaggaBfdCounters", "quaggaBfdNeighbors",
		"chronySources", "chronySourceStats", "chronyTracking", "dechwPowerStatus",
		"dhcpv4", "dhcpv6Leases", "dhcpv6Prefixes", "dmidecodeInfo", "dyndnsAccounts",
		"haproxyCounters", "haproxyInfo", "ipsecPhase1", "ipsecPools", "monitStatus",
		"nginxVts", "nutUpsStatus", "qfeedsStats", "quaggaBfdCounters", "quaggaBfdNeighbors",
		"quaggaBgpSummary", "quaggaOspfOverview", "tailscaleStatus",
		"trafficShaperStatistics", "lldpdNeighbors",
		"quaggaBgpSummary", "quaggaOspfOverview", "tailscaleStatus", "netbirdStatus",
		"trafficShaperStatistics",
		"trafficShaperStatistics", "crowdsecVersion",
		"trafficShaperStatistics", "torCircuits", "torStreams", "torHiddenServices",
		"relaydStatusSum",

		// Plugin data endpoints (POST). Only their 404 is cached; a successful POST
		// response is body-dependent and always goes to the box (see the doc comment).
		"crowdsecAlerts", "crowdsecDecisions", "crowdsecBouncers", "crowdsecMachines",
		"crowdsecCollections", "crowdsecScenarios", "crowdsecParsers",
		"crowdsecPostoverflows", "crowdsecAppsecConfigs", "crowdsecAppsecRules",
		"captivePortalSessions", "ipsecPhase2", "quaggaOspfNeighbors",
		"smartList", "smartInfo",

		// vnstatInterfaceList is the os-vnstat plugin's entry point (#215): a 404 here
		// means the plugin is absent, and FetchVnstat bails out before ever calling
		// get_json_data. vnstatGetJsonData is deliberately NOT listed here: its actual
		// request path always carries a per-interface "?iface=" query string, but this
		// negative cache is keyed on the fixed, registered path (no query) — so a TTL
		// set on it would never match a real request and would be a no-op. See the
		// FetchVnstat doc comment in vnstat.go.
		"vnstatInterfaceList",
	}
}
