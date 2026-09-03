package opnsense

import (
	"container/list"
	"net/http"
	"sort"
	"sync"
	"time"
)

const (
	maxResponseCacheEntryBytes = 4 << 20
	maxResponseCacheBytes      = 32 << 20
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
	order      *list.List
	bytes      int
	mu         sync.Mutex
}

type cacheEntry struct {
	expiresAt  time.Time
	body       []byte
	statusCode int
	elem       *list.Element
	cost       int
}

func newResponseCache() *responseCache {
	return &responseCache{
		now:        time.Now,
		ttls:       make(map[EndpointPath]time.Duration),
		absentTTLs: make(map[EndpointPath]time.Duration),
		entries:    make(map[EndpointPath]cacheEntry),
		order:      list.New(),
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
		rc.remove(path)
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
		rc.remove(path)
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
	if !ok {
		return cacheEntry{}, false
	}
	if !rc.now().Before(entry.expiresAt) {
		rc.remove(path)
		return cacheEntry{}, false
	}
	rc.order.MoveToFront(entry.elem)
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
	if len(body) > maxResponseCacheEntryBytes {
		return false
	}
	rc.remove(path)
	for rc.bytes+len(body) > maxResponseCacheBytes {
		back := rc.order.Back()
		if back == nil {
			return false
		}
		rc.remove(back.Value.(EndpointPath))
	}
	entry := cacheEntry{body: body, statusCode: statusCode, expiresAt: rc.now().Add(ttl), cost: len(body)}
	entry.elem = rc.order.PushFront(path)
	rc.entries[path] = entry
	rc.bytes += entry.cost
	return true
}

func (rc *responseCache) remove(path EndpointPath) {
	entry, ok := rc.entries[path]
	if !ok {
		return
	}
	if entry.elem != nil {
		rc.order.Remove(entry.elem)
	}
	rc.bytes -= entry.cost
	delete(rc.entries, path)
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
//
// #495: this is the NEGATIVE-CACHEABLE set, which is narrower than the set of
// endpoints whose 404 means "plugin absent". Those are two different questions and
// they were one list until a canary run against a box without os-vnstat reported
// vnstatGetJsonData as a vanished core route. Ask the semantic question through
// PluginGatedEndpoints below; ask the caching question here.
func NegativeCacheable404Endpoints() []EndpointName {
	return []EndpointName{
		// Per-plugin service status. The 200 body ({"status":"running"}) is live
		// state and is never cached — only the 404 is.
		"apcupsdServiceStatus", "captivePortalServiceStatus", "chronyServiceStatus",
		"crowdsecServiceStatus", "dnsmasqServiceStatus", "dyndnsServiceStatus",
		"haproxyServiceStatus", "ipsecServiceStatus", "keaServiceStatus",
		"monitServiceStatus", "nginxServiceStatus", "nutServiceStatus",
		"quaggaServiceStatus", "syslogServiceStatus", "tailscaleServiceStatus",
		"unboundServiceStatus", "wireguardServiceStatus", "netbirdServiceStatus",

		// Plugin data endpoints (GET). Kept alphabetical and unique —
		// TestPluginGatedEndpoints_HasNoDuplicates enforces the uniqueness, because a
		// list carrying the same name three times cannot be reviewed for what is
		// MISSING, which is the only question that matters here.
		"acmeCertificates", "apcupsdUpsStatus", "bpfStatistics", "captivePortalZones",
		"chronySourceStats", "chronySources", "chronyTracking", "clamavVersion",
		"crowdsecVersion", "dechwPowerStatus", "dhcpv4", "dhcpv6Leases", "dhcpv6Prefixes",
		"dmidecodeInfo", "dyndnsAccounts", "haproxyCounters", "haproxyInfo", "haproxyTables",
		"firewallMigrationOutbound", "firewallMigrationRules", "gatewayGroups", "ipsecPhase1", "ipsecPools", "lldpdNeighbors", "monitStatus", "netbirdStatus",
		"nginxBans", "nginxVts", "nutUpsStatus", "qfeedsStats", "quaggaBfdCounters",
		"quaggaBfdNeighbors", "quaggaBfdSummary", "quaggaBgpRoute4", "quaggaBgpRoute6",
		"quaggaBgpSummary", "quaggaOspfOverview", "relaydStatusSum",
		"siproxdRegistrations", "tailscaleStatus", "torCircuits", "torHiddenServices",
		"torStreams", "trafficShaperStatistics", "zerotierNetworks",

		// FRR (quagga) session/interface detail (#197/#198) and opt-in
		// route/LSDB volume gauges (#199). All ten are plain GETs on the
		// registered (query-less) path — the search_* bootgrid endpoints rely on
		// OPNsense's searchRecordsetBase default rowCount of 9999 rather than an
		// explicit "?current=1&rowCount=-1" query string, so (unlike
		// vnstatGetJsonData below) their negative-cache key always matches the
		// actual request path.
		"quaggaBgpNeighbors", "quaggaOspfInterface", "quaggaOspfDatabase",
		"quaggaOspfRoute", "quaggaOspfv3Overview", "quaggaOspfv3Interface",
		"quaggaOspfv3Route", "quaggaOspfv3Database", "quaggaGeneralRoute4",
		"quaggaGeneralRoute6",

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

// PluginGatedEndpoints returns every endpoint whose 404 means "the plugin is not
// installed" rather than "this route vanished upstream". It is the SEMANTIC set,
// and a superset of NegativeCacheable404Endpoints.
//
// Parameterized data routes can belong only to this semantic set when their real
// request path does not match the registered base path used as the cache key.
// vnstatGetJsonData and zerotierNetworkInfo are the two current cases.
// vnstatGetJsonData is unambiguously plugin-gated - it is an os-vnstat route and
// 404s precisely when os-vnstat is absent - but it cannot be negative-cached,
// because the cache keys on the registered query-less path while every real request
// carries "?iface=<device>", so a TTL on it would never match. Reading the caching
// list as an answer to the semantic question made the canary file it under "core
// route absent - investigate", its highest-signal section, on any box without the
// plugin. The nightly testbed has os-vnstat installed, so only the production
// release box surfaced it.
//
// Consumers: cmd/apidrift (is this 404 expected?) and acl.go. main.go's TTL wiring
// wants NegativeCacheable404Endpoints instead. TestPluginGatedIncludesVnstatGetJsonData
// enforces that cacheable stays a subset of this.
func PluginGatedEndpoints() []EndpointName {
	return append(NegativeCacheable404Endpoints(), "vnstatGetJsonData", "zerotierNetworkInfo")
}

// CacheEntryView is a read-only snapshot of one held response-cache entry,
// exposed for the web UI's cache/freshness card. It carries no reference to
// the underlying cache, so holding one never blocks or mutates the cache.
type CacheEntryView struct {
	// Endpoint is the endpoint name resolved via a reverse lookup of the
	// client's configured endpoints; "" if the path no longer maps to a
	// known endpoint name.
	Endpoint string
	Path     string
	// StatusCode is the cached response's status: 200 for a positive
	// (success-body) entry, 404 for a negative ("plugin absent") entry.
	StatusCode int
	// TTL is the configured TTL for this entry's status class: the
	// positive TTL (SetEndpointCacheTTL) for a 200, or the absent TTL
	// (SetEndpointAbsentTTL) for a 404.
	TTL time.Duration
	// Remaining is how much longer the entry is valid for (expiresAt - now);
	// it may be negative if the entry has just expired but not yet been
	// evicted by the next get/put.
	Remaining time.Duration
	// PluginGated reports whether this endpoint is in PluginGatedEndpoints().
	PluginGated bool
}

// CacheSnapshot returns a read-only, point-in-time view of every entry
// currently held in the client's response cache, sorted by Path. It never
// mutates the cache and never triggers a request. A client with no cache
// (caching never configured) returns nil.
func (c *Client) CacheSnapshot() []CacheEntryView {
	if c.cache == nil {
		return nil
	}

	rev := make(map[EndpointPath]EndpointName, len(c.endpoints))
	for name, path := range c.endpoints {
		rev[path] = name
	}

	gated := make(map[EndpointName]bool)
	for _, name := range PluginGatedEndpoints() {
		gated[name] = true
	}

	rc := c.cache
	rc.mu.Lock()
	defer rc.mu.Unlock()

	now := rc.now()
	out := make([]CacheEntryView, 0, len(rc.entries))
	for path, entry := range rc.entries {
		var ttl time.Duration
		if entry.statusCode == http.StatusNotFound {
			ttl = rc.absentTTLs[path]
		} else {
			ttl = rc.ttls[path]
		}
		name := rev[path]
		out = append(out, CacheEntryView{
			Endpoint:    string(name),
			Path:        string(path),
			StatusCode:  entry.statusCode,
			TTL:         ttl,
			Remaining:   entry.expiresAt.Sub(now),
			PluginGated: gated[name],
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
