package options

import (
	"time"

	"github.com/alecthomas/kingpin/v2"
)

var (
	firmwareCacheTTL = kingpin.Flag(
		"exporter.firmware-cache-ttl",
		"How long to cache firmware API responses (status and, when enabled, package details). The firmware data OPNsense serves is the stored result of the box's own update check, which it refreshes roughly daily, so re-fetching it every scrape only costs firewall CPU. Set to 0 to fetch on every scrape.",
	).Envar("OPNSENSE_EXPORTER_FIRMWARE_CACHE_TTL").Default("12h").Duration()

	cacheTTL = kingpin.Flag(
		"exporter.cache-ttl",
		"How long to cache responses from slow-moving API endpoints (system/CPU identity, certificate inventory) and to remember that a plugin-gated endpoint is absent (its 404). This data changes only on an admin action — a config edit, a certificate renewal, a plugin install — so re-fetching it every scrape only costs firewall CPU. The cost is staleness: a newly installed plugin, or a cert change, can take up to this long to show up. Set to 0 to fetch everything on every scrape. Live data (counters, rates, service run-state) is never cached regardless of this setting.",
	).Envar("OPNSENSE_EXPORTER_CACHE_TTL").Default("1h").Duration()
)

// EndpointCacheTTLs maps an OPNsense API endpoint name to how long a successful
// GET response for it may be served from cache instead of re-fetched. Only
// endpoints whose payload is wholly slow-moving belong here: anything carrying a
// counter, rate or live status must be fetched every scrape.
type EndpointCacheTTLs map[string]time.Duration

// CacheTTLs returns the per-endpoint response-cache TTLs for successful responses.
// Endpoints absent from the map — which is all of them but these — are never cached.
func CacheTTLs() EndpointCacheTTLs {
	ttls := EndpointCacheTTLs{}

	// Both firmware endpoints are gated by the same daily-ish check on the box:
	// "firmware" (api/core/firmware/status) reads the stored result of that check,
	// and "firmwareInfo" (api/core/firmware/info) lists installed plugins, which
	// change only on a package install. One TTL therefore governs both.
	if *firmwareCacheTTL > 0 {
		ttls["firmware"] = *firmwareCacheTTL
		ttls["firmwareInfo"] = *firmwareCacheTTL
	}

	if *cacheTTL > 0 {
		// Machine identity: the CPU model is fixed until the hardware changes, and the
		// OPNsense/FreeBSD versions change only on an upgrade.
		ttls["cpuType"] = *cacheTTL
		ttls["systemInformation"] = *cacheTTL

		// Certificate inventory: descriptions and validity windows. Expiry is alerted on
		// a days-to-weeks horizon, so an hour of staleness is invisible; these carry no
		// counters, only notBefore/notAfter and in-use flags.
		ttls["certificates"] = *cacheTTL
		ttls["caCertificates"] = *cacheTTL
		ttls["acmeCertificates"] = *cacheTTL
	}

	return ttls
}

// AbsentCacheTTL returns how long a 404 from a plugin-gated endpoint is remembered,
// so a firewall without the plugin is not asked for it on every scrape. 0 disables
// negative caching. The endpoints this applies to are opnsense.PluginGatedEndpoints();
// they are wired in main (this package cannot import opnsense, which imports it).
func AbsentCacheTTL() time.Duration {
	return *cacheTTL
}
