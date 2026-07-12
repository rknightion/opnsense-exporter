package options

import (
	"time"

	"github.com/alecthomas/kingpin/v2"
)

var firmwareCacheTTL = kingpin.Flag(
	"exporter.firmware-cache-ttl",
	"How long to cache firmware API responses (status and, when enabled, package details). The firmware data OPNsense serves is the stored result of the box's own update check, which it refreshes roughly daily, so re-fetching it every scrape only costs firewall CPU. Set to 0 to fetch on every scrape.",
).Envar("OPNSENSE_EXPORTER_FIRMWARE_CACHE_TTL").Default("12h").Duration()

// EndpointCacheTTLs maps an OPNsense API endpoint name to how long a successful
// GET response for it may be served from cache instead of re-fetched. Only
// endpoints whose payload is wholly slow-moving belong here: anything carrying a
// counter, rate or live status must be fetched every scrape.
type EndpointCacheTTLs map[string]time.Duration

// CacheTTLs returns the per-endpoint response-cache TTLs. Endpoints absent from
// the map (i.e. all of them by default) are never cached.
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

	return ttls
}
